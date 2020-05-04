#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <linux/ipv6.h>
#include <time.h>
#include <netdb.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stddef.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <errno.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/uio.h>

#ifdef __linux__
#  if defined IPV6_RECVPKTINFO
#    include <linux/version.h>
#    if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14)
#      if defined IPV6_2292PKTINFO
#        undef IPV6_RECVPKTINFO
#        undef IPV6_PKTINFO
#        define IPV6_RECVPKTINFO IPV6_2292PKTINFO
#        define IPV6_PKTINFO IPV6_2292PKTINFO
#      endif
#    endif
#  endif
#endif

#ifdef __linux__
#  if defined IP_PKTINFO
#    define HAVE_IP_PKTINFO
#  endif
#endif

/*
 *	Linux uses IPV6_RECVPKTINFO for the setsockopt() call,
 *	and IPV6_PKTINFO for sendmsg() and recvmsg()
 *	Others use IPV6_PKTINFO for all calls.
 */
#ifdef IPV6_PKTINFO
#ifdef __linux__
#define SSO_IPV6_RECVPKTINFO IPV6_RECVPKTINFO
#else
#define SSO_IPV6_RECVPKTINFO IPV6_PKTINFO
#endif
#endif

#ifdef __APPLE__
#define SOL_IP IP_PKTINFO
#endif

#define BUFSIZE 1024

// Constants
#define DEFAULT_HTTP_PORT "8080"   // Default service name or port number
#define DEFAULT_HTTPS_PORT "8443"  // Default service name or port number
#define MAXCONNQLEN  256        // Max # of connection requests to queue
#define MAX_HTTP_SOCKETS  2   // One HTTP socket for IPv4 and one for IPv6
#define MAX_HTTPS_SOCKETS  2  // One HTTPS socket for IPv4 and one for IPv6
#define CLI_OPTS    "vp:s:"   // Command line options
#define INVALID_DESC -1       // Invalid file descriptor

// crypto material files
char cert_file[] = "cert.pem";
char key_file []= "key.pem";

// Handy boolean type
typedef enum { false = 0, true } boolean;

// Globals
char hostBfr[NI_MAXHOST];   // For use w/getnameinfo(3)
char srvBfr[NI_MAXHOST];    // For use w/getnameinfo(3)
char servBfr[NI_MAXSERV];   // For use w/getnameinfo(3)
char srvportBfr[NI_MAXSERV];// For use w/getnameinfo(3)
char server_hostname[NI_MAXHOST]; // to store server name
const char *execName;        // Executable name
boolean     verbose = false; // Verbose mode?

// Function prototypes
int set_sock_opts(int socket);

int sendto_from(int socket, void *buffer, size_t bufferLen, int flags,
	       struct sockaddr *clientAddr, socklen_t *clientLen,
	       struct sockaddr *srvAddr, socklen_t *srvLen, uint *ifindex);
  
int  openSocket(const char *service, int desc[], size_t *descSize);

void web_1x1png(int http_Socket[], size_t http_SocketSize,
            int https_Socket[], size_t https_SocketSize);

void gen_http_headers(char *buffer, int *length, char *date);

void get_png(char *buffer, int *length);

void verbose_info(int socket, struct sockaddr *sadr, socklen_t sadrLen);

void log_write(char *date, char secure, char *timestamp);

// Macro to terminate the program if a system call error occurs,
// printing errno before exiting
#define CHECK(expr)                                           \
  do {                                                        \
     if ( (expr) == -1 ) {                                    \
        fprintf(stderr, "line %d: System call ERROR - %s.\n", \
                 __LINE__, strerror(errno));                  \
        exit(1);                                              \
     }                                                        \
  } while (false)

// Usage message
void usage(const char * execName) {
   fprintf( stderr, "Usage: %s [-v] [-p <http_port>] [-s <https_port]\n", execName );
   exit(1);
}

void init_openssl()
{ 
  SSL_load_error_strings();	
  OpenSSL_add_ssl_algorithms();
}

SSL_CTX *create_context()
{
  const SSL_METHOD *method;
  SSL_CTX *ctx;

  method = SSLv23_server_method();
  ctx = SSL_CTX_new(method);
  if (!ctx) {
    perror("Unable to create SSL context");
    ERR_print_errors_fp(stderr);
    exit(1);
  }
  return ctx;
}

void configure_context(SSL_CTX *ctx)
{
  SSL_CTX_set_ecdh_auto(ctx, 1);

  /* Set the key and cert */
  if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(1);
  }
  if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0 ) {
    ERR_print_errors_fp(stderr);
    exit(1);
  }
}

//Set socket options to listen on unbound IPv6 addresses
int set_sock_opts(int socket) {
	int proto, flag;
  int enable = 1; // Set it
	struct sockaddr_storage addr;
	socklen_t addr_len = sizeof(addr);

  /* If we fail it will be because the system doesn't support the 
   * options we want, so set errno
   */
	errno = ENOSYS;
  /* Need to find address family to set corresponding options */
	if (getsockname(socket, (struct sockaddr *) &addr, &addr_len) < 0) {
		return -1;
	}

#ifdef IP_FREEBIND
	(void) setsockopt(socket, IPPROTO_IP, IP_FREEBIND, &enable, sizeof(enable));
#endif
#ifdef IP_BINDANY
	if (addr.ss_family == AF_INET) {
		(void) setsockopt(socket, IPPROTO_IP, IP_BINDANY, &enable, sizeof(enable));
	}
#endif
#ifdef IPV6_BINDANY
	if (addr.ss_family == AF_INET6) {
		(void) setsockopt(socket, IPPROTO_IPV6, IPV6_BINDANY, &enable, sizeof(enable));
	}
#endif

// IPv4
	if (addr.ss_family == AF_INET) {
#ifdef HAVE_IP_PKTINFO
		// If on Linux
		proto = SOL_IP;
		flag = IP_PKTINFO;
#endif
#ifdef IP_RECVDSTADDR
		proto = IPPROTO_IP;
		// Set IP_RECVDSTADDR option (*BSD)
		flag = IP_RECVDSTADDR;
#endif
	} else if (addr.ss_family == AF_INET6) {
// IPv6
#ifdef IPV6_PKTINFO
		proto = IPPROTO_IPV6;
		flag = SSO_IPV6_RECVPKTINFO;
#endif
	}  
  return setsockopt(socket, proto, flag, &enable, sizeof(enable));
}
/* 
 * Function similar to recvfrom but also gets you the server address at 
 * which the message arrived
 */
int recvfrom_to(int socket, void *buffer, size_t bufferLen, int flags,
	       struct sockaddr *client, socklen_t *clientLen,
	       struct sockaddr *srv, socklen_t *srvLen, uint *ifindex)
{
	struct msghdr msgheader;
	struct cmsghdr *control_msg;
	struct iovec msg_iov;
	char control_buf[256];
	int err;
	struct sockaddr_storage srcAddr;
	socklen_t srcLen = sizeof(srcAddr);

  // In order to be able to get the server side address at which we got the message
  // we need proper support in recvmsg
#if !defined(IP_PKTINFO) && !defined(IP_RECVDSTADDR) && !defined (IPV6_PKTINFO)
	srv = NULL:
#endif

  // Get socket info
  if (getsockname(socket, (struct sockaddr *)&srcAddr, &srcLen) < 0) {
		return -1;
	}

	/*
	 *	Initialize the server (srv) address.  It may be INADDR_ANY here,
	 *	with a more specific address given by recvmsg(), below.
	 */
	if (srcAddr.ss_family == AF_INET) {
#if !defined(IP_PKTINFO) && !defined(IP_RECVDSTADDR)
		return recvfrom(socket, buffer, bufferLen, flags, client, clientLen);
#else
		struct sockaddr_in *dst = (struct sockaddr_in *) srv;
		struct sockaddr_in *src = (struct sockaddr_in *) &srcAddr;
		
		if (*srvLen < sizeof(*dst)) {
			errno = EINVAL;
			return -1;
		}
		*srvLen = sizeof(*dst);
		*dst = *src;
#endif
	}	else if (srcAddr.ss_family == AF_INET6) {
#if !defined(IPV6_PKTINFO)
		return recvfrom(socket, buffer, bufferLen, flags, client, clientLen);
#else
		struct sockaddr_in6 *dst = (struct sockaddr_in6 *) srv;
		struct sockaddr_in6 *src = (struct sockaddr_in6 *) &srcAddr;
		
		if (*srvLen < sizeof(*dst)) {
			errno = EINVAL;
			return -1;
		}
		*srvLen = sizeof(*dst);
		*dst = *src;
#endif
	}

	// Set up iov and msgheader
	memset(&msgheader, 0, sizeof(struct msghdr));
	msg_iov.iov_base = buffer;
	msg_iov.iov_len  = bufferLen;
	msgheader.msg_control = control_buf;
	msgheader.msg_controllen = sizeof(control_buf);
	msgheader.msg_name = client;
	msgheader.msg_namelen = clientLen ? *clientLen : 0;
	msgheader.msg_iov  = &msg_iov;
	msgheader.msg_iovlen = 1;
	msgheader.msg_flags = 0;

	// Receive a packet
	if ((err = recvmsg(socket, &msgheader, flags)) < 0) {
		return err;
	}

	if (clientLen) *clientLen = msgheader.msg_namelen;

  control_msg = CMSG_FIRSTHDR(&msgheader);
	// Process ancillary data  received in msgheader - cmsg(3)
	for (control_msg;
	     control_msg != NULL;
	     control_msg = CMSG_NXTHDR(&msgheader,control_msg)) {
#ifdef IP_PKTINFO
		if ((control_msg->cmsg_level == SOL_IP) &&
		    (control_msg->cmsg_type == IP_PKTINFO)) {
      fprintf(stderr, "RECVFROM_TO IPv4\n");
      struct in_pktinfo *i =
        (struct in_pktinfo *) CMSG_DATA(control_msg);
			((struct sockaddr_in *)srv)->sin_addr = i->ipi_addr;
			*srvLen = sizeof(struct sockaddr_in);
			break;
		}
#endif

#ifdef IP_RECVDSTADDR
		if ((control_msg->cmsg_level == IPPROTO_IP) &&
		    (control_msg->cmsg_type == IP_RECVDSTADDR)) {
      fprintf(stderr, "RECVFROM_TO IPv4 IP_RECVDTSADDR\n");
			struct in_addr *i = (struct in_addr *) CMSG_DATA(control_msg);
			((struct sockaddr_in *)srv)->sin_addr = *i;
			*srvLen = sizeof(struct sockaddr_in);
			break;
		}
#endif

#ifdef IPV6_PKTINFO
		if ((control_msg->cmsg_level == IPPROTO_IPV6) &&
		    (control_msg->cmsg_type == IPV6_PKTINFO)) {
      fprintf(stderr, "RECVFROM_TO IPv6\n");
			struct in6_pktinfo *i =
			  (struct in6_pktinfo *) CMSG_DATA(control_msg);
			((struct sockaddr_in6 *)srv)->sin6_addr = i->ipi6_addr;
      *ifindex = i->ipi6_ifindex;
			*srvLen = sizeof(struct sockaddr_in6);
			break;
		}
#endif
	}
	return err;
}
/*
 * Add Server Source Address to outgoing packet so it matches the incoming (server/local) address
 * of the earlier received packet
 */
void addSrcAddr(struct msghdr* msgheader, void* control_buf, const struct sockaddr* srcAddr, uint ifindex)
{
	struct cmsghdr *control_msg = NULL;

  if(((struct sockaddr_in*) srcAddr)->sin_family == AF_INET6) {
  #ifdef IPV6_PKTINFO
    struct in6_pktinfo *packet;

    msgheader->msg_control = control_buf;
    msgheader->msg_controllen = CMSG_SPACE(sizeof(*packet));

    control_msg = CMSG_FIRSTHDR(msgheader);
    control_msg->cmsg_level = IPPROTO_IPV6;
    control_msg->cmsg_type = IPV6_PKTINFO;
    control_msg->cmsg_len = CMSG_LEN(sizeof(*packet));

    packet = (struct in6_pktinfo *) CMSG_DATA(control_msg);
    memset(packet, 0, sizeof(*packet));
    packet->ipi6_addr = ((struct sockaddr_in6*) srcAddr)->sin6_addr;
    packet->ipi6_ifindex = ifindex;
    msgheader->msg_controllen = control_msg->cmsg_len;
#endif
  }
  else {
#ifdef IP_PKTINFO
    struct in_pktinfo *packet;

    msgheader->msg_control = control_buf;
    msgheader->msg_controllen = CMSG_SPACE(sizeof(*packet));

    control_msg = CMSG_FIRSTHDR(msgheader);
    control_msg->cmsg_level = IPPROTO_IP;
    control_msg->cmsg_type = IP_PKTINFO;
    control_msg->cmsg_len = CMSG_LEN(sizeof(*packet));

    packet = (struct in_pktinfo *) CMSG_DATA(control_msg);
    memset(packet, 0, sizeof(*packet));
    packet->ipi_spec_dst = ((struct sockaddr_in *)srcAddr)->sin_addr;
    packet->ipi_ifindex = ifindex;
    msgheader->msg_controllen = control_msg->cmsg_len;
#endif
#ifdef IP_SENDSRCADDR
    struct in_addr *in;

    msgheader->msg_control = control_buf;
    msgheader->msg_controllen = CMSG_SPACE(sizeof(*in));

    control_msg = CMSG_FIRSTHDR(msgheader);
    control_msg->cmsg_level = IPPROTO_IP;
    control_msg->cmsg_type = IP_SENDSRCADDR;
    control_msg->cmsg_len = CMSG_LEN(sizeof(*in));

    in = (struct in_addr *) CMSG_DATA(control_msg);
    *in = source->sin4.sin_addr;
    msgheader->msg_controllen = control_msg->cmsg_len;
#endif
  }
}

/* 
 * Function similar to sendto but sets the source address of the outgoing
 * packet
 */
int sendto_from(int socket, void *buffer, size_t bufferLen, int flags,
	       struct sockaddr *clientAddr, socklen_t *clientLen,
	       struct sockaddr *srvAddr, socklen_t *srvLen, uint *ifindex)
{
	struct msghdr msgheader;
	struct cmsghdr *control_msg;
	struct iovec msg_iov;
	char control_buf[256];
  int err, count;

	// Set up iov and msgheader
	memset(&msgheader, 0, sizeof(struct msghdr));
	msg_iov.iov_base = buffer;
	msg_iov.iov_len  = bufferLen;
	msgheader.msg_control = control_buf;
	msgheader.msg_controllen = sizeof(control_buf);
	msgheader.msg_name = clientAddr;
	msgheader.msg_namelen = clientLen ? *clientLen : 0;
	msgheader.msg_iov  = &msg_iov;
	msgheader.msg_iovlen = 1;
	msgheader.msg_flags = 0;

  // In order to be able to get the server side address at which we got the message
  // we need proper support in recvmsg
#if !defined(IP_PKTINFO) && !defined(IP_RECVDSTADDR) && !defined (IPV6_PKTINFO)
	srvAddr = NULL:
#endif

	// IPv4 
	if (srvAddr->sa_family == AF_INET) {
#if !defined(IP_PKTINFO) && !defined(IP_RECVDSTADDR)
		return sendto(socket, buffer, bufferLen, 0, clientAddr, clientLen);
#else
    // struct sockaddr_in *from = (struct sockaddr_in *) srv;
    // struct sockaddr_in *to = (struct sockaddr_in *) &srcAddr;
		
    // addCMsgSrcAddr(&msgh, cbuf, p->d_anyLocal.get_ptr(), 0);
    
    // if (*srvLen < sizeof(*dst)) {
    //   errno = EINVAL;
    //   return -1;
    // }
    // *srvLen = sizeof(*dst);
    // *dst = *src;
#endif
	}	else if (srvAddr->sa_family == AF_INET6) { //IPv6
#if !defined(IPV6_PKTINFO)
		return sendto(socket, buffer, bufferLen, 0, clientAddr, clientLen);
#else
    // Add IPv6 address to socket to send from specific address
    addSrcAddr(&msgheader, control_buf, srvAddr, *ifindex);
#endif
	}
	// Send a packet
	count = sendmsg(socket, &msgheader, flags);  
  // err = del_ifaddress(srvAddr, *ifindex);
  return count;
}

/******************************************************************************
* Function: openSocket
*
* Description:
*    Open passive (server) sockets for the indicated inet service & protocol.
*    Notice in the last sentence that "sockets" is plural.  During the interim
*    transition period while everyone is switching over to IPv6, the server
*    application has to open two sockets on which to listen for connections...
*    one for IPv4 traffic and one for IPv6 traffic.
*
* Parameters:
*    port  - Pointer to a character string representing the well-known port
*               on which to listen (can be a service name or a decimal number).
*    desc     - Pointer to an array into which the socket descriptors are
*               placed when opened.
*    descSize - This is a value-result parameter.  On input, it contains the
*               max number of descriptors that can be put into 'desc' (i.e. the
*               number of elements in the array).  Upon return, it will contain
*               the number of descriptors actually opened.  Any unused slots in
*               'desc' are set to INVALID_DESC.
*
* Return Value:
*    0 on success, -1 on error.
******************************************************************************/
int openSocket( const char *port,
                     int         desc[ ],
                     size_t     *descSize ) {
  struct addrinfo *ai;
  int              aiErr;
  struct addrinfo *aiHead;
  struct addrinfo  hints    = { .ai_flags  = AI_PASSIVE,    /* Server mode. */
                               .ai_family = PF_UNSPEC };   /* IPv4 or IPv6 */
  size_t           maxDescs = *descSize;
  int err;

  // Initialize output parameters.  When the loop completes, *descSize is 0.
  while ( *descSize > 0 ) {
    desc[ --( *descSize ) ] = INVALID_DESC;
  }

  hints.ai_socktype = SOCK_STREAM; // TCP protocol
  hints.ai_protocol = IPPROTO_TCP;
  /*
  ** Look up the service's well-known port number.  Notice that NULL is being
  ** passed for the 'node' parameter, and that the AI_PASSIVE flag is set in
  ** 'hints'.  Thus, the program is requesting passive address information.
  ** The network address is initialized to :: (all zeros) for IPv6 records, or
  ** 0.0.0.0 for IPv4 records.
  */
  if ( ( aiErr = getaddrinfo( NULL,
                             port,
                             &hints,
                             &aiHead ) ) != 0 )
  {
    fprintf( stderr,
             "line %d: ERROR - %s.\n",
             __LINE__, gai_strerror( aiErr ) );
    return -1;
  }
  /*
  ** For each of the address records returned, attempt to set up a passive
  ** socket.
  */
  for ( ai = aiHead;
       ( ai != NULL ) && ( *descSize < maxDescs );
       ai = ai->ai_next ) {
    if ( verbose ) {
       /*
       ** Display the current address info.   Start with the protocol-
       ** independent fields first.
       */
       fprintf(stderr,
               "Setting up a passive socket based on the "
               "following address info:\n"
               "   ai_flags     = 0x%02X\n"
               "   ai_family    = %d (PF_INET = %d, PF_INET6 = %d)\n"
               "   ai_socktype  = %d (SOCK_STREAM = %d, SOCK_DGRAM = %d)\n"
               "   ai_protocol  = %d (IPPROTO_TCP = %d, IPPROTO_UDP = %d)\n"
               "   ai_addrlen   = %d (sockaddr_in = %lu, "
               "sockaddr_in6 = %lu)\n",
               ai->ai_flags,
               ai->ai_family,
               PF_INET,
               PF_INET6,
               ai->ai_socktype,
               SOCK_STREAM,
               SOCK_DGRAM,
               ai->ai_protocol,
               IPPROTO_TCP,
               IPPROTO_UDP,
               ai->ai_addrlen,
               sizeof(struct sockaddr_in),
               sizeof(struct sockaddr_in6));
       /*
       ** Now display the protocol-specific formatted socket address.  Note
       ** that the program is requesting that getnameinfo(3) convert the
       ** host & service into numeric strings.
       */
       getnameinfo(ai->ai_addr,
                   ai->ai_addrlen,
                   hostBfr,
                   sizeof(hostBfr),
                   servBfr,
                   sizeof(servBfr),
                   NI_NUMERICHOST | NI_NUMERICSERV);
       switch (ai->ai_family)
       {
          case PF_INET:   /* IPv4 address record. */
          {
             struct sockaddr_in *p = (struct sockaddr_in*) ai->ai_addr;
             fprintf(stderr,
                     "   ai_addr      = sin_family:   %d (AF_INET = %d, "
                     "AF_INET6 = %d)\n"
                     "                  sin_addr:     %s\n"
                     "                  sin_port:     %s\n",
                     p->sin_family,
                     AF_INET,
                     AF_INET6,
                     hostBfr,
                     servBfr);
             break;
          }  /* End CASE of IPv4. */
          case PF_INET6:   /* IPv6 address record. */
          {
             struct sockaddr_in6 *p = (struct sockaddr_in6*) ai->ai_addr;
             fprintf(stderr,
                     "   ai_addr      = sin6_family:   %d (AF_INET = %d, "
                     "AF_INET6 = %d)\n"
                     "                  sin6_addr:     %s\n"
                     "                  sin6_port:     %s\n"
                     "                  sin6_flowinfo: %d\n"
                     "                  sin6_scope_id: %d\n",
                     p->sin6_family,
                     AF_INET,
                     AF_INET6,
                     hostBfr,
                     servBfr,
                     p->sin6_flowinfo,
                     p->sin6_scope_id);
             break;
          }  // End CASE of IPv6
          default:   // Not IPv4 and not IPv6 ??
          {
             freeaddrinfo(aiHead);
             return -1;
           }  // End of Default
       }  // End SWITCH on protocol family
    }  // End IF verbose mode

    // Create a socket using the info in the addrinfo structure.
    CHECK( desc[*descSize] = socket( ai->ai_family, ai->ai_socktype, ai->ai_protocol ) );
    CHECK( setsockopt( desc[ *descSize ],
                     SOL_SOCKET, SO_REUSEADDR,
                     &(int){ 1 }, sizeof(int) ) );

    /*
    ** Here is the code that prevents "IPv4 mapped addresses"
    ** If an IPv6 socket was just created, then set the
    ** IPV6_V6ONLY socket option.
    */
    if ( ai->ai_family == PF_INET6 ) {
#if defined( IPV6_V6ONLY )
      // Disable IPv4 mapped addresses.
      int v6Only = 1;
      CHECK(setsockopt(desc[ *descSize],
            IPPROTO_IPV6,
            IPV6_V6ONLY,
            &v6Only,
            sizeof(v6Only)));
#else
      /*
      ** IPV6_V6ONLY is not defined, so the socket option can't be set and
      ** thus IPv4 mapped addresses can't be disabled.  Print a warning
      ** message and close the socket.  Design note: If the
      ** #if...#else...#endif construct were removed, then this program
      ** would not compile (because IPV6_V6ONLY isn't defined).  That's an
      ** acceptable approach; IPv4 mapped addresses are certainly disabled
      ** if the program can't build!  However, since this program is also
      ** designed to work for IPv4 sockets as well as IPv6, I decided to
      ** allow the program to compile when IPV6_V6ONLY is not defined, and
      ** turn it into a run-time warning rather than a compile-time error.
      ** IPv4 mapped addresses are still disabled because _all_ IPv6 traffic
      ** is disabled (all IPv6 sockets are closed here), but at least this
      ** way the server can still service IPv4 network traffic.
      */
      fprintf(stderr,
             "Line %d: WARNING - Cannot set IPV6_V6ONLY socket "
             "option.  Closing IPv6 %s socket.\n",
             __LINE__,
             ai->ai_protocol == IPPROTO_TCP  ?  "TCP"  :  "UDP" );
      CHECK( close( desc[ *descSize ] ) );
      continue;   // Go to top of FOR loop w/o updating *descSize!
#endif // IPV6_V6ONLY
      }  // End IF this is an IPv6 socket
      // Bind the socket.  The info from the addrinfo structure is used.
      CHECK( bind( desc[ *descSize ],
                 ai->ai_addr,
                 ai->ai_addrlen ) );
      /*
      ** If this is a TCP socket, put the socket into passive listening mode
      ** (listen is only valid on connection-oriented sockets).
      */
      if ( ai->ai_socktype == SOCK_STREAM ) {
         CHECK( listen( desc[ *descSize ],
                      MAXCONNQLEN ) );
      }
      // Socket set up okay.  Bump index to next descriptor array element.
      *descSize += 1;
  }  // End FOR each address info structure returned
   // Dummy check for unused address records.
   if ( verbose && ( ai != NULL ) ) {
      fprintf( stderr,
               "Line %d: WARNING - Some address records were "
               "not processed due to insufficient array space.\n",
               __LINE__ );
  }  /* End IF verbose and some address records remain unprocessed. */

  // Clean up.
  freeaddrinfo(aiHead);
  return 0;
}  // End openSckt()

/******************************************************************************
* Function: web_1x1png
*
* Description:
*    Listen on a set of sockets and send an HTTP response with a 1x1 PNG
*
* Parameters:
*    http_Socket     - Array of TCP socket descriptors on which to listen.
*    http_SocketSize - Size of the tcpSocket array (# of elements).
*    https_Socket     - Array of UDP socket descriptors on which to listen.
*    https_SocketSize - Size of the udpSocket array (# of elements).
*
* Return Value: None.
******************************************************************************/
void web_1x1png(int http_Socket[], size_t http_SocketSize,
                int https_Socket[], size_t https_SocketSize) {

  ssize_t                  count;
  struct pollfd           *desc;
  size_t                   descSize = http_SocketSize + https_SocketSize;
  int                      idx;
  int                      newSckt;
  int                      status;
  size_t                   StrLen;
  struct sockaddr         *sadr;
  socklen_t                sadrLen;
  struct sockaddr_storage  sockStor;
  struct sockaddr_storage  srv_sockStor;

  char       buffer[1500];
  int        outBytes;
  char       date[256];
  char       time_str[32];
  time_t     now;
  struct tm *tm_now;
  char secure = ' ';

  // Allocate memory for the poll(2) array.
  desc = malloc(descSize * sizeof(struct pollfd));
  if ( desc == NULL ) {
    fprintf( stderr,
             "(line %d): ERROR - %s.\n",
             __LINE__,
             strerror( ENOMEM ) );
    exit(1);
  }
  // Initialize the poll(2) array, merges the two socket arrays
  for (idx = 0; idx < descSize; idx++ ) {
    desc[idx].fd      = idx < http_SocketSize  ?  http_Socket[idx] // First array
                                           :  https_Socket[idx - http_SocketSize]; //second array
    desc[idx].events  = POLLIN;
    desc[idx].revents = 0;
  }

  // Initialise SSL
  SSL_CTX *ctx;
  init_openssl();
  ctx = create_context();
  configure_context(ctx);
  

  if (verbose) {
    fprintf(stderr, "Entering server loop\n");
  }
  // Main server loop.  Handles both TCP & UDP requests.  This is
  // an interative server, and all requests are handled directly within the
  // main loop.
  while (true) {// Forever
    // Wait for packets on any of the sockets.  The DO..WHILE construct is
    // used to restart the system call in the event the process is
    // interrupted by a signal.
    do {
      status = poll(desc, descSize, -1);  // Wait indefinitely for input
    } while ((status < 0) && (errno == EINTR));
    
    CHECK(status);
    // Got something
    for (idx = 0; idx < descSize; idx++) {
      switch (desc[idx].revents) {
        case 0:        // Not this socket, try next
           continue;
        case POLLIN:   // This is the one
           break;
        default:       // poll errors
           fprintf( stderr, "(line %d): ERROR - poll error (0x%02X).\n",
                    __LINE__, desc[idx].revents);
           exit(1);
      }  // End SWITCH on returned poll events


      // Obtain current time
      time(&now);
      tm_now = gmtime(&now);
      strftime(date, 256, "%a,%e %b %Y %I:%M:%S GMT", tm_now);
      strftime(time_str, 32, "%s.000", tm_now);

       // Determine if this is an HTTP or HTTPS request
      if (idx < http_SocketSize) { // Low index -> HTTP per merge above
        // HTTP connection requested.  Accept it.  Notice the use of
        // the sockaddr_storage data type.
        sadrLen = sizeof(sockStor);
        sadr    = (struct sockaddr*) &sockStor;
        CHECK(newSckt = accept(desc[idx].fd, sadr, &sadrLen));
        CHECK(shutdown(newSckt, SHUT_RD));// Server never recv's anything
        
        secure = ' ';
        // Client address-specific fields
        getnameinfo(sadr,
                   sadrLen,
                   hostBfr, // Global var
                   sizeof(hostBfr),
                   servBfr, // Global var
                   sizeof(servBfr),
                   NI_NUMERICHOST | NI_NUMERICSERV);

        if (verbose) {
          verbose_info(newSckt, sadr, sadrLen);
        }

        // Read some headers, mainly to avoid responding too quickly to the client
        // Don't really care what is in there as we are not parsing them
        count = read(newSckt, buffer, 1500);
        CHECK(count);

        gen_http_headers(buffer, &outBytes, date);
        while (outBytes > 0) {
           do {
              count = write(newSckt, buffer, outBytes);
           } while ( ( count < 0 ) && ( errno == EINTR ) );
           CHECK(count);
           outBytes -= count;
        }  // End WHILE there is data to send
        
        if (verbose) {
          fprintf(stderr, "Send PNG\n");
        }
        get_png(buffer, &outBytes);
        while (outBytes > 0) {
           do {
              count = write(newSckt, buffer, outBytes);
           } while ( ( count < 0 ) && ( errno == EINTR ) );
           CHECK(count);
           outBytes -= count;
        }  // End WHILE there is data to send

        CHECK(close(newSckt));
        // End HTTP
      }  else {
        SSL *ssl;
        
        sadrLen = sizeof(sockStor);
        sadr    = (struct sockaddr*) &sockStor;
        
        if (verbose) {
          fprintf(stderr, "SSL Connection\n");
        }
        CHECK(newSckt = accept(desc[idx].fd, sadr, &sadrLen));
        // Client address-specific fields
        getnameinfo(sadr,
                   sadrLen,
                   hostBfr, // Global var
                   sizeof(hostBfr),
                   servBfr, // Global var
                   sizeof(servBfr),
                   NI_NUMERICHOST | NI_NUMERICSERV);
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, newSckt);

        secure = 's';
        if (verbose) {
          verbose_info(newSckt, sadr, sadrLen);
        }

        if(verbose) {
          fprintf(stderr,"SSL Accept\n");
        }
        if (SSL_accept(ssl) <= 0) {
           ERR_print_errors_fp(stderr);
           exit(1);
        }

        // Read some headers, mainly to avoid responding too quickly to the client
        // Don't really care what is in there as we are not parsing them
        count = SSL_read(ssl, buffer, 1500);
        if (count <= 0) {
           ERR_print_errors_fp(stderr);
           exit(1);
        }
        
        // write HTTP headers
        gen_http_headers(buffer, &outBytes, date);
        if(verbose) {
          fprintf(stderr,"Send Headers\n");
        }

        count = SSL_write(ssl, buffer, outBytes);
        if (count <= 0) {
           ERR_print_errors_fp(stderr);
           exit(1);
        }
        count = outBytes;
        get_png(buffer+count, &outBytes);
        count += outBytes;
        if(verbose) {
          fprintf(stderr,"Send PNG\n");
        }
        count = SSL_write(ssl, buffer, count);
        if (verbose) {
          fprintf(stderr,"PNG write count: %ld\n", count);
        }
        if (count <= 0) {
           ERR_print_errors_fp(stderr);
           exit(1);
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        CHECK(close(newSckt));
      } // End HTTPS
      log_write(date, secure, time_str);
      desc[idx].revents = 0;   /* Clear the returned poll events. */
    }  // End FOR each socket descriptor.
  }  // End WHILE forever.
}

void gen_http_headers(char *buffer, int* len, char *date) {
  char    *headers[10];
  int slen = 0;
  
  headers[0] = "HTTP/1.1 200 OK\r\n";
  headers[1] = "Server: apnic/1.0.0\r\n";
  headers[2] = "Date: : ";
  headers[3] = date;
  headers[4] = "\r\nContent-Type: image/png\r\n";
  headers[5] = "Content-Length: 68\r\n"; // Length of the PNG image
  headers[6] = "Last-Modified: Mon, 28 Sep 1970 06:00:00 GMT\r\n";
  headers[7] = "Connection: keep-alive\r\n";
  headers[8] = "Access-Control-Allow-Origin: *\r\n";
  headers[9] = "\r\n";

  int i;
  // Cat headers together
  for (i=0; i<10; i++) {
    strcpy(buffer+slen, headers[i]);
    slen += strlen(headers[i]);
  }
  *len = slen;
  if (verbose) {
    fprintf(stderr, "All Headers: %s", buffer);
  }
}
/****************************************************************************************************/
void get_png(char *buffer, int *len) {
  const unsigned char png[] = 
  {0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52, \
   0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4, \
   0x89, 0x00, 0x00, 0x00, 0x0a, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00, \
   0x05, 0x00, 0x01, 0x0d, 0x0a, 0x2d, 0xb4, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, \
   0x42, 0x60, 0x82, 0x00};

  memcpy(buffer, png, sizeof(png));
  *len = sizeof(png);
}
/****************************************************************************************************/
void log_write(char *date, char secure, char *timestamp) {
  fprintf(stdout, \
    "%s %s [%s] \"GET something HTTP/1.1\" 200 68 \"-\" \"Some web browser\" \"Some TLS version\" 0.0000 http%c %s some-URL\n",\
    server_hostname, hostBfr, date, secure, timestamp);
}
/****************************************************************************************************/
void verbose_info(int socket, struct sockaddr *sadr, socklen_t sadrLen) {
  struct sockaddr         *clientAddr;
  socklen_t                clientAddrLen;

  struct sockaddr         *srvAddr;
  socklen_t                srvAddrLen;
  uint                     ifIndex;

  struct sockaddr_storage  sockStor;
  struct sockaddr_storage  srv_sockStor;
  
  size_t                   StrLen;
  char                    *ClientStr;
  

  srvAddrLen = sizeof(sockStor);
  srvAddr    = (struct sockaddr*) &srv_sockStor;

  if (getsockname(socket, srvAddr, &srvAddrLen)) {
    return; // KABOOM!
  };
  // Display the socket address of the remote client.  Begin with
  // the address-independent fields
  fprintf(stderr,
           "Sockaddr info for new TCP client:\n"
           "   sa_family = %d (AF_INET = %d, AF_INET6 = %d)\n"
           "   addr len  = %d (sockaddr_in = %ld, "
           "sockaddr_in6 = %ld)\n",
           sadr->sa_family,
           AF_INET,
           AF_INET6,
           sadrLen,
           sizeof(struct sockaddr_in),
           sizeof(struct sockaddr_in6));

  // Already done in the calling function with global var
  // // Client address-specific fields
  // getnameinfo(sadr,
  //            sadrLen,
  //            hostBfr,
  //            sizeof(hostBfr),
  //            servBfr,
  //            sizeof(servBfr),
  //            NI_NUMERICHOST | NI_NUMERICSERV);

  // Server address-specific fields.
  getnameinfo(srvAddr,
              srvAddrLen,
              srvBfr,
              sizeof(srvBfr),
              srvportBfr,
              sizeof(srvportBfr),
              NI_NUMERICHOST | NI_NUMERICSERV);

  switch ( sadr->sa_family ) {
    case AF_INET:  // IPv4 address
    {
      struct sockaddr_in *p = (struct sockaddr_in*) sadr;
      fprintf(stderr,
              "Client info: \n"
              "   sin_addr  = sin_family: %d\n"
              "               sin_addr:   %s\n"
              "               sin_port:   %s\n",
              p->sin_family,
              hostBfr,
              servBfr );

      // Print the server address that got the packet
      p = (struct sockaddr_in*) srvAddr;
      fprintf(stderr,
              "Server address: \n"
              "   sin_addr  = sin_family: %d\n"
              "               sin_addr:   %s\n"
              "               sin_port:   %s\n",
              p->sin_family,
              srvBfr,
              srvportBfr );
       break;
    }  // End CASE of IPv4
    case AF_INET6:  // IPv6 address
    {
      struct sockaddr_in6 *p = (struct sockaddr_in6*) sadr;
      fprintf(stderr,
              "Client info: \n"
              "   sin6_addr = sin6_family:   %d\n"
              "               sin6_addr:     %s\n"
              "               sin6_port:     %s\n"
              "               sin6_flowinfo: %d\n"
              "               sin6_scope_id: %d\n",
              p->sin6_family,
              hostBfr,
              servBfr,
              p->sin6_flowinfo,
              p->sin6_scope_id);

      // Print the server address that got the packet
      p = (struct sockaddr_in6*) srvAddr;
      fprintf(stderr,
              "Server address: \n"
              "   sin_addr  = sin6_family: %d\n"
              "               sin6_addr:   %s\n"
              "               sin6_port:   %s\n",
              p->sin6_family,
              srvBfr,
              srvportBfr);
      break;
    }  // End CASE of IPv6
    default:   // Not IPv4 and not IPv6 ??
    {
      // TODO add something if you want to deal with this
       break;
    }  // End of Default
  }  /* End SWITCH on address family. */

  // Store the client's IP address
  // ClientStr = hostBfr;
  // StrLen = strlen(ClientStr);

  // Write the client's IP address to stderr
  // fprintf(stderr, "Client's address is %s.\n", hostBfr);

}

/******************************************************************************
* Function: main
*
* Description:
*    Simple server that binds on TCP and UDP, IPv4 and IPv6
*    On IPv6 listens on all addresses of a whole prefix
*    Sends back text with the addresses of both endpoints
*
* Parameters:
*    argc and argv
*
* Return Values:
*    Should run forever, exit if it can't create sockets
******************************************************************************/
int main(int argc, char *argv[])
{
  int         opt;
  const char *http_port   = DEFAULT_HTTP_PORT;
  const char *https_port   = DEFAULT_HTTPS_PORT;
  int         http_Socket[ MAX_HTTP_SOCKETS ];     /* Array of HTTP socket descriptors. */
  size_t      http_SocketSize = MAX_HTTP_SOCKETS;  /* Size of http_Socket (# of elements).   */
  int         https_Socket[ MAX_HTTPS_SOCKETS ];     /* Array of HTTPS socket descriptors. */
  size_t      https_SocketSize = MAX_HTTPS_SOCKETS;  /* Size of https_Socket (# of elements).   */

  // Set the program name (w/o directory prefix).
  execName = strrchr( argv[ 0 ], '/' );
  execName = execName == NULL  ?  argv[ 0 ]  :  execName + 1;

  // Process command options.
  opterr = 0;   // Turns off "invalid option" error messages
  while ( ( opt = getopt( argc, argv, CLI_OPTS ) ) >= 0 ) {
    switch ( opt ) {
      case 'v':   // Verbose mode
        verbose = true;
        break;
      case 'p': // HTTP port
        http_port = optarg;
        break;
      case 's': // HTTPS port
        https_port = optarg;
        break;
      default:
        usage(execName);
    }  // End SWITCH on command option
  }  // End WHILE processing options
  // // Process command line arguments.
  // switch ( argc - optind ) {
  //   case 0:  break;
  //   case 1:  port = argv[ optind ]; break;
  //   default:  usage(execName);
  // }
  // Open TCP sockerts for both HTTP and HTTPS port, for each of IPv4 & IPv6
  if ((openSocket(http_port, http_Socket, &http_SocketSize) < 0) ||
      (openSocket(https_port, https_Socket, &https_SocketSize) < 0))
  {
    exit(1);
  }
  
  if (gethostname(server_hostname, NI_MAXHOST)) {
    strcpy(server_hostname, "no.server.name"); // Could not get hostname
  }

  // Run the "web" server.
  if ((http_SocketSize > 0) || (https_SocketSize > 0)) {
    web_1x1png(http_Socket, http_SocketSize, https_Socket, https_SocketSize);
  }

  // web_1x1png() never returns, but socket creation might fail
  if (verbose) {
    fprintf( stderr, "Couldn't open sockets, bailing.\n");
  }
  return 0;
}  // End main()