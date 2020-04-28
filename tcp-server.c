/*
 * tcp-server.c
 * 
 * A simple TCP server that demonstrates an IPv6 wildcard socket binding
 * Code adaptyed from W. Stevens Unix Newtwork Programming Vol 1.
 * Compiled on Debian.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include <arpa/inet.h>

/* error return */
void
error(char *msg) {
  perror(msg);
  exit(1);
  }

/* tcp sesion handler
 * respond to incoming TCP connections with a string of the current
 * time of day, and then echo's back a single message and terminate the
 * tcp session
 */

void 
handle_session(int ssockfd) {
  time_t now=time(0);
  char buffer[80];
  size_t index ;
  int n ;
  size_t length=strftime(buffer,sizeof(buffer),"%a %b %d %T %Y\n",localtime(&now));
  if (length==0) {
    snprintf(buffer,sizeof(buffer),"Error: buffer overflow\n");
    }

  /* upon session start write the local time to the remote client */

  index=0;
  while (index<length) {
    ssize_t count=write(ssockfd,buffer+index,length-index);
    if (count<0) {
      if (errno==EINTR) continue;
      error("failed to write to socket");
      } 
    else {
      index+=count;
      }
    }

  memset(buffer,0, 256);
    
  /* recieve a message from the remote client */

  n = recv(ssockfd, buffer, 255, 0);
  if (n < 0)
      error("ERROR reading from socket");

  printf("Message from client: %s\n", buffer);

  /* and send it back to the client */

  n = send(ssockfd, "Server got your message\n", 23+1, 0);
  if (n < 0)
    error("ERROR writing to socket");
    
  return;
  }

/*
 * tcp server
 *
 * set up a resident process listening on the nominated port with an IPv6 wildcard
 * and invoke the session handler for each new incoming session
 */

int 
main(int argc, char *argv[]) {
    int sockfd, portno;
    char buffer[256];
    struct sockaddr_in6 serv_addr;
    int n;
    int reuseaddr=1;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <port number>\n", argv[0]);
        exit(0);
        }

    printf("\nIPv6 TCP Server Started...\n");
    
    //Sockets Layer Call: socket()
    sockfd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (sockfd < 0)
      error("ERROR opening socket");

    if (setsockopt(sockfd,SOL_SOCKET,SO_REUSEADDR,&reuseaddr,sizeof(reuseaddr))<0)
      error("ERROR setting REUSE socket option") ;

    bzero((char *) &serv_addr, sizeof(serv_addr));

    /* the port number is provided through the CLI as the arg to the server */
    portno = atoi(argv[1]);
    serv_addr.sin6_flowinfo = 0;
    serv_addr.sin6_family = AF_INET6;

    /* the IPv6 address is the IPv6 wildcard defined in netinet/in.h */
    serv_addr.sin6_addr = in6addr_any;
    serv_addr.sin6_port = htons(portno);

    
    /* bind the socket to the IPv6 wildcard address */
    if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
        error("ERROR on binding");

    /* set up the server's listen status */
    listen(sockfd, SOMAXCONN);

    for (;;) {
      struct sockaddr_in6 cli_addr ;
      socklen_t clilen = sizeof(cli_addr);
      pid_t pid ;
      int newsockfd;
      char client_addr_ipv6[256] ;
    
      /* rendezvous with incoming conections */

      if (((newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen))) < 0)
        error("ERROR on accept");

      inet_ntop(AF_INET6, &(cli_addr.sin6_addr),client_addr_ipv6, 100);
      printf("Incoming connection from client having IPv6 address: %s\n",client_addr_ipv6);

      /* and pass them to a forked session handler */

      pid=fork();
      if (pid<0) {
        error("failed to create child process") ;
        } 
      else if (pid==0) {
        close(sockfd);
        handle_session(newsockfd);
        close(newsockfd);
        _exit(0);
        } 
      else {
        close(newsockfd);
        }
    }
}
