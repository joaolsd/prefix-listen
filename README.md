### Listen on a whole prefix

Code that shows how to listen on a whole (IPv6) prefix and respond to packets addressed to any address in that prefix.
Also, code that uses this and pretends to be a webserver returning HTTP headers and 1x1 PNG as payload.

In addition to the code you need a Linux system where you configure a local route table entry that ties the target prefix to the loopback interface.

	ip route add local 2001:db8:1:1::/64 dev lo

Check it is there with:
	ip -6 route list table local

and, of course the network itself needs a route pointing to the server/host as the destination for the prefix.