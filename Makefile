.DEFAULT_GOAL := all

clean:
	rm *.o tcp-server test-server udp_server

web-1x1.o: web-1x1.c
	gcc -c web-1x1.c -I /usr

tcp-server.o: tcp-server.c
	gcc -c tcp-server.c

test-server: test-server.c
	gcc -c test-server.c

udp_server: udp_server.c
	gcc -c udp_server.c

all: tcp-server.o test-server.o udp_server.o web-1x1.o
	gcc -o tcp-server tcp-server.o
	gcc -o test-server test-server.o
	gcc -o udp_server udp_server.o
	gcc -o web-1x1 web-1x1.o  -L/usr/lib/x86_64-linux-gnu/ -lssl -lcrypto
	