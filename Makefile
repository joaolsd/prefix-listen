.DEFAULT_GOAL := all
.PHONY: check-env install clean

WEB-1x1_RUN_TEMPLATE=run-web-1x1.sh.tmpl

check-env:
ifndef HOST
	$(error HOST is undefined)
endif

clean:
	$(RM) *.o tcp-server test-server udp_server

web-1x1.o: web-1x1.c
	gcc -c web-1x1.c -I /usr

tcp-server.o: tcp-server.c
	gcc -c tcp-server.c

test-server: test-server.c
	gcc -c test-server.c

udp_server: udp_server.c
	gcc -c udp_server.c

config: check-env ${WEB-1x1_SERVIVE_TEMPLATE}
	@echo "making $(HOST)"
	sed -e "s/@cc@/$(HOST)/g" < ${WEB-1x1_RUN_TEMPLATE} > run-web-1x1.sh
	

all: tcp-server.o test-server.o udp_server.o web-1x1.o
	gcc -o tcp-server tcp-server.o
	gcc -o test-server test-server.o
	gcc -o udp_server udp_server.o
	gcc -o web-1x1 web-1x1.o  -L/usr/lib/x86_64-linux-gnu/ -lssl -lcrypto

install: all config
	/usr/bin/install -m 755 web-1x1 /usr/local/bin
	/usr/bin/install -m 755 run-web-1x1.sh /usr/local/bin
	/usr/bin/install -m 755 web-1x1.service /etc/systemd/system
