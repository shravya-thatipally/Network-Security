CC=gcc
CFLAGS=-g -Wall 
LIBS=-lpthread -lcrypto
pbproxy: pbproxy.c
	$(CC) -o pbproxy pbproxy.c $(CFLAGS) $(LIBS)


.PHONY: clean
clean:
	rm -f *.o pbproxy
