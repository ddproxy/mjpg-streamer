###############################################################
#
# Purpose: Makefile for "M-JPEG Streamer"
# Author.: Tom Stoeveken (TST)
# Version: 0.3
# License: GPL
#
###############################################################

CC = gcc

OTHER_HEADERS = ../../mjpg_streamer.h ../../utils.h ../output.h ../input.h

CFLAGS += -O1 -DLINUX -D_GNU_SOURCE -Wall -shared -fPIC
#CFLAGS +=  -g
#CFLAGS += -DDEBUG
LFLAGS += -lpthread -ldl 

all: output_https.so

clean:
	rm -f *.a *.o core *~ *.so *.lo

output_https.so: $(OTHER_HEADERS) output_https.c httpd.lo security.o
	$(CC) $(CFLAGS) -o $@ output_https.c httpd.lo security.o -lssl -lcrypto

httpd.lo: $(OTHER_HEADERS) httpd.h httpd.c
	$(CC) -c $(CFLAGS) -o $@ httpd.c -lcrypto -lssl
	
security.o: security.h security.c
	$(CC) -c $(CFLAGS) -o $@ security.c -lcrypto -lssl
	
