CC = gcc
CFLAGS = -O2 -Wall -Wextra
LDLIBS = -lpcap

all: interceptor

interceptor: interceptor.c
	$(CC) $(CFLAGS) -o interceptor interceptor.c $(LDLIBS)

clean:
	rm -f interceptor

.PHONY: all clean
