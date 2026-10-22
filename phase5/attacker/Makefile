CC = gcc
CFLAGS = -O2 -Wall -Wextra
LDLIBS = -lpcap

all: zonewalker

zonewalker: zonewalker.c
	$(CC) $(CFLAGS) -o zonewalker zonewalker.c $(LDLIBS)

clean:
	rm -f zonewalker

.PHONY: all clean
