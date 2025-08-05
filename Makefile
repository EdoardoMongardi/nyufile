CC = gcc
CFLAGS = -Wall -Wextra -std=c17 -O2
LDFLAGS = -lcrypto

all: nyufile

nyufile: nyufile.c
	$(CC) $(CFLAGS) nyufile.c -o nyufile $(LDFLAGS)

clean:
	rm -f nyufile
