CC=gcc
CFLAGS=-Wall -Wextra -fsanitize=undefined -g -lcrypto -lmcheck

serverPr: server.o intserver.o ../util.o
	$(CC) -o serverPr ../util.o intserver.o server.o $(CFLAGS)

clean:
	rm  *.o serverPr ../util.o

