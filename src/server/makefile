CC=gcc
CFLAGS=-Wall -lcrypto

serverPr: server.o intserver.o ../util.o
	$(CC) -o serverPr ../util.o intserver.o server.o $(CFLAGS)

clean:
		rm  *.o serverPr

