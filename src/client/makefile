CC=gcc
CFLAGS=-Wall -Wextra -fsanitize=undefined -fsanitize=address -lmcheck -g -lcrypto

clientPr: client.o intclient.o ../util.o
	$(CC) -o clientPr ../util.o intclient.o client.o $(CFLAGS)

clean:
	rm  *.o clientPr ../util.o
