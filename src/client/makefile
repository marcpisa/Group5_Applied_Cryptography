CC=gcc
CFLAGS=-Wall -Wextra -fsanitize=undefined -fsanitize=address -lmcheck -g -lcrypto

# -fsanitize=undefined -fsanitize=address -lmcheck

clientPr: client.o intclient.o ../util.o
	$(CC) -o clientPr ../util.o intclient.o client.o $(CFLAGS)

clean:
	rm  *.o clientPr ../util.o
