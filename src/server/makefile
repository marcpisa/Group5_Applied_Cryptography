CC=gcc
CFLAGS=-Wall -Wextra -fsanitize=undefined -fsanitize=address -lmcheck -g -lcrypto

# -fsanitize=undefined -fsanitize=address -lmcheck

serverPr: server.o intserver.o ../util.o
	$(CC) -o serverPr ../util.o intserver.o server.o $(CFLAGS)

clean:
	rm  *.o serverPr ../util.o

