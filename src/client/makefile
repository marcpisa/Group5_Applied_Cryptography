all: clientPr

clientPr: client.o intclient.o
	gcc -Wall -o clientPr client.o intclient.o -lcrypto

client.o: intclient.h
intpeer.o: intclient.h ../util.h

clean:
		rm  *.o clientPr

