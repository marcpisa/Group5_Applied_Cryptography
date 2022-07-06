all: serverPr

serverPr: server.o intserver.o
	gcc -Wall -o serverPr server.o intserver.o

server.o: intserver.h
intserver.o: intserver.h ../util.h

clean:
		rm  *.o serverPr