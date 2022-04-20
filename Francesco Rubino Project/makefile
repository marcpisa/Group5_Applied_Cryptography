all: peer ds initCovid

peer: peer.o intpeer.o
	gcc -Wall -o peer peer.o intpeer.o

ds: server.o intserver.o
	gcc -Wall -o ds server.o intserver.o

initCovid: initCovid.o
	gcc -Wall -o initCovid initCovid.o

peer.o: intpeer.h
intpeer.o: intpeer.h util.h
server.o: intserver.h
intserver.o: intserver.h util.h

clean:
		rm  *.o peer ds initCovid
		rm -r /tmp/covid-FrancescoRubino


