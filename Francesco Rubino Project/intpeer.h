#include "util.h"

int askForChanges(int listenerUDP, struct sockaddr_in* neigh_addr, struct sockaddr_in srv_addr, int *numNeighbors, int *hop);
	//Funzione utilizzata dal peer ogni qual volta voglia controllare che i vicini siano rimasti gli stessi. Utilizzata di solito prima che il peer inizi delle comunicazioni

void aggiornaEntry(char* path, char* comando, int numero);
	//Funzione che aggiorna il dato indicato in 'comando' nell'entry giornaliera aggiungendoci il valore specificato in numero

void aggiornaRegister(char* path, int nc, int tam, int gua);
	//Funzione che aggiorna o crea il file specificato in 'path' con i valori indicati nelle altre variabili

int floodForEntries(char* file, int port, struct sockaddr_in* neigh_addr, int numNeighbors, int hop);
	//Funzione di flooding per la richiesta di file che il peer non ha relativo al giornio indicato nel nome del file

void floodForEntriesManager(int sd, char* mex, int port, struct sockaddr_in* neigh_addr, int numNeighbors);
	//Funzione che gestisce una richiesta di flooding da parte di un vicino

int getGuarigioni(char* path, int *res);
	//Funzione che restituisce le guarigioni relative al file indicato nella variabile path

int getNuoviCasi(char* path, int *res);
	//Funzione che restituisce i nuovi casi relativi al file indicato nella variabile path

int getTamponi(char* path, int *res);
	//Funzione che restituisce i tamponi relative al file indicato nella variabile path

int getAll(char* path, int *nc, int *tam, int *gua);
	//Funzione che restituisce tutti i dati relatvi al file indicato nella variabile path

void sendYourData(struct sockaddr_in* neigh_addr, int numNeighbors, int port);
	//Funzione utilizzata da un peer per diffondere nel network i propri dati giornalieri

void requestManager(int sd, char* mex, int port);
	//Funzione che gestisce un REQ_DATA da parte di un vicino

void dailyDataManager(int sd, char* mex, int port, struct sockaddr_in* neigh_addr, int numNeighbors);
	//Funzione che gestisce l'arrivo di un dato giornaliero di un peer del network

void updateDailyTotal(int port);
	//Funzione che salva i dati giornaleri ricevuti da tutti i peer del network


int split(char* orig, char* str1, char* str2, char* del);
	//Funzione che divide il buffer orig in due parti (in str1 e str2) al primo riscontro del delimitatore del

int stringToDate(char* string, int *day, int *mon, int *year);
	//Funzione che interpreta la data contenuta in string e la traduce in interi su day, mon e year

int mod(int a, int b);
	//Funzione che restituisce a modulo b
