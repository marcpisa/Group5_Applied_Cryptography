#include "util.h"

void gestioneRichiesta(int cd, struct sockaddr_in cl_addr, char* buffer, struct cv_peer* registered_peers, int *numPeer);
	//Funzione che gestisce la richiesta da parte di un peer

int mod(int a, int b);
	//Funzione che restituisce a modulo b
