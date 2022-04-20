#include "intserver.h"

void gestioneRichiesta (int cd, struct sockaddr_in cl_addr, char* buffer, struct cv_peer* registered_peers, int *numPeer)
{
	int ret, i, j, len, s, app, ind, hop;
	socklen_t addrlen;
	char buffer_app[BUF_LEN];
	addrlen = sizeof(cl_addr);

	//strcpy(buffer_copy, buffer);
	//Controllo se il peer è già registrato
	/* Creiamo delle associazioni tra cosa abbiamo ricevuto in ingresso e una variabile per lo switch per capire cosa dobbiamo fare:
		REQ_JOIN = 1;
		REQ_CNG = 2;
		REQ_STOP = 3;
		ERRORE RICHIESTA = 0;*/
	
	if (strcmp(buffer, REQ_JOIN) == 0) s = 1;
	else if (strcmp(buffer, REQ_CNG) == 0) s = 2;
	else if (strcmp(buffer, REQ_STOP) == 0) s = 3;
	else s = 0;
	switch(s)
	{
		case 1: //REQ_JOIN
	
			printf("La richiesta dal client è di tipo join... \n");

			//CONTROLLO DI NON AVER RAGGIUNTO IL LIMITE MASSIMO DI PEER CONNESSI ALLA RETE
			if (*numPeer == MAX_PEER)
			{
				sprintf(buffer, "%i", REQ_DEN);
				len = sizeof(int);
				ret = sendto(cd, buffer, len, 0, (struct sockaddr*)&cl_addr, addrlen);	
				if (ret < 0)
				{
					perror("Errore in fase di invio dati: ");
					exit(-1);
				} 
				break;
			}
			
			for (i = 0; i < *numPeer; i++)
			{
				//CONTROLLO CHE NON SI SIA GIà REGISTRATO IN PRECEDENZA
				if (cl_addr.sin_port == registered_peers[i].p_port && cl_addr.sin_addr.s_addr == registered_peers[i].p_addr)
				{
					printf("Il client che ha chiesto di registrarsi si è già registrato in precedenza...\n");
					printf("Gli rimando i dati...\n");
					registered_peers[i].changes = 0;
					break;;
				}
				if (cl_addr.sin_port < registered_peers[i].p_port)
				{
					for (j = *numPeer - 1; j >= i; j--)
					{
						registered_peers[j+1].p_port = registered_peers[j].p_port;
						registered_peers[j+1].p_addr = registered_peers[j].p_addr;
						registered_peers[j+1].changes = registered_peers[j].changes;
					}
					registered_peers[i].p_addr = cl_addr.sin_addr.s_addr;
					inet_ntop(AF_INET, (void *)&cl_addr.sin_addr, buffer_app, INET_ADDRSTRLEN);
					registered_peers[i].p_port = cl_addr.sin_port;
					registered_peers[i].changes = 0;
					printf("Nuovo peer con indirizzo ip: %s e porta %i salvato...\n", buffer_app, ntohs(cl_addr.sin_port));
					//AUMENTIAMO IL NUMERO DI PEER APPARTENENTI AL NETWORK
					(*numPeer)++;
					break;
				}
			}
			// CASO IN CUI ABBIAMO FINITO IL FOR SENZA ESSERE STATO INSERITO
			if (i == *numPeer)
			{
				registered_peers[*numPeer].p_addr = cl_addr.sin_addr.s_addr;
				inet_ntop(AF_INET, (void *)&cl_addr.sin_addr, buffer_app, INET_ADDRSTRLEN);
				registered_peers[*numPeer].p_port = cl_addr.sin_port;
				registered_peers[*numPeer].changes = 0;
				//AUMENTIAMO IL NUMERO DI PEER APPARTENENTI AL NETWORK
				(*numPeer)++;
				printf("Nuovo peer con indirizzo ip: %s e porta %i salvato...\n", buffer_app, ntohs(cl_addr.sin_port));
			}
			memset(buffer, 0, strlen(buffer));
			if (*numPeer == 1 || *numPeer == 2) sprintf(buffer, "%i", *numPeer-1);
			else sprintf(buffer, "%i", 2);
			sscanf(buffer, "%i", &app);
			printf("Il numero di neighbors del nuovo client è %i...\n", app);

			len = sizeof(int);
			ret = sendto(cd, buffer, len, 0, (struct sockaddr*)&cl_addr, addrlen);
			if (ret < 0)
			{
				perror("Errore in fase di invio dati: ");
				exit(-1);
			}
			// INIZIO GESTIONE PER LA COMUNICAZIONE DEI VICINI
			if (*numPeer == 2)
			{
			//CASO DEL SECONDO PEER CONNESSO
				//INVIO DELL'INDIRIZZO DEL PEER
				ind = mod(i+1, *numPeer); //Settiamo l'indice
				inet_ntop(AF_INET, (void *)&registered_peers[ind].p_addr, buffer, INET_ADDRSTRLEN);
				addrlen = sizeof(cl_addr);
				ret = sendto(cd, buffer, INET_ADDRSTRLEN, 0, (struct sockaddr*)&cl_addr, addrlen);
				if (ret < 0)
				{
					perror("Errore in fase di invio dell'indirizzo del neighbor: ");
					exit(-1);
				}
				
				//INVIO DELLA PORTA DEL PEER
				len = DIM_PORT;
				sprintf(buffer, "%i", ntohs(registered_peers[ind].p_port));
				addrlen = sizeof(cl_addr);
				ret = sendto(cd, buffer, len, 0, (struct sockaddr*)&cl_addr, addrlen);
				if (ret < 0)
				{
					perror("Errore in fase di invio della porta del neighbor: ");
					exit(-1);
				}
				//RICORDIAMO CHE IL PRIMO PEER HA AVUTO UN CAMBIAMENTO DI VICINATO
				registered_peers[ind].changes = 1;
			}
			else if (*numPeer > 2)
			{
				// INVIO DELL'INDIRIZZO DEL PRIMO PEER VICINO
				ind = mod(i-1, *numPeer); //Settiamo l'indice
				inet_ntop(AF_INET, (void *)&registered_peers[ind].p_addr, buffer, INET_ADDRSTRLEN);
				addrlen = sizeof(cl_addr);
				ret = sendto(cd, buffer, INET_ADDRSTRLEN, 0, (struct sockaddr*)&cl_addr, addrlen);
				if (ret < 0)
				{
					perror("Errore in fase di invio dell'indirizzo del neighbor: ");
					exit(-1);
				}
				
				//INVIO DELLA PORTA DEL PRIMO PEER VICINO
				len = DIM_PORT;
				sprintf(buffer, "%i", ntohs(registered_peers[ind].p_port));
				addrlen = sizeof(cl_addr);
				ret = sendto(cd, buffer, len, 0, (struct sockaddr*)&cl_addr, addrlen);
				if (ret < 0)
				{
					perror("Errore in fase di invio della porta del neighbor: ");
					exit(-1);
				}
				printf("Gli sto mandando la porta %s\n", buffer);
				registered_peers[ind].changes = 1; //PER INDICARE CHE SONO CAMBIATI I SUOI VICINI
				
				//INVIO DELL'INDIRIZZO DEL SECONDO PEER VICINO
				ind = mod(i+1, *numPeer); //Settiamo l'indice
				inet_ntop(AF_INET, (void *)&registered_peers[ind].p_addr, buffer, INET_ADDRSTRLEN);
				addrlen = sizeof(cl_addr);
				ret = sendto(cd, buffer, INET_ADDRSTRLEN, 0, (struct sockaddr*)&cl_addr, addrlen);
				if (ret < 0)
				{
					perror("Errore in fase di invio dell'indirizzo del neighbor: ");
					exit(-1);
				}
				
				//INVIO DELLA PORTA DEL SECONDO PEER VICINO
				len = DIM_PORT;
				sprintf(buffer, "%i", ntohs(registered_peers[ind].p_port));
				printf("Gli sto mandando la porta %s\n", buffer);
				addrlen = sizeof(cl_addr);
				ret = sendto(cd, buffer, len, 0, (struct sockaddr*)&cl_addr, addrlen);
				if (ret < 0)
				{
					perror("Errore in fase di invio della porta del neighbor: ");
					exit(-1);
				}
				registered_peers[ind].changes = 1;
			}
			//INVIO DEL NUMERO DI HOP
			if (*numPeer <= 4) hop = 0;
			else hop = (*numPeer-1)/2 - 1;
			len = DIM_HOP;
			sprintf(buffer, "%i", hop);
			ret = sendto(cd, buffer, len, 0, (struct sockaddr*)&cl_addr, addrlen);
			if (ret < 0)
			{
				perror("Errore in fase di invio del numero di hop al peer che si è iscritto: ");
				exit(-1);
			}
			printf("Ora i peer connessi sono %i... \n", *numPeer);
			
			break;
		case 2: //REQ_CNG
			for (i = 0; i < *numPeer; i++)
			{
				if (cl_addr.sin_port == registered_peers[i].p_port && cl_addr.sin_addr.s_addr == registered_peers[i].p_addr)
				{
					if (registered_peers[i].changes != 0)
					{
						if (*numPeer > 2) sprintf(buffer, "%i", ACNG2);
						else sprintf(buffer, "%i", ACNG1);
						len = REQ_DIM;
						ret = sendto(cd, buffer, len, 0, (struct sockaddr*)&cl_addr, addrlen);
						if (ret < 0)
						{
							perror("Errore in fase di invio per la richiesta di cambiamenti: ");
							exit(-1);
						}
						// MANDIAMO AL PEER CHE LI HA RICHIESTI I SUOI VICINI
						ind = mod(i-1, *numPeer);
						len = INET_ADDRSTRLEN;
						//sprintf(buffer, "%i", registered_peers[ind].p_addr);
						inet_ntop(AF_INET, (void *)&registered_peers[ind].p_addr, buffer, INET_ADDRSTRLEN);
						ret = sendto(cd, buffer, len, 0, (struct sockaddr*)&cl_addr, addrlen);
						if (ret < 0)
						{
							perror("Errore in fase di invio dati: ");
							exit(-1);
						}
	
						len = DIM_PORT;
						sprintf(buffer, "%i", ntohs(registered_peers[ind].p_port));
						ret = sendto(cd, buffer, len, 0, (struct sockaddr*)&cl_addr, addrlen);
						if (ret < 0)
						{
							perror("Errore in fase di invio dati: ");
							exit(-1);
						}
						
						if (*numPeer > 2)
						{
							len = INET_ADDRSTRLEN;
							ind = mod(i+1, *numPeer);
							inet_ntop(AF_INET, (void *)&registered_peers[ind].p_addr, buffer, INET_ADDRSTRLEN);
							ret = sendto(cd, buffer, len, 0, (struct sockaddr*)&cl_addr, addrlen);
							if (ret < 0)
							{
								perror("Errore in fase di invio dati: ");
								exit(-1);
							}
							printf("Indirizzo ip %s inviato con successo", buffer);
		
							len = DIM_PORT;
							sprintf(buffer, "%i", ntohs(registered_peers[ind].p_port));
							ret = sendto(cd, buffer, len, 0, (struct sockaddr*)&cl_addr, addrlen);
							if (ret < 0)
							{
								perror("Errore in fase di invio dati: ");
								exit(-1);
							}
							printf("Numero porta %s inviato con successo", buffer);
						}
						// RESETTIAMO LA VARIABILE CHANGES DATO CHE GLIELI ABBIAMO GIà COMUNICATI
						registered_peers[i].changes = 0;
						printf("Comunicazione cambio neighbors avvenuta con successo...\n");
					}
					else
					{
						//NON CI SONO STATI CAMBIAMENTI DI VICINANZA E GLIELO COMUNICHIAMO
						sprintf(buffer, "%i", NCNG);
						len = REQ_DIM;
						ret = sendto(cd, buffer, len, 0, (struct sockaddr*)&cl_addr, addrlen);
						if (ret < 0)
						{
							perror("Errore in fase di invio per la richiesta di cambiamenti: ");
							exit(-1);
						}
						printf("Non ci sono stati cambiamenti di vicinanza... Comunicazione effettuata\n");
					}
					if (*numPeer <= 4) hop = 0;
					else hop = (*numPeer-1)/2 -1;
					len = DIM_HOP;
					sprintf(buffer, "%i", hop);
					ret = sendto(cd, buffer, len, 0, (struct sockaddr*)&cl_addr, addrlen);
					if (ret < 0)
					{
						perror("Errore in fase di invio del numero di hop al peer che si è iscritto: ");
						exit(-1);
					}
					return;	
				}
			}
			printf("Il peer che ci ha contattato non è registrato al network...\n");
			break;
		case 3: //REQ_STOP
			printf ("Richiesta di tipo stop...\n");
			for (i = 0; i < *numPeer; i++)
			{
				if (cl_addr.sin_addr.s_addr == registered_peers[i].p_addr && cl_addr.sin_port == registered_peers[i].p_port)
				{
					//SALVIAMO AI SUOI NEIGHBORS IL CAMBIAMENTO DI VICINANZA
					ind = mod(i-1, *numPeer);
					registered_peers[ind].changes = 1;
					ind = mod(i+1, *numPeer);
					registered_peers[ind].changes = 1;
					for (; i < (*numPeer)-1; i++)
					{
							registered_peers[i].p_addr = registered_peers[i+1].p_addr;
							registered_peers[i].p_port = registered_peers[i+1].p_port;
							registered_peers[i].changes = registered_peers[i+1].changes;
					}
					registered_peers[i].p_addr = 0;
					registered_peers[i].p_port = 0;
					registered_peers[i].changes = 0;
					printf("Eliminata struttura dati che faceva riferimento al client che ha fatto la richiesta...\n");
					
					addrlen = sizeof(cl_addr);
					len = REQ_DIM;
					strcpy(buffer, REQ_ACC);
					ret = sendto(cd, buffer, len, 0, (struct sockaddr*)&cl_addr, addrlen);
					(*numPeer)--;
					break;
				}
			}
			break;
		default: //ERRORE RICHIESTA
				printf("La richiesta da parte del client non è corretta. Non verrà presa in considerazione...\n");
			break;
	}
	return;
}

int mod(int a, int b)
{
	int r = a % b;
	return r < 0 ? r + b: r;
}
