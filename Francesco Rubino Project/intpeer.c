#include "intpeer.h"

int askForChanges(int listenerUDP, struct sockaddr_in* neigh_addr, struct sockaddr_in srv_addr, int *numNeighbors, int *hop)
{
	int ret, i, len, app, port;
	socklen_t addrlen;
	
	char buffer[BUF_LEN];
	
	addrlen = sizeof(srv_addr);

	//PREAMBOLO
	len = REQ_DIM;
	strcpy(buffer, REQUEST);
	ret = sendto(listenerUDP, buffer, len, 0, (struct sockaddr*)&srv_addr, addrlen);
	if (ret < 0)
	{
		perror("Errore in fase di invio: ");
		exit(-1);
	}
	len = REQ_DIM;
	ret = recvfrom(listenerUDP, buffer, len, 0, (struct sockaddr*)&srv_addr, &addrlen);
	if (ret < 0)
	{
		perror("Errore in fase di ricezione dati: ");
		exit(-1);
	}
	
	//TIPOLOGIA RICHIESTA
	len = REQ_DIM;
	strcpy(buffer, REQ_CNG);
	ret = sendto(listenerUDP, buffer, len, 0, (struct sockaddr*)&srv_addr, addrlen);
	if (ret < 0)
	{
		perror("Errore in fase di richiesta di cambio vicini: ");
		exit(-1);
	}
	len = sizeof(int);
	memset(buffer, 0, strlen(buffer));
	ret = recvfrom(listenerUDP, buffer, len, 0, (struct sockaddr*)&srv_addr, &addrlen);
	if (ret < 0)
	{
			perror("Errore in fase di ricezione dati per ricahiedere se ci sono stati vicini: ");
			exit(-1);
	}
	app = atoi(buffer);
	if (app == NCNG); /*{printf("Non ci sono stati cambiamenti dei neighbors...\n");}*/
	else if (app == ACNG1 || app == ACNG2)
	{
		printf("Ci sono stati dei cambiamenti di neighbors...\n\n");
		*numNeighbors = app; //aggiorno il numero di neighbors per il peer

			printf("Ora i vicini sono:\n\n");
		for (i = 0; i < *numNeighbors; i++)
		{
			memset(&neigh_addr[i], 0, sizeof(neigh_addr[i]));
			neigh_addr[i].sin_family = AF_INET;
			addrlen = sizeof(srv_addr);
			ret = recvfrom(listenerUDP, buffer, INET_ADDRSTRLEN, 0, (struct sockaddr*)&srv_addr, &addrlen);
			if (ret < 0)
			{
				perror("Errore in ricezione dell'indirizzo di un neighbor: ");
				exit(-1);
			}
			inet_pton(AF_INET, buffer, &neigh_addr[i].sin_addr);
			printf("Neighbor No%i:\n   Indirizzo IP: %s\n   ", i+1, buffer);
		
			len = DIM_PORT;
			ret = recvfrom(listenerUDP, buffer, len, 0, (struct sockaddr*)&srv_addr, &addrlen);
			if (ret < 0)
			{
				perror("Errore in ricezione dela porta di un neighbor: ");
				exit(-1);
			}
			port = atoi(buffer);
			printf("No porta: %i\n\n", port); 
			neigh_addr[i].sin_port = htons(port);
		}
	}
	else {printf("Risposta del server in seguito ad askForChanges non avvenuta con successo...\n\n"); return -1;}
	
	//ORA IL SERVER MANDERà IL NUMERO DI HOP DA UTILIZZARE IN UNA EVENTUALE FLOOD FOR ENTRIES
	memset(buffer, 0, strlen(buffer));
	len = DIM_HOP;
	ret = recvfrom(listenerUDP, buffer, len, 0, (struct sockaddr*)&srv_addr, &addrlen);
	if (ret < 0)
	{
		perror("Errore in fase di invio del numero di hop al peer che si è iscritto: ");
		exit(-1);
	}
	*hop = atoi(buffer);
	return 0;
}


void updateDailyTotal(int port)
{
	int gua, nc, tam;
	time_t t;
	struct tm tm;
	char bufferApp1[BUF_LEN];
	char bufferApp2[BUF_LEN];
	char bufferApp3[BUF_LEN];
	char bufferApp4[BUF_LEN];
	char bufferApp5[BUF_LEN];
	char bufferApp6[BUF_LEN];
	char path[BUF_LEN];
	FILE* fd1;

	t = time(NULL);
	tm = *localtime(&t);

	//INIZIALIZZO I BUFFER
	strcpy(bufferApp1, "");
	strcpy(bufferApp2, "");
	strcpy(bufferApp3, "");
	strcpy(bufferApp4, "");
	strcpy(bufferApp5, "");
	strcpy(bufferApp6, "");

	//PRENDIAMO I DATI DALLA DAILY LIST
	chdir("/tmp");
	if (chdir("covid-FrancescoRubino") == -1)
	{
		mkdir("covid-FrancescoRubino", S_IRWXU);
		chdir("covid-FrancescoRubino");
	}
	sprintf(path, "port%i", port);
	if (chdir(path) == -1)
	{
		mkdir(path, S_IRWXU);
		chdir(path);
	}
	fd1  = fopen("dailyList.txt", "r");
	if (fd1 < 0)
	{
		printf("Errore: file dailyList.txt non esistente");
		return;
	}
	fscanf(fd1, "%s %i %i %i", bufferApp1, &nc, &tam, &gua);
	fclose(fd1);

	if (chdir("totali_giornalieri") == -1)
	{
		mkdir("totali_giornalieri", S_IRWXU);
		chdir("totali_giornalieri");
	}
	strcpy(bufferApp1, "nuoviCasi");
	strcpy(bufferApp3, "tamponi");
	strcpy(bufferApp5, "guarigioni");
	sprintf(bufferApp2, "%i", nc);
	sprintf(bufferApp4, "%i", tam);
	sprintf(bufferApp6, "%i", gua);

	sprintf(path, "%02d-%02d-%d.txt", tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900);
	fd1 = fopen(path, "w");
	fprintf(fd1, "%s %s %s %s %s %s", bufferApp1, bufferApp2, bufferApp3, bufferApp4, bufferApp5, bufferApp6);
	fclose(fd1);
	return;
}


void aggiornaEntry(char* path, char* comando, int numero)
{
	FILE* fd1;
	int totale;
	char bufferApp1[BUF_LEN];
	char bufferApp2[BUF_LEN];
	char bufferApp3[BUF_LEN];
	char bufferApp4[BUF_LEN];
	char bufferApp5[BUF_LEN];
	char bufferApp6[BUF_LEN];
	
	//LO FACCIO PER EVENTUALMENTE CREARE IL FILE
	fd1 = fopen(path, "a+");
	fclose(fd1);

	// AZZERO TUTTI I BUFFER
	strcpy(bufferApp1, "");
	strcpy(bufferApp2, "");
	strcpy(bufferApp3, "");
	strcpy(bufferApp4, "");
	strcpy(bufferApp5, "");
	strcpy(bufferApp6, "");
	fd1 = fopen(path, "r");
	printf("Aperto il file!\n");
	fscanf(fd1, "%s %s %s %s %s %s", bufferApp1, bufferApp2, bufferApp3, bufferApp4, bufferApp5, bufferApp6);
	fclose(fd1);

	if (strcmp(bufferApp1, "") == 0) //FILE APERTO PER LA PRIMA VOLTA
	{
		printf("File aperto per la prima volta, ora lo configuro...\n");
		strcpy(bufferApp1, "nuoviCasi");
		strcpy(bufferApp3, "tamponi");
		strcpy(bufferApp5, "guarigioni");
		if (strcmp(comando, "nuoviCasi")==0)
		{
			printf("Prima di inserire i nuovi casi inserire i tamponi...  I tamponi devono essere più della somma di nuovi casi e guarigioni...\n");
			return;
		}
		else if (strcmp(comando, "tamponi")==0)
		{
			sprintf(bufferApp2, "%i", 0);
			sprintf(bufferApp4, "%i", numero);
			sprintf(bufferApp6, "%i", 0);
		}
		else
		{
			printf("Prima di inserire le guarigioni inserire i tamponi... I tamponi devono essere più della somma di nuovi casi e guarigioni...\n");
			return;
		}
		printf("Configurazione e sottomissione dati avvenuta con successo...\n");
	}
	else
	{
		printf("Aggiornamento in corso...\n");
		if (strcmp(comando, "nuoviCasi")==0)
		{
			totale = atoi(bufferApp4) - numero - atoi(bufferApp2) - atoi(bufferApp6);
			if (totale < 0)
			{
				printf("Non ci sono abbastanza tamponi per giustificare i nuovi casi...  I tamponi devono essere più della somma di nuovi casi e guarigioni...\n");
				return;
			}
			totale = atoi(bufferApp2) + numero;
			sprintf(bufferApp2, "%i", totale);
		}
		else if (strcmp(comando, "tamponi") == 0)
		{
			totale = atoi(bufferApp4) + numero;
			sprintf(bufferApp4, "%i", totale);
		}
		else
		{
			totale = atoi(bufferApp4) - atoi(bufferApp2) - atoi(bufferApp6) - numero;
			if (totale < 0)
			{
				printf("Non ci sono abbastanza tamponi per giustificare le guarigioni...  I tamponi devono essere più della somma di nuovi casi e guarigioni...\n");
				return;
			}
			totale = atoi(bufferApp6) + numero;
			sprintf(bufferApp6, "%i", totale);
		}
		printf("Aggiornamento avvenuto con successo!\n");
	}
	// LO APRO IN SCRITTURA PERCHè VOGLIO CHE ELIMINI QUELLO CHE C'è PRIMA
	fd1 = fopen(path, "w");
	printf("Il dati giornalieri ora sono i seguenti:  %s:%s %s:%s %s:%s\n", bufferApp1, bufferApp2, bufferApp3, bufferApp4, bufferApp5, bufferApp6);
	fprintf(fd1, "%s %s %s %s %s %s", bufferApp1, bufferApp2, bufferApp3, bufferApp4, bufferApp5, bufferApp6);
	fclose(fd1);
	return;
}

void aggiornaRegister(char* path, int nc, int tam, int gua)
{
	FILE* fd1;
	char bufferApp1[BUF_LEN];
	char bufferApp2[BUF_LEN];
	char bufferApp3[BUF_LEN];
	char bufferApp4[BUF_LEN];
	char bufferApp5[BUF_LEN];
	char bufferApp6[BUF_LEN];
	
	//LO FACCIO PER EVENTUALMENTE CREARE IL FILE
	fd1 = fopen(path, "a+");
	fclose(fd1);

	// AZZERO TUTTI I BUFFER
	strcpy(bufferApp1, "");
	strcpy(bufferApp2, "");
	strcpy(bufferApp3, "");
	strcpy(bufferApp4, "");
	strcpy(bufferApp5, "");
	strcpy(bufferApp6, "");
	
	strcpy(bufferApp1, "nuoviCasi");
	strcpy(bufferApp3, "tamponi");
	strcpy(bufferApp5, "guarigioni");
	sprintf(bufferApp2, "%i", nc);
	sprintf(bufferApp4, "%i", tam);
	sprintf(bufferApp6, "%i", gua);
	
	fd1 = fopen(path, "w");
	fprintf(fd1, "%s %s %s %s %s %s", bufferApp1, bufferApp2, bufferApp3, bufferApp4, bufferApp5, bufferApp6);
	fclose(fd1);
	return;
}





int floodForEntries(char* file, int port, struct sockaddr_in* neigh_addr, int numNeighbors, int hop)
{
	int i, ret, new_sd, app, nbytes, nc, tam, gua;
	socklen_t addrlen;
	struct sockaddr_in peer_addr;
	char buffer[BUF_LEN];
	char bufferApp1[BUF_LEN];
	char bufferApp2[BUF_LEN];
	char bufferApp3[BUF_LEN];
	char bufferApp4[BUF_LEN];
	char bufferApp5[BUF_LEN];

	//FORMATO MESSAGGIO: flood_for_entries my_port hops name_file
	sprintf(buffer, "%s %i %i %s", FLOOD_FOR_ENTRIES, port, hop, file);

	for (i = 0; i < numNeighbors; i++)
	{
		if (neigh_addr[i].sin_port == port) continue;
		new_sd = socket(AF_INET, SOCK_STREAM, 0);
		peer_addr = neigh_addr[i];
		addrlen = sizeof(peer_addr);
		ret = connect(new_sd, (struct sockaddr*)&peer_addr, addrlen);
		if (ret < 0)
		{
			perror("Errore in fase di connessione con il peer vicino: ");
			exit(-1);
		}

		//MANDO LA DIMENSIONE
		nbytes = COM_LEN;
		app = strlen(buffer);
		memset(bufferApp1, 0, strlen(buffer));
		sprintf(bufferApp1, "%i", app);
		ret = send(new_sd, bufferApp1, nbytes, 0);
		if (ret < 0)
		{
			perror("Errore in fase di invio: ");
			exit(-1);	
		}
		//IL BUFFER è STATO GIà PREPARATO PRIMA
		nbytes = app;
		ret = send(new_sd, buffer, nbytes, 0);
		if (ret < 0)
		{
			perror("Errore in fase di invio: ");
			exit(-1);
		}
		// ORA RICEVEREMO LA RISPOSTA
		nbytes = COM_LEN;
		memset(bufferApp1, 0, strlen(bufferApp1));
		ret = recv(new_sd, bufferApp1, nbytes, 0); //Ora uso bufferApp1 perchè buffer non voglio sporcarlo per i prossimi cicli del for
		if (ret < 0)
		{
			perror("Errore in fase di ricezione: ");
			exit(-1);
		}
		nbytes = atoi(bufferApp1);
		ret = recv(new_sd, bufferApp1, nbytes, 0);
		if (ret < 0)
		{
			perror("Errore in fase di ricezione");
			exit(-1);
		}
		close(new_sd);
		
		printf("Ho ricevuto %s\n", bufferApp1);
		sscanf(bufferApp1, "%s %s %s %s", bufferApp2, bufferApp3, bufferApp4, bufferApp5);
		if (strcmp(bufferApp2, REPLY_FOR_ENTRIES) != 0)
		{
			printf("Errore in ricezione sul messaggio mandato dal neighbor.. Non è un replyForEntries\n\n");
			continue;
		}

		if (strcmp(bufferApp3, NOT_FOUND) == 0)
		{
			printf("Ricevuto un messaggio di not found da un neighbor...\n\n");	
		}
		else
		{
			//UTILIZZO LA FUNZIONE AGGIORNA REGISTER
			printf("Dato mancante trovato in rete!\n\n");
			nc = atoi(bufferApp3);
			tam = atoi(bufferApp4);
			gua = atoi(bufferApp5);
			aggiornaRegister(file, nc, tam, gua);
			return 1;
		}
	}
	printf("Nessuno è riuscito a trovare il dato di cui avevamo bisogno...\n\n");
	return -1;
}

void floodForEntriesManager(int sd, char* mex, int port, struct sockaddr_in* neigh_addr, int numNeighbors)
{
	int i, ret, new_sd, app, len, orig_port, hop, nc, tam, gua;
	socklen_t addrlen;
	struct sockaddr_in peer_addr;
	char buffer[BUF_LEN];
	char bufferApp1[BUF_LEN];
	char bufferApp2[BUF_LEN];
	char bestResult[BUF_LEN];
	char file[BUF_LEN];
	char path[BUF_LEN];
	FILE* fd1;

	sscanf(mex, "%s %i %i %s", bufferApp1, &orig_port, &hop, file);
	//Controlliamo se abbiamo il file
	chdir("/tmp");
	if (chdir("covid-FrancescoRubino") == -1)
	{
		mkdir("covid-FrancescoRubino", S_IRWXU);
		chdir("covid-FrancescoRubino");
	}
	sprintf(path, "port%i", port);
	if (chdir(path) == -1)
	{
		mkdir(path, S_IRWXU);
		chdir(path);
	}
	if (chdir("totali_giornalieri") == -1)
	{
		mkdir("totali_giornalieri", S_IRWXU);
		chdir("totali_giornalieri");
	}
	fd1 = fopen(file, "r");
	if (fd1 == NULL)
	{
		//VUOL DIRE CHE NON CE LO ABBIAMO
		if (hop == 0 || numNeighbors == 1)
		{
			//MASSIMO DEGLI HOP RAGGIUNTO: PREPARO IL MESSAGGIO DI NOT FOUND
			memset(buffer, 0, strlen(buffer));
			sprintf(buffer, "%s %s", REPLY_FOR_ENTRIES, NOT_FOUND);

			printf("Mando messaggio di not found ad un neighbor a seguito di richiesta di un entry...\n");
			len = COM_LEN;
			app = strlen(buffer);
			sprintf(bufferApp2, "%i", app);
			ret = send(sd, bufferApp2, len, 0);
			if (ret < 0)
			{
				perror("Errore in fase di invio : ");
				exit(-1);
			}
			len = strlen(buffer);
			ret = send(sd, buffer, len, 0);
			if (ret < 0)
			{
				perror("Errore in fase di invio");
				exit(-1);
			}
			return;
		}
		else
		{
			//PREPARO LA RICHIESTA PER IL FLOODING
			memset(buffer, 0, strlen(buffer));
			printf("Non ho il dato richiesto dal vicino. Provo a chiederee all'altro vicino...\n");
			
			sprintf(buffer, "%s %i %i %s", bufferApp1, port, hop-1, file);
			for (i = 0; i < numNeighbors; i++)
			{
				memset(bestResult, 0, strlen(bestResult));
				
				if (neigh_addr[i].sin_port == htons(orig_port)) continue;
				peer_addr = neigh_addr[i];
				addrlen = sizeof(peer_addr);
				new_sd = socket(AF_INET, SOCK_STREAM, 0);
			
				ret = connect(new_sd, (struct sockaddr*)&peer_addr, addrlen);
				if (ret < 0)
				{
					perror("Errore in fase di connect: ");
					exit(-1);
				}

				len = COM_LEN;
				app = strlen(buffer);
				sprintf(bufferApp2, "%i", app);
				ret = send(new_sd, bufferApp2, len, 0);
				if (ret < 0)
				{
					perror("Errore in fase di invio: ");
					exit(-1);
				}

				len = strlen(buffer);
				ret = send(new_sd, buffer, len, 0);
				if (ret < 0)
				{
					perror("Errore in fase di invio: ");
					exit(-1);
				}

				len = COM_LEN;
				memset(bufferApp2, 0, strlen(bufferApp2));
				ret = recv(new_sd, bufferApp2, len, 0);
				if (ret < 0)
				{
					perror("Errore in fase di ricezione: ");
					exit(-1);
				}

				len = atoi(bufferApp2);
				ret = recv(new_sd, bestResult, len, 0);
				if (ret < 0)
				{
					perror("Errore in fase di ricezione: ");
					exit(-1);
				}

				close(new_sd);
				//CONTROLLIAMO SE CI HA DATO IL RISULTATO
				memset(bufferApp1, 0, strlen(bufferApp1));
				memset(bufferApp2, 0, strlen(bufferApp2));
				sscanf(bestResult, "%s %s", bufferApp1, bufferApp2);
				if (strcmp(bufferApp2, NOT_FOUND) != 0)
				{
					//VUOL DIRE CHE è ARRIVATO IL RISULTATO, LO MANDIAMO A CHI LO HA CHIESTO
					len = COM_LEN;
					memset(bufferApp1, 0, strlen(bufferApp1));
					app = strlen(bestResult);
					sprintf(bufferApp1, "%i", app);
					ret = send(sd, bufferApp1, len, 0);
					if (ret < 0)
					{
						perror("Errore in fase di invio: ");
						exit(-1);
					}
				
					len = strlen(bestResult);
					ret = send(sd, bestResult, len, 0);
					if (ret < 0)
					{
						perror("Errore in fase di invio: ");
						exit(-1);
					}
					printf("Abbiamo inviato la risposta al peer che ha chiesto il flooding...\n\n");
					return;
				}
				else printf("Il vicino %i non ha trovato la entry richiesta...\n", neigh_addr[i].sin_port);
			}
			// SE SIAMO ARRIVATI FIN QUI VUOL DIRE CHE NESSUNO CI HA DATO UNA RISPOSTA SODDISFACENTE, QUINDI GLIELO DICIAMO A CHI LO HA CHIESTO A NOI
			len = COM_LEN;
			memset(bufferApp1, 0, strlen(bufferApp1));
			app = strlen(bestResult);
			sprintf(bufferApp1, "%i", app);
			ret = send(sd, bufferApp1, len, 0);
			if (ret < 0)
			{
				perror("Errore in fase di invio: ");
				exit(-1);
			}
		
			len = strlen(bestResult);
			ret = send(sd, bestResult, len, 0);
			if (ret < 0)
			{
				perror("Errore in fase di invio: ");
				exit(-1);
			}
			printf("Abbiamo inviato la risposta al peer che ha chiesto il flooding... è not_found\n\n");
			return;
		}
	}
	else
	{
		ret = getAll(file, &nc, &tam, &gua);
		if (ret < 0)
		{
			printf("Ci deve essere stato un errore perchè il file non esiste...\n\n");
			return;
		}
		//PREPARO IL BUFFER CON LA RISPOSTA
		memset(buffer, 0, strlen(buffer));
		sprintf(buffer, "%s %i %i %i", REPLY_FOR_ENTRIES, nc, tam, gua);
		
		//ORA GLIELO MANDO
		len = COM_LEN;
		app = strlen(buffer);
		memset(bufferApp1, 0, strlen(bufferApp1));
		sprintf(bufferApp1, "%i", app);
		ret = send(sd, bufferApp1, len, 0);
		if (ret < 0)
		{
			perror("Errore in fase di invio: ");
			exit(-1);
		}
		
		len = strlen(buffer);
		ret = send(sd, buffer, len, 0);
		if (ret < 0)
		{
			perror("Errore in fase di invio: ");
			exit(-1);
		}
		printf("Abbiamo inviato la risposta al peer che ha chiesto il flooding...\n\n");
		return;	
	}
}


int getGuarigioni(char* path, int *res)
{
	FILE* fd1;
	char bufferApp1[BUF_LEN];
	char bufferApp2[BUF_LEN];
	char bufferApp3[BUF_LEN];
	char bufferApp4[BUF_LEN];
	char bufferApp5[BUF_LEN];
	char bufferApp6[BUF_LEN];

	fd1 = fopen(path, "r");
	if (fd1 == NULL)
	{
		printf("Nessun file trovato...\n");
		return -1;				
	}
	fscanf(fd1, "%s %s %s %s %s %s", bufferApp1, bufferApp2, bufferApp3, bufferApp4, bufferApp5, bufferApp6);
	fclose(fd1);
	*res = atoi(bufferApp6);
	return 1;
}

int getNuoviCasi(char* path, int *res)
{
	FILE* fd1;
	char bufferApp1[BUF_LEN];
	char bufferApp2[BUF_LEN];
	char bufferApp3[BUF_LEN];
	char bufferApp4[BUF_LEN];
	char bufferApp5[BUF_LEN];
	char bufferApp6[BUF_LEN];

	fd1 = fopen(path, "r");
	if (fd1 == NULL)
	{
		printf("Nessun file trovato...\n");
		return -1;				
	}
	fscanf(fd1, "%s %s %s %s %s %s", bufferApp1, bufferApp2, bufferApp3, bufferApp4, bufferApp5, bufferApp6);
	fclose(fd1);
	*res = atoi(bufferApp2);
	return 1;
}

int getAll(char* path, int *nc, int *tam, int *gua)
{
	FILE* fd1;
	char bufferApp1[BUF_LEN];
	char bufferApp2[BUF_LEN];
	char bufferApp3[BUF_LEN];
	char bufferApp4[BUF_LEN];
	char bufferApp5[BUF_LEN];
	char bufferApp6[BUF_LEN];

	fd1 = fopen(path, "r");
	if (fd1 == NULL)
	{
		printf("Nessun file trovato...\n");
		return -1;				
	}
	fscanf(fd1, "%s %s %s %s %s %s", bufferApp1, bufferApp2, bufferApp3, bufferApp4, bufferApp5, bufferApp6);
	fclose(fd1);
	*nc = atoi(bufferApp2);
	*tam = atoi(bufferApp4);
	*gua = atoi(bufferApp6);
	return 1;
}

int getTamponi(char* path, int *res)
{
	FILE* fd1;
	char bufferApp1[BUF_LEN];
	char bufferApp2[BUF_LEN];
	char bufferApp3[BUF_LEN];
	char bufferApp4[BUF_LEN];
	char bufferApp5[BUF_LEN];
	char bufferApp6[BUF_LEN];

	fd1 = fopen(path, "r");
	if (fd1 == NULL)
	{
		printf("Nessun file trovato...\n");
		return -1;				
	}
	fscanf(fd1, "%s %s %s %s %s %s", bufferApp1, bufferApp2, bufferApp3, bufferApp4, bufferApp5, bufferApp6);
	fclose(fd1);
	*res = atoi(bufferApp4);
	return 1;
}


void sendYourData(struct sockaddr_in* neigh_addr, int numNeighbors, int port)
{
	int ret, i, sd, app, gua, nc, tam, len;
	time_t t1;
	struct tm tm1;
	socklen_t addrlen;
	struct sockaddr_in peer_addr;
	char buffer[BUF_LEN];
	char bufferApp1[BUF_LEN];
	char path[BUF_LEN];

	char prova[BUF_LEN];

	//PREPARIAMO IL BUFFER
	chdir("/tmp");
	if (chdir("covid-FrancescoRubino") == -1)
	{
		mkdir("covid-FrancescoRubino", S_IRWXU);
		chdir("covid-FrancescoRubino");
	}
	sprintf(path, "port%i", port);
	if (chdir(path) == -1)
	{
		mkdir(path, S_IRWXU);
		chdir(path);
	}
	if (chdir("dati_giornalieri") == -1)
	{
		mkdir("dati_giornalieri", S_IRWXU);
		chdir("dati_giornalieri");
	}
		//NOME DEL FILE
	t1 = time(NULL);
	tm1 = *localtime(&t1);
	// SCRIVIAMO IL NOME DEL FILE IN BUFFER E CI FACCIAMO DARE IL DATO CHE CI SERVE DALLA GETALL
	sprintf(buffer, "%02d-%02d-%d.txt", tm1.tm_mday, tm1.tm_mon + 1, tm1.tm_year + 1900);
	//printf("Nel buffer per aprire il file c'è scritto %s\n", buffer);
	ret = getAll(buffer, &nc, &tam, &gua);
	if (ret < 0)
	{
		printf("Non abbiamo nessun dato da inviare agli altri peer. Oggi non abbiamo registrato niente...\n\n");
		return;
	}
	else printf("Abbiamo dei dati da mandare...\n");

	// ORA POSSIAMO INSERIRE IL DATO OTTENUTO NEL BUFFER
			/*Il numero di porta lo inserisco due volte perchè il primo sta significare chi è l'origine del dato, il secondo chi è il neighbor che lo manda
				Quando verrà ricevuto da altri peer il primo rimane lo stesso mentre il secondo prima lo controlleranno per evitare di mandare il messaggio a chi glielo ha 
				mandato e poi lo sostituiranno con il proprio*/
	sprintf(bufferApp1, "%s %i %i %i %i %i", DAILY_DATA, port, port, nc, tam, gua);
	
	memset(buffer, 0, strlen(buffer));
	for (i = 0; i < numNeighbors; i++)
	{
		peer_addr = neigh_addr[i];
		inet_ntop(AF_INET, (void*)&peer_addr.sin_addr, prova, INET_ADDRSTRLEN);
		printf("Stiamo contattando: %s %i\n", prova, ntohs(peer_addr.sin_port));
		addrlen = sizeof(peer_addr);
		sd = socket(AF_INET, SOCK_STREAM, 0);
		ret = connect(sd, (struct sockaddr*)&peer_addr, addrlen);
		if (ret < 0)
		{
			perror("Errore in fase di connect: ");
			exit(-1);
		}
		printf("Connessione con il vicino effettuata...\n\n");
		// MANDO LA DIMENSIONE		
		len = COM_LEN;
		app = strlen(bufferApp1);
		sprintf(buffer, "%i", app);
		ret = send(sd, buffer, len, 0);
		if (ret < 0)
		{
			perror("Errore in fase di invio: ");
			exit(-1);
		}
		
		//ORA MANDO IL DATO
		len = strlen(bufferApp1);
		ret = send(sd, bufferApp1, len, 0);
		if (ret < 0)
		{
			perror("Errore in fase di invio: ");
			exit(-1);
		}

		//MI FACCIO MANDARE UN ACK
		len = REQ_DIM;
		memset(buffer, 0, strlen(buffer));
		ret = recv(sd, buffer, len, 0);
		if (ret < 0)
		{
			perror("Errorein fase di ricezione: ");
			exit(-1);		
		}
	
		if (strcmp(buffer, ACK) != 0) printf("Errore nella ricezione dell'ack da parte del neighbor %i\n", i+1);
		else printf("Dato giornaliero del nostro peer mandato correttamente al neighbor %i\n", i+1);
		
		close(sd);
	}
}


void requestManager(int sd, char* mex, int port)
{
	int ret, app, len;
	char buffer[BUF_LEN];
	char bufferApp1[BUF_LEN];
	char bufferApp2[BUF_LEN];
	char file[BUF_LEN];
	char path[BUF_LEN];
	FILE* fd1;


	memset(buffer, 0, strlen(buffer));
	memset(bufferApp1, 0, strlen(bufferApp1));
	memset(bufferApp2, 0, strlen(bufferApp2));
	memset(file, 0, strlen(file));
	memset(path, 0, strlen(path));
	
	printf("Il messaggio arrivato è %s\n", mex);
	sscanf(mex, "%s %s", bufferApp1, file);
	//ACCEDIAMO ALLA DIRECTORY
	chdir("/tmp");
	if (chdir("covid-FrancescoRubino") == -1)
	{
		mkdir("covid-FrancescoRubino", S_IRWXU);
		chdir("covid-FrancescoRubino");
	}
	sprintf(path, "port%i", port);
	if (chdir(path) == -1)
	{
		mkdir(path, S_IRWXU);
		chdir(path);
	}
	if (chdir("calcoli_get") == -1)
	{
		mkdir("calcoli_get", S_IRWXU);
		chdir("calcoli_get");
	}
	fd1 = fopen(file, "r");
	if (fd1 == NULL)
	{
		//Non ce lo abbiamo
		printf("Il dato richiesto dal vicino non ce lo abbiamo: glielo faccio sapere...\n");
		strcpy(buffer, REPLY_DATA);
		len = COM_LEN;
		app = strlen(buffer);
		sprintf(bufferApp1, "%i", app);
		ret = send(sd, bufferApp1, len, 0);
		if (ret < 0)
		{
			perror("Errore in fase di invio: ");
			exit(-1);
		}

		len = strlen(buffer);
		ret = send(sd, buffer, len, 0);
		if (ret < 0)
		{
			perror("Errore in fase di invio: ");
			exit(-1);
		}
		return;
	}
	else
	{
		//Ce lo abbiamo
		printf("Abbiamo il dato richiesto dal vicino: glielo facciamo sapere...\n");
		fscanf(fd1, "%s", bufferApp2);
		fclose(fd1);
		sprintf(buffer, "%s %s", REPLY_DATA, bufferApp2);

		len = COM_LEN;
		app = strlen(buffer);
		sprintf(bufferApp1, "%i", app);
		ret = send(sd, bufferApp1, len, 0);
		if (ret < 0)
		{
			perror("Errore in fase di invio: ");
			exit(-1);
		}

		len = strlen(buffer);
		ret = send(sd, buffer, len, 0);
		if (ret < 0)
		{
			perror("Errore in fase di invio: ");
			exit(-1);
		}
		return;
	}
}


void dailyDataManager(int sd, char* mex, int port, struct sockaddr_in* neigh_addr, int numNeighbors)
{
	int ret, i, new_sd, app, len, neigh_port, ncList, tamList, guaList, nc, tam, gua; // le var con il suffisso 'List' sono i dati che ho in lista, gli altri sono quelli arrivati
	socklen_t addrlen;
	struct sockaddr_in peer_addr;
	char buffer[BUF_LEN];
	char bufferApp1[BUF_LEN];
	char orig_port[BUF_LEN];
	char listaPeerRicevuti[BUF_LEN];
	char path[BUF_LEN];
	FILE* f;

	//MANDIAMO L'ACK A CHI CI HA MANDATO IL DATO
	len = REQ_DIM;
	strcpy(buffer, ACK);
	ret = send(sd, buffer, len, 0);
	if (ret < 0)
	{
		perror("Errore in fase di invio: ");
		exit(-1);
	}
	
	// GESTIAMO IL DATO RICEVUTO
	strcpy(listaPeerRicevuti, "");
	strcpy(bufferApp1, "");
	strcpy(orig_port, "");

	chdir("/tmp");
	if (chdir("covid-FrancescoRubino") == -1)
	{
		mkdir("covid-FrancescoRubino", S_IRWXU);
		chdir("covid-FrancescoRubino");
	}
	sprintf(path, "port%i", port);
	if (chdir(path) == -1)
	{
		mkdir(path, S_IRWXU);
		chdir(path);
	}
	//LO APRO IN MODALITà APPEND PER CREARLO NEL CASO IN CUI NON ESISTA
	f = fopen("dailyList.txt", "a+");
	fclose(f);

	//ORA LO APRO IN LETTURA
	f = fopen("dailyList.txt", "r");
	fscanf(f, "%s %i %i %i", listaPeerRicevuti, &ncList, &tamList, &guaList);
	fclose(f);

	sscanf(mex, "%s %s %i %i %i %i", bufferApp1, orig_port, &neigh_port, &nc, &tam, &gua);
		//CONTROLLO SE HO GIà IL DATO O SE è IL MIO DATO
	if(strstr(listaPeerRicevuti, orig_port) == NULL && port != atoi(orig_port))
	{
		printf("Arrivato un dato giornaliero che non ho...\n");
		guaList += gua;
		ncList += nc;
		tamList += tam;
		strcat(listaPeerRicevuti, ":");
		strcat(listaPeerRicevuti, orig_port);
		f = fopen("dailyList.txt", "w");
		fprintf(f, "%s %i %i %i", listaPeerRicevuti, ncList, tamList, guaList);
		fclose(f);

		for (i = 0; i < numNeighbors; i++)
		{
			//printf("Stiamo vautando %i e %i\n", ntohs(neigh_addr[i].sin_port), neigh_port);
			if (neigh_addr[i].sin_port == htons(neigh_port)) continue;

			peer_addr = neigh_addr[i];
			addrlen = sizeof(peer_addr);
			new_sd = socket(AF_INET, SOCK_STREAM, 0);
			ret = connect(new_sd, (struct sockaddr*)&peer_addr, addrlen);
			if (ret < 0)
			{
				perror("Errore in fase di connessione: ");
				exit(-1);
			}
			
			sprintf(buffer, "%s %s %i %i %i %i", DAILY_DATA, orig_port, port, nc, tam, gua);
			len = COM_LEN;
			memset(bufferApp1, 0, strlen(bufferApp1));
			app = strlen(buffer);
			sprintf(bufferApp1, "%i", app);
			ret = send(new_sd, bufferApp1, len, 0);
			if (ret < 0)
			{
				perror("Errore in fase di invio: ");
				exit(-1);
			}
	
			len = strlen(buffer);
			ret = send(new_sd, buffer, len, 0);
			if (ret < 0)
			{
				perror("Errore in fase di invio: ");
				exit(-1);
			}
	
			len = REQ_DIM;
			memset(bufferApp1, 0, strlen(bufferApp1));
			ret = recv(new_sd, bufferApp1, len, 0);
			if (ret < 0)
			{
				perror("Errore in fase di ricezione: ");
				exit(-1);
			}
			printf("Abbiamo ricevuto l'ACK da un neighbor...\n\n");
			close(new_sd);
		}
	}
}


int split(char* orig, char* str1, char* str2, char* del)
{
	char orig_copy[BUF_LEN];
	char* token;
	
	strcpy(orig_copy, orig);
	token = strtok(orig_copy, del);
	if (token == NULL) return -1;
	strcpy(str1, token);
	token = strtok(NULL, "\0");
	if (token == NULL) return -1;
	strcpy(str2, token);
	return 0;
}

int stringToDate(char* string, int *day, int *mon, int *year)
{
	int num;
	char* token;
	char string_copy[BUF_LEN];
	num = 0;
	
	strcpy(string_copy, string);
	token = strtok(string_copy, "-");
	if (token == NULL) return -1;
	num = atoi(token);
	if (num == 0) return -1;
	*day = num;
	token = strtok(NULL, "-");
	if (token == NULL) return -1;
	num = atoi(token);
	if (num == 0) return -1;
	*mon = num;
	token = strtok(NULL, "-");
	if (token == NULL) return -1;
	num = atoi(token);
	if (num == 0) return -1;
	*year = num;
	return 0;
}


