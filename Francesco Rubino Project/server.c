#include "intserver.h"

int main(int argc, char* argv[])
{
	// ********** VARIABILI **********

	// VARIABILI DI TEMPO
	time_t t;
	struct tm tm;
	struct timeval tv;

	int ret, listener, len, port, i, /*j,*/ numPeer, fdmax, new_sd, s, ind;
	int alreadyClosed;
	uint32_t addr_app;
	fd_set master;
	fd_set read_fds;
	socklen_t addrlen;
	char buffer[BUF_LEN];
	
	// BUFFER PER LA GESTIONE DEI COMANDI DA TASTIERA
	char comando1[MAX_LEN_CMD];
	char comando2[MAX_LEN_CMD];
	char comando3[MAX_LEN_CMD];

	//STRUTTURE PER I SOCKET
	struct sockaddr_in srv_addr, cl_addr;
	struct cv_peer registered_peers[MAX_PEER];
	
	// ********* FINE VARIABILI *********

	alreadyClosed = 0;
	tv.tv_sec = SELECT_SEC_TO_WAIT;
	tv.tv_usec = 0;
	
	FD_ZERO(&master);
	FD_ZERO(&read_fds);
	numPeer = 0;
	if (argc != 2)
	{
		printf("Errore mella fase di avvio: numero argomenti errati...\n");
		exit(-1);
	}
	listener = socket(AF_INET, SOCK_DGRAM, 0);
	if (listener == -1)
	{
		perror("Errore nella fase di creazione del socket: ");
		exit(-1);
	}
	printf("\nProgramma DS per gestione dei peers avviato correttamente: mi appresto ad inizializzare le strutture dati necessarie...\n\n");
	printf("Socket creato correttamente...\n");
	
	//PULIZIA E ALLOCAMENTO IN MEMORIA DELLA STRUTTURA DEL SOCKET
	memset(&srv_addr, 0, sizeof(srv_addr));
	srv_addr.sin_family = AF_INET;
	sscanf(argv[1], "%i", &port);
	srv_addr.sin_port = htons(port);
	srv_addr.sin_addr.s_addr = INADDR_ANY;

	// FASE DI BIND DEL SOCKET SERVER
	addrlen = sizeof(srv_addr);
	ret = bind(listener, (struct sockaddr*)&srv_addr, addrlen);
	if (ret < 0)
	{
		perror("Errore in fase di bind: ");
		exit(-1);
	}
	printf("Bind del socket con indirizzo %i e porta %i eseguita correttamente...\n", srv_addr.sin_addr.s_addr, port);
	
	// INSERIMENTO NEL FIELDSET DEL LISTENER SERVER E DELLO STANDARD INPUT PER LA GESTIONE DEI COMANDI DA PARTE DELL'UTENTE
	FD_SET(listener, &master);
	FD_SET(fileno(stdin), &master);
	if (listener > fileno(stdin)) fdmax = listener;
	else fdmax = fileno(stdin);
	printf("Okay, ora il server è in ascolto...\n\n");
	
	while(1)
	{
		// CONTROLLO CHE ORE SONO PER GESTIRE LA CHIUSURA DEI REGISTER
		t = time(NULL);
		tm = *localtime(&t);
		/*if (tm.tm_hour == 18 && alreadyClosed != 1)
		{
			for (i = 0; i < numPeer; i++)
			{
				new_sd = socket(AF_INET, SOCK_DGRAM, 0);
				len = REQ_DIM;
				strcpy(buffer, REQ_CLOSE);
				//CONFIGURO DESCRITTORE SERVER
				srv_addr.sin_family = AF_INET;
				srv_addr.sin_addr.s_addr = registered_peers[i].p_addr;
				srv_addr.sin_port = registered_peers[i].p_port;

				addrlen = sizeof(srv_addr);
				ret = sendto(new_sd, buffer, len, 0, (struct sockaddr*)&srv_addr, addrlen);
				if (ret < 0)
				{
					perror("Errore nell'invio di richiesta close ai peers: ");
					exit(-1);
				}
				ret = recvfrom(new_sd, buffer, len, 0, (struct sockaddr*)&srv_addr, &addrlen);
				if (ret < 0)
				{
					perror("Errore in fase di ricezione ack: ");
					exit(-1);
				}
				if (strcmp(buffer, NACK_CLOSE) == 0) printf("Il peer ci ha risposto con NACK... Probabilmente glielo abbiamo mandato due volte...\n\n");
				else if (strcmp(buffer, ACK_CLOSE) != 0) i--; //Glielo rimando
				close(new_sd);
			}
			alreadyClosed = 1;
			printf("\nRichiesta chiusura del register odierno avvenuta con successo.\n");
		}*/
		if (tm.tm_hour == 0  && alreadyClosed == 1) alreadyClosed = 0;
		// FINE CONTROLLO

		memset(buffer, 0, sizeof(buffer));
		read_fds = master;
		select(fdmax+1, &read_fds, NULL, NULL, &tv);
		for (i = 0; i <= fdmax; i++)
		{
			if (FD_ISSET(i, &read_fds))
			{
				if (i == listener)
				{
					// GESTIONE DI UNA NUOVA RICHIESTA DA PARTE DI UN CLIENT
					addrlen = sizeof(cl_addr);
					len = REQ_DIM;
					ret = recvfrom(listener, buffer, len, 0, (struct sockaddr*)&cl_addr, &addrlen);
					if (ret < 0)
					{
						perror("Errore in fase di ricezione dati: ");
						exit(-1);
					}
					if (strcmp(buffer, REQUEST) != 0) printf("Messaggio ricevuto in ingresso da un client: errore nel suo invio...\n Gestione non effettuata...\n");
					else
					{
						// GLI SI ASSOCIA UN NUOVO SOCKET PER LA GESTIONE DELLA RICHIESTA
						inet_ntop(AF_INET, (void *)&cl_addr.sin_addr, buffer, INET_ADDRSTRLEN);
						printf("Intercettata nuova richiesta da un client. \nIndirizzo ip: %s\nNumero porta: %i\n", buffer, ntohs(cl_addr.sin_port));
						new_sd = socket(AF_INET, SOCK_DGRAM, 0);
						addrlen = sizeof(cl_addr);
						memset(buffer, 0, sizeof(buffer));
						strcpy(buffer, REQ_TYPE);
						ret = sendto(new_sd, buffer, len, 0, (struct sockaddr*)&cl_addr, addrlen);
						if (ret < 0)
						{
							perror("Errore in fase di connessione del socket UDP appena creato per la gestione della richiesta di un client: ");	
							exit(-1);						
						}
						FD_SET(new_sd, &master);
						if (new_sd > fdmax){fdmax = new_sd;}
					}
				}
				else if (i == fileno(stdin))
				{
						strcpy(comando1, ""); strcpy(comando2, ""); strcpy(comando3, "");
						fgets(buffer, BUF_LEN, stdin);
						sscanf(buffer, "%s %s %s", comando1, comando2, comando3);
						if (strcmp(comando1, "") == 0)
						{
							printf("Errore nell'inserimento dei dati.\n");
							continue;
						}
						/* Per utilizzare lo switch consideriamo queste associazioni:
						HELP = 1;
						SHWPEERS = 2;
						SHWNEIGH = 3;
						ESC = 4;
						CLOSE = 5;
						COMANDO ERRATO = 0;*/
						if (strcmp(comando1, HELP) == 0) s = 1;
						else if (strcmp(comando1, SHWPEERS) == 0) s = 2;
						else if (strcmp(comando1, SHWNEIGH) == 0) s = 3;
						else if (strcmp(comando1, ESC) == 0) s = 4;
						else if (strcmp(comando1, CLOSE) == 0) s = 5;
						else s = 0;
						switch(s)
						{
							case 1: //HELP
								printf("\n\n************* DISCOVERY SERVER ***************\n\n");
								printf("               Lista comandi:\n\n");
								printf("help: panoramica dei possibili comandi rivolgibili al server.\n\n");
								printf("showpeers: elenco dei peers connessi al network.\n\n");
								printf("showneighbors [peer]: mostra i neighbors del peer indicato. Se non è stato indicato nessun peer verranno mostrati i neighbors di tutti.\n\n");
								printf("esc: termina il DS. Causa la terminazione di tutti i peer. I peer possono salvare info su un file per poterle utilizzare in seguito.\n\n");
								printf("**********************************************\n\n");
								break;
							case 2: //SHWPEERS
								printf("\n\n**** ELENCO DEI PEER CONNESSI AL NETWORK ****\n\n");
								for (i = 0; i < numPeer; i++)
								{
									inet_ntop(AF_INET, (void *)&registered_peers[i].p_addr, buffer, INET_ADDRSTRLEN);
									printf("Peer Numero %i: IP %s, porta %i\n", i+1, buffer, ntohs(registered_peers[i].p_port));
								}
								printf("\n**********************************************\n\n");
								break;
							case 3: //SHWNEIGH
								if (strcmp(comando2, "") == 0)
								{
									printf("\n\n**** ELENCO DEI PEER E NEIGHBORS CONNESSI AL NETWORK ****\n\n");
									for (i = 0; i < numPeer; i++)
									{
										inet_ntop(AF_INET, (void *)&registered_peers[i].p_addr, buffer, INET_ADDRSTRLEN);
										printf("Peer Numero %i: IP %s, porta %i\n", i+1, buffer, ntohs(registered_peers[i].p_port));
										if (numPeer > 1)
										{
											ind = mod(i-1, numPeer);
											inet_ntop(AF_INET, (void *)&registered_peers[ind].p_addr, buffer, INET_ADDRSTRLEN);
											printf("        Neighbor: IP %s, porta %i\n", buffer, ntohs(registered_peers[ind].p_port));
										}
										if (numPeer > 2)
										{
											ind = mod(i+1, numPeer);
											inet_ntop(AF_INET, (void *)&registered_peers[ind].p_addr, buffer, INET_ADDRSTRLEN);
											printf("        Neighbor: IP %s, porta %i\n", buffer, ntohs(registered_peers[ind].p_port));
										}
										//printf("\n");
									}
									printf("\n**********************************************************\n\n");
									break;
								}
								else if (strcmp(comando2, "") != 0 && strcmp(comando3, "") == 0)
								{
										printf("Errore nell'inserimento dei dati... Riprova!\n");
										break;
								}
								else
								{
									inet_pton(AF_INET, comando2, &addr_app);
									port = atoi(comando3);
									printf("\n\n**** PEER E SUOI NEIGHBORS CONNESSI AL NETWORK ****\n\n");
									for (i = 0; i < numPeer; i++)
									{
										if (registered_peers[i].p_addr == addr_app && registered_peers[i].p_port == htons(port))
										{
											inet_ntop(AF_INET, (void *)&registered_peers[i].p_addr, buffer, INET_ADDRSTRLEN);
											printf("Peer Numero %i: IP %s, porta %i\n", i+1, buffer, ntohs(registered_peers[i].p_port));
											if (numPeer > 1)
											{
												ind = mod(i-1, numPeer);
												inet_ntop(AF_INET, (void *)&registered_peers[ind].p_addr, buffer, INET_ADDRSTRLEN);
												printf("        Neighbor: IP %s, porta %i\n", buffer, ntohs(registered_peers[ind].p_port));
											}
											if (numPeer > 2)
											{
												ind = mod(i+1, numPeer);
												inet_ntop(AF_INET, (void *)&registered_peers[ind].p_addr, buffer, INET_ADDRSTRLEN);
												printf("        Neighbor: IP %s, porta %i\n", buffer, ntohs(registered_peers[ind].p_port));
											}
											break;
										}
									}
									if (i == numPeer)
									{
										printf("Nessun peer registrato trovato che corrisponde ai dati inseriti in ingresso.\n");
									}
									printf("\n*****************************************************\n\n");
									break;
								}
								break;
							case 4: //ESC
								for (i = 0; i < numPeer; i++)
								{
									//CONFIGURO IL DESCRITTORE DEL CLIENT
									cl_addr.sin_family = AF_INET;
									cl_addr.sin_addr.s_addr = registered_peers[i].p_addr;
									cl_addr.sin_port = registered_peers[i].p_port;
		
									len = REQ_DIM;
									addrlen = sizeof(cl_addr);
									strcpy(buffer, REQ_ESC);
									new_sd = socket(AF_INET, SOCK_DGRAM, 0);
									ret = sendto(new_sd, buffer, len, 0, (struct sockaddr*)&cl_addr, addrlen);
									if (ret < 0)
									{
										perror("Errore in fase di richiesta di ESC ai peer: ");
										exit(-1);
									}
									close(new_sd);
								}
								exit(0);
								break;
							case 5: //CLOSE
								t = time(NULL);
								tm = *localtime(&t);
								/*if (tm.tm_hour >= 18)
								{
									printf("\n Sono passate le 18 e i peer già stanno gestendo il register di domani: non è possibile chiuderlo ora. Riprova domani!\n\n");
									break;
								}*/
								if (tm.tm_hour == 0)
								{
									printf("\nI register di oggi sono appena stati aperti. Non ha senso chiuderli di già, vai a dormire...\n");
									break;
								}
								if (alreadyClosed == 1)
								{
									printf("\n Chiusura del register odierno già chiesta in precedenza... Non è possibile più chiederla per oggi\n\n");
									break;
								}
								for (i = 0; i < numPeer; i++)
								{
									new_sd = socket(AF_INET, SOCK_DGRAM, 0);
									len = REQ_DIM;
									strcpy(buffer, REQ_CLOSE);
									//CONFIGURO IL DESCRITTORE
									srv_addr.sin_family = AF_INET;
									srv_addr.sin_addr.s_addr = registered_peers[i].p_addr;
									srv_addr.sin_port = registered_peers[i].p_port;

									addrlen = sizeof(srv_addr);
									ret = sendto(new_sd, buffer, len, 0, (struct sockaddr*)&srv_addr, addrlen);
									if (ret < 0)
									{
										perror("Errore nell'invio di richiesta close ai peers: ");
										close(new_sd);
										break;
									}
									len = REQ_DIM;
									ret = recvfrom(new_sd, buffer, len, 0, (struct sockaddr*)&srv_addr, &addrlen);
									if (ret < 0)
									{
										perror("Errore in ricezione: ");
										close(new_sd);
										break;
									}
									close(new_sd);
								}
								alreadyClosed = 1;
								printf("Richiesta di chiusura del register odierno avvenuta con successo.\n");
								break;
							default:
								printf("Il comando inserito non è corretto: riprovare con un atro comando.\n");
								break;
						}
						fflush(stdin);
				}
				else
				{
					// GESTORE RICHIESTA
					len = REQ_DIM;
					addrlen = sizeof(cl_addr);
					memset(buffer, 0, sizeof(buffer));
					ret = recvfrom(i, buffer, len, 0, (struct sockaddr*)&cl_addr, &addrlen);
					if (ret < 0)
					{
						perror("Errore in fase di ricezione dati: ");
						exit(-1);	
					}
					/*printf("\nSono il gestore: Intercettata nuova richiesta da un client. \n");*/
					printf("Gestore: inizio gestione richiesta...\n");
					gestioneRichiesta(i, cl_addr, buffer, registered_peers, &numPeer);
					printf("Gestione terminata! Pronto per gestire altre richieste...\n\n");
					//PROVA
					/*printf("I changed ora sono: ");
					for (j = 0; j < numPeer; j++)
					{
						printf("%i ", registered_peers[j].changes);
					}
					printf("\n");*/
					close(i);
					FD_CLR(i, &master);
				}
			}
		}
	}
	return 0;
}
