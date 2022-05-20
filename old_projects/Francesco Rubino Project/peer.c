#include "intpeer.h"

int main(int argc, char* argv[])
{
	//***************** VARIABILI ****************
	// VARIABILI DI TEMPO
	time_t t, t2;
	struct tm tm, tm2, tmApp;

	// VARIABILI PER GESTIONE CHIUSURA REGISTRO GIORNALIERO

	/* Already Closed è una variabile che può avere valori 0, 1 o 2.
	   Already Closed = 0: In situazioni "normali" si trova in questo stato. Indica che il register odierno è ancora aperto.
	   Already Closed = 1: Indica che il server ha chiesto la chiusura del register. In questa fase i peer si scambiano i propri dati odierni e settano un timestamp. Dopo un certo
					periodo di tempo passano alla fase due facendo controlli sul timestamp.
	   Already Closed = 2: Dopo un certo periodo di tempo diamo per buono di aver ricevuto tutti i dati odierni e facciamo il calcolo. D'ora in poi è possibile usare il register
					di oggi per fare delle operazioni*/
	int alreadyClosed;
	struct tm startCount;

	// VARIABILI PER I DATI DELLE ENTRY
	int nc, tam, gua;

	//VARIABILI DI TIMEOUT PER IL SELECT E PER LA START
	struct timeval tv, to_start;

	// VARIABILI PER COMANDO GET
	int conta, pre;
	
	// VARIABILI PER GESTIONE SOCKET
	int connected = 0; // Variabile su cui controllo se ci siamo registrati al DS o no
	fd_set read_fds, master;
	int new_sd, listenerUDP, listenerTCP, nbytes, ret, numNeighbors, i, s, fdmax, port, app, pid;
	struct sockaddr_in my_addr, srv_addr, peer_addr, neigh_addr[MAX_NEIGHBORS], bu_srv_addr;
	socklen_t addrlen;

	//VARIABILE PER STABILIRE L'ORIZZONTE NEL FLOODING
	int hop = 0;

	// BUFFER
	char buffer[BUF_LEN];
	char bufferApp1[BUF_LEN];
	char bufferApp2[BUF_LEN];
	char path[BUF_LEN];
	char nomeFile[BUF_LEN];
	char comando1[MAX_LEN_CMD];
	char comando2[MAX_LEN_CMD];
	char comando3[MAX_LEN_CMD];
	
	// VARIABILI PER LA GESTIONE DEI FILE
	FILE* fd1;
	//**************** FINE VARIABILI ***************
	
	
	//CONTROLLO SUGLI ARGOMENTI
	if (argc != 2)
	{
		printf("Errore all'avvio dell'applicazione peer! Argomenti errati. \n");
		exit(-1);	
	}
	printf("\n******** PEER COVID MANAGER ********\n");
	printf("Covid Manager è stato avviato con successo...\n");

	// SETTAGGIO VARIABILI DI CONTROLLO
	t = time(NULL);
	tm = *localtime(&t);
	//if (tm.tm_hour > 18) alreadyClosed = 2; else alreadyClosed = 0;
	alreadyClosed = 0; // Questo va commentato se si vuole considerare la chiusura alle 18
	tv.tv_sec = SELECT_SEC_TO_WAIT;
	tv.tv_usec = 0;

	//CREAZIONE DEL SOCKET UDP PER COMUICAZIONI CON DS
	listenerUDP = socket(AF_INET, SOCK_DGRAM, 0); //SOCKET IN ASCOLTO
	if (listenerUDP == -1)
	{
		perror("Errore nella creazione del socket UDP: ");	
		exit(-1);
	}
	printf("\nSocket UDP per comunicazioni con il DS creato con successo...\n");

	//CREAZIONE SOCKET TCP PER COMUNICAZIONI CON I PEER
	listenerTCP = socket(AF_INET, SOCK_STREAM, 0);
	if (listenerTCP == -1)
	{
		perror("Errore nella fase di creazione del socket TCP: ");
	}
	printf("Socket TCP per le comunicazioni con i peer creato con successo...\n");

	//PULIZIA E CONFIGURAZIONE PER IL SOCKET PER COMUNICAZIONI CON DS
	port = atoi(argv[1]);
	memset(&my_addr, 0, sizeof(my_addr));
	my_addr.sin_family = AF_INET;
	my_addr.sin_port = htons(port);
	my_addr.sin_addr.s_addr = INADDR_ANY;
	addrlen = sizeof(my_addr);
	
	//BIND E RELATIVO CONTROLLO PER IL SOCKET UDP
	ret = bind(listenerUDP, (struct sockaddr*)&my_addr, addrlen);
	if(ret < 0)
	{
		perror("Errore in fase di bind del socket UDP: ");
		exit(-1);
	}
	printf("Configurata porta di ascolto %i per comunicazioni UDP... Bind effettuata con successo...\n", port);

	//BIND E RELATIVO CONTROLLO PER IL SOCKET TCP
	ret = bind(listenerTCP, (struct sockaddr*)&my_addr, addrlen);
	if (ret < 0)
	{
		perror("Errore in fase di bind del socket TCP: ");
		exit(-1);
	}
	ret = listen(listenerTCP, 10);
	if (ret < 0)
	{
		perror("Errore in fase di listen per il TCP: ");
		exit(-1);
	}
	printf("Configurata porta di ascolto %i per comunicazioni TCP... Bind effettuata con successo...\n\n", port);
	
	// CONFIGURAZIONE SET
	FD_ZERO(&master);
	FD_ZERO(&read_fds);
	FD_SET(fileno(stdin), &master);
	FD_SET(listenerUDP, &master);
	FD_SET(listenerTCP, &master);
	if (listenerUDP > listenerTCP && listenerUDP > fileno(stdin)) fdmax = listenerUDP;
	else if (listenerTCP > listenerUDP && listenerTCP > fileno(stdin)) fdmax = listenerTCP;
	else fdmax = fileno(stdin);
	
	
	while(1)
	{
begin:	t = time(NULL);
		tm = *localtime(&t);
		// A MEZZANOTTE RISTABILISCO LA VARIABILE ALREADY CLOSED
		if (tm.tm_hour == 0  && alreadyClosed == 2) alreadyClosed = 0;
		// CONTROLLO SU QUANTO TEMPO è PASSATO NEL CASO IN CUI ALREADY CLOSED è A 1
		if (startCount.tm_year != 0 && alreadyClosed == 1)
		{
			t2 = mktime(&startCount);
			if (difftime(t, t2) > TIME_TO_WAIT)
			{
				// NEL REPORTER DI OGGI CI AGGIUNGIAMO I DATI CHE ABBIAMO OTTENUTO
				updateDailyTotal(atoi(argv[1]));
				alreadyClosed = 2;
				startCount.tm_year = 0;
				printf("\nIl timer è scaduto: d'ora in poi non possiamo più ricevere dati giornalieri per oggi e si passa alla gestione del register di domani...\n\n");
			}
		}

		memset(buffer, 0, sizeof(buffer));
		read_fds = master;
		select(fdmax+1, &read_fds, NULL, NULL, &tv);
		for (i = 0; i <= fdmax; i++)
		{
			if(FD_ISSET(i, &read_fds))
			{
				if (i == listenerTCP)
				{
					addrlen = sizeof(peer_addr);
					new_sd = accept(listenerTCP, (struct sockaddr*)&peer_addr, &addrlen);
					FD_SET(new_sd, &master);
					if (new_sd > fdmax) fdmax = new_sd;
				}
				else if (i == listenerUDP)
				{
					//GESTIONE MESSAGGIO DA PARTE DI DS
					nbytes = REQ_DIM;
					addrlen = sizeof(&srv_addr);
					ret = recvfrom(listenerUDP, buffer, nbytes, 0, (struct sockaddr*)&srv_addr, &addrlen);
					if (ret < 0)
					{
						perror("Errore in fase di ricezione di messaggio da parte del DS: ");
						exit(-1);
					}
					//printf("Messaggio da parte del DS... %s\n", buffer);

					/* REQ_CLOSE = 1
					   REQ_EXIT = 2
					   ERRORE = 0
					*/
					if (strcmp(buffer, REQ_CLOSE) == 0) s = 1;
					else if (strcmp(buffer, REQ_ESC) == 0) s = 2;
					else s = 0;
					switch(s)
					{
						case 1: //CLOSE
							port = atoi(argv[1]);
							if (alreadyClosed == 0)
							{
								
								alreadyClosed = 1;
								//DOBBIAMO CONFIGURARE IL DAILY LIST CON I NOSTRI DATI GIORNALIERI
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
								t = time(NULL);
								tm = *localtime(&t);
								// SCRIVIAMO IL NOME DEL FILE IN BUFFER E CI FACCIAMO DARE I DATI CHE CI SERVONO DALLA GETALL
								memset(buffer, 0, strlen(buffer));
								sprintf(buffer, "%02d-%02d-%d.txt", tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900);
								ret = getAll(buffer, &nc, &tam, &gua);
								if (ret < 0)
								{
									nc = 0;
									tam = 0;
									gua = 0;
								}

								chdir("..");
								fd1 = fopen("dailyList.txt", "w");
								fprintf(fd1, "%i/ %i %i %i", atoi(argv[1]), nc, tam, gua);
								fclose(fd1);

								// SETTO LA VARIABILE DI TEMPO CHE SERVE DA TIMER
								t = time(NULL);
								startCount = *localtime(&t);
		
								//MANDIAMO L'ACK AL SERVER
								strcpy(buffer, ACK_CLOSE);
								nbytes = REQ_DIM;
								addrlen = sizeof(srv_addr);
								ret = sendto(listenerUDP, buffer, nbytes, 0, (struct sockaddr*)&srv_addr, addrlen);
								if (ret < 0)
								{
									perror("Errore in fase di invio ack: ");
									exit(-1);
								}
								printf("\nChiusura del register odierno richiesta dal server... D'ora in poi sarà modificabile il register di domani.\n\n");
								//PRIMA CONTROLLO SE I MIEI VICINI SONO CAMBIATI, DOPO MANDO I MIEI RISULTATI GIORNALIERI AI NEIGHBORS
								srv_addr = bu_srv_addr;
								ret = askForChanges(listenerUDP, neigh_addr, srv_addr, &numNeighbors, &hop);
								
								//CREO UN ALTRO PROCESSO PER MANDARE I DATI GIORNALIERI PER EVITARE DEADLOCK
								pid = fork();
								if (pid == -1)
								{
									perror("Errore in fase di fork: ");
									exit(-1);
								}
								if (pid == 0)
								{
									close(listenerUDP);
									close(listenerTCP);
									sendYourData(neigh_addr, numNeighbors, atoi(argv[1]));
									printf("Abbiamo inviato correttamente i nostri dati giornalieri ai nostri vicini...\n");
									exit(0);
								}
							}
							else
							{
								printf("\nAbbiamo ricevuto una richiesta di chiusura del register da parte del server. Non è possibile farlo perchè è già stato chiuso!\n\n");
								//MANDIAMO IL NACK AL SERVER PERCHè ABBIAMO GIà RICEVUTO UNA RICHIESTA DI CHIUSURA IN PRECEDENZA
								strcpy(buffer, NACK_CLOSE);
								nbytes = REQ_DIM;
								addrlen = sizeof(srv_addr);
								ret = sendto(listenerUDP, buffer, nbytes, 0, (struct sockaddr*)&srv_addr, addrlen);
								if (ret < 0)
								{
									perror("Errore in fase di invio ack: ");
									exit(-1);
								}
							}
							break;
						case 2: //EXIT
							printf("Il server ci ha chiesto di uscire. Chiusura forzata!\n\n");
							exit(0);
							break;
						default:
							printf("\nErrore nel messaggio ricevuto dal server: contattarlo per farglielo presente...\n\n");
							break;
					}
				}
				else if (i == fileno(stdin))
				{
					//GESTIONE INPUT DA TASTIERA
					strcpy(comando1, ""); strcpy(comando2, ""); strcpy(comando3, "");
					fgets(buffer, BUF_LEN, stdin);
					sscanf(buffer, "%s %s %s", comando1, comando2, comando3);
					if (strcmp(comando1, "") == 0)
					{
						printf("Errore nell'inserimento dei dati.\n");
						continue;
					}
					/* Per utilizzare lo switch consideriamo queste associazioni:
					START = 1;
					ADD = 2;
					GET = 3;
					STOP = 4;
					HELP = 5;
					COMANDO ERRATO = 0;*/
					if (strcmp(comando1, START) == 0) s = 1;
					else if (strcmp(comando1, ADD) == 0) s = 2;
					else if (strcmp(comando1, GET) == 0) s = 3;
					else if (strcmp(comando1, STOP) == 0) s = 4;
					else if (strcmp(comando1, HELP) == 0) s = 5;
					else s = 0;
					switch(s)
					{
						case 1: //************** START ****************

							if (strcmp(comando2, "") == 0 || strcmp(comando3, "") == 0)
							{
								printf("Errore nell'inserimento dei dati.\n");
								break;
							}

							//CONTROLLO CHE SIA GIA CONNESSO
							if (connected == 1) {printf("\nNon c'è bisogno di rifare il join. Siamo già connessi\n\n"); break;}

							//PULIZIA E CONFIGURAZIONE DELLA STRUTTURA DATI CHE FA RIFERIMENTO AL DS
							memset(&srv_addr, 0, sizeof(srv_addr));
							srv_addr.sin_family = AF_INET;
							port = atoi(comando3);
							srv_addr.sin_port = htons(port);
							inet_pton(AF_INET, comando2, &srv_addr.sin_addr);

						
							//SALVO SU UNA STRUTTURA LE INFO DEL SERVER NEL CASO IN CUI MI DOVESSE SERVIRE IN SEGUITO
							bu_srv_addr = srv_addr;

							//SETTO IL TIMEOUT
							to_start.tv_sec = TIMEOUT_START;
							to_start.tv_usec = 0;
							setsockopt(listenerUDP, SOL_SOCKET, SO_RCVTIMEO, (const char*)&to_start, sizeof(to_start));

							//CHIAMATA AL SERVER DS PER FARGLI UNA RICHIESTA E PER UN INIZIALE HANDSHAKE
							printf("\nAllocazione della memoria per il socket server avvenuta con successo...\n");
							addrlen = sizeof(srv_addr);
							strcpy(buffer, REQUEST);
							nbytes = REQ_DIM;
							printf("Mi appresto a chiamare il server...\n");
							ret = sendto(listenerUDP, buffer, nbytes, 0, (struct sockaddr*)&srv_addr, addrlen);
							if (ret < 0)
							{
								perror("Errore in fase di invio join richiesto al Discovery Server: ");
								exit(-1);
							}
		
							nbytes = REQ_DIM;
							ret = recvfrom(listenerUDP, buffer, nbytes, 0, (struct sockaddr*)&srv_addr, &addrlen);
							if (ret < 0)
							{
								printf("Il server non ci risponde... Riprova più tardi!\n\n");
								break;	
							}

							//RESETTO IL TIMEOUT
							to_start.tv_sec = 0;
							to_start.tv_usec = 0;
							setsockopt(listenerUDP, SOL_SOCKET, SO_RCVTIMEO, (const char*)&to_start, sizeof(to_start));
	
							//INVIO RICHIESTA DI JOIN AL DS
							strcpy(buffer, REQ_JOIN);
							nbytes = REQ_DIM;
							ret = sendto(listenerUDP, buffer, nbytes, 0, (struct sockaddr*)&srv_addr, addrlen);
							if (ret < 0)
							{
								perror("Errore in fase di invio dati: ");
								exit(-1);	
							}
							printf("Ho inviato la richiesta di join al server...\n");
	
							nbytes = sizeof(int);
							ret = recvfrom(listenerUDP, buffer, nbytes, 0, (struct sockaddr*)&srv_addr, &addrlen);
							app = atoi(buffer);
							if (numNeighbors == -1)
							{
								printf("Richiesta rifiutata dal server: ci siamo già registrati in precedenza...\n");
								connected = 1;
								break;
							}
							numNeighbors = app;

							//RICEZIONE DEI NEIGHBORS
							for (i = 0; i < numNeighbors; i++)
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
								printf("Neighbor No%i:\nIndirizzo IP: %s\n", i+1, buffer);
		
								nbytes = DIM_PORT;
								ret = recvfrom(listenerUDP, buffer, nbytes, 0, (struct sockaddr*)&srv_addr, &addrlen);
								if (ret < 0)
								{
									perror("Errore in ricezione dela porta di un neighbor: ");
									exit(-1);
								}
								port = atoi(buffer);
								printf("No porta: %i\n", port); 
								neigh_addr[i].sin_port = htons(port);
							}
							//RICEZIONE DEL NUMERO DI HOP PER L'EVENTUALE FLOODING
							nbytes = DIM_HOP;
							memset(buffer, 0, strlen(buffer));
							ret = recvfrom(listenerUDP, buffer, nbytes, 0, (struct sockaddr*)&srv_addr, &addrlen);
							if (ret < 0)
							{
								perror("Errore in ricezione del numero di hop");
								exit(-1);
							}
							hop = atoi(buffer);
							printf("Registrazione al DS avvenuta con successo...\n");
							connected++;
							// FINE RICHIESTA DI REGISTRAZIONE DOPO ESSERSI FATTO COMUNICARE LA LISTA DEI SUIOI NEIGHBORS
							break;

						case 2: //************** ADD ******************
							//CONTROLLO SUI DATI INSERITI
							if (strcmp(comando2, "nuoviCasi") != 0 && strcmp(comando2, "tamponi") != 0 && strcmp(comando2, "guarigioni") != 0)
							{
								printf("Errore nei dai inseriti in ingresso: paramentro 2...\n\n");
								break;
							}
							ret = atoi(comando3);
							if (ret == 0)
							{
								printf("Errore nei dati inseriti in ingresso: parametro 3...\n\n");
								break;
							}
							//CONFIGURAZIONE PATH E FILE ACCESSIBILE
							port = atoi(argv[1]);
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
							t = time(NULL);
							tm = *localtime(&t);
							chdir(path);
							if (alreadyClosed == 1 || alreadyClosed == 2)
							{
								tm.tm_mday++;
								mktime(&tm);
							} 
							sprintf(path, "%02d-%02d-%d.txt", tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900);
							
							//AGGIUNTA DI UNA ENTRY SUL FILE ODIERNO
							printf("\nInizio aggiornamento register...\n");
							aggiornaEntry(path, comando2, atoi(comando3));
							printf("Operazione conclusa!\n\n");
							break;
							//********** FINE ADD **********
			
						case 3: //********** GET ***********
							//CONTROLLO SUL COMANDO
							if (strcmp(comando2, "variazioneGuarigioni") != 0 && strcmp(comando2, "totaleGuarigioni") != 0 && strcmp(comando2, "variazioneNuoviCasi") != 0 &&
								strcmp(comando2, "variazioneTamponi") != 0 && strcmp(comando2, "totaleTamponi") != 0 && strcmp(comando2, "totaleNuoviCasi") != 0)
							{
								printf("\nErrore nell'inserimento dei dati. Riprova\n");
								break;
							}
							
							// CONTROLLO VALIDITà PARAMETRI
							if (strcmp(comando3, "") == 0)
							{
								printf("Errore nell'inserimento dei dati.\n");
								break;
							}
							app = split(comando3, bufferApp1, bufferApp2, ":");
							if (app == -1)
							{
								printf("Errore nel periodo dato in ingresso...\n");
								break;
							}
							printf("Split terminata!");
							
								//NON SI PUò FARE LA VARIAZIONE DI UN SOLO GIORNO
							if (strcmp(bufferApp1, bufferApp2) == 0 && (strcmp(comando2, "variazioneGuarigioni") == 0 || strcmp(comando2, "variazioneNuoviCasi") == 0 
																		|| strcmp(comando2, "variazioneTamponi") == 0))
							{
								printf("Errore nell'inserimento dei dati: in un calcolo di variazione i due parametri non possono essere uguali...\n\n");
								break;
							}	
								//PRIMA DATA
							if (strcmp(bufferApp1, "*") == 0)
							{
								strcpy(bufferApp1, FIRST_DAY);
								app = stringToDate(bufferApp1, &tm.tm_mday, &tm.tm_mon, &tm.tm_year); //Ora su tm c'è la prima data
								if (app == -1)
								{
									printf("Errore nei dati in ingresso...");
									break;
								}
							} 
							else 
							{
								strcpy(buffer, FIRST_DAY);
								app = stringToDate(bufferApp1, &tm.tm_mday, &tm.tm_mon, &tm.tm_year); //Ora su tm c'è la prima data
								if (app == -1)
								{
									printf("Errore nei dati in ingresso...");
									break;
								}
								app = stringToDate(buffer, &tmApp.tm_mday, &tmApp.tm_mon, &tmApp.tm_year);
								if (app == -1)
								{
									printf("Errore nei dati in ingresso...");
									break;
								}
								tm.tm_hour = 0;
								tm.tm_min = 0;
								tm.tm_sec = 0;
								tmApp.tm_hour = 0;
								tmApp.tm_min = 0;
								tmApp.tm_sec = 0;
								t = mktime(&tm);
								t2 = mktime(&tmApp);
								if  (difftime(t, t2) < 0)
								{
									printf("\nPrima data minore della prima data inseribile!\n\n");
									memset(buffer, 0, strlen(buffer));
									memset(bufferApp1, 0, strlen(bufferApp1));
									memset(bufferApp2, 0, strlen(bufferApp2));
									break;
								}
							}
							printf("Prima data controllata con successo...\n\n");

								//SECONDA DATA
							if (strcmp(bufferApp2, "*") == 0)
							{
								//è possibile fare i calcoli solamente sui giorni i cui register sono stati già chiusi
								t = time(NULL);
								tm2 = *localtime(&t);
								if (alreadyClosed == 0 || alreadyClosed == 1)
								{
									tm2.tm_mday--;
									mktime(&tm2); //Ora su tm2 c'è la seconda data
								}
								sprintf(bufferApp2, "%02d-%02d-%d", tm2.tm_mday, tm2.tm_mon + 1, tm2.tm_year + 1900);
							}
							else 
							{
								memset(buffer, 0, strlen(buffer));
								//sscanf(bufferApp2, "%02d-%02d-%d", &tm2.tm_mday, &tm2.tm_mon, &tm2.tm_year); //Ora su tm2 c'è la seconda data
								app = stringToDate(bufferApp2, &tm2.tm_mday, &tm2.tm_mon, &tm2.tm_year);
								if (app == -1)
								{
									printf("Errore nei dati in ingresso...");
									break;
								}
								tm2.tm_hour = 0;
								tm2.tm_sec = 0;
								tm2.tm_min = 0;
								t2 = mktime(&tm2);

								t = time(NULL);
								tmApp = *localtime(&t);
								tmApp.tm_mon++;
								tmApp.tm_year += 1900;
								if (alreadyClosed == 1 || alreadyClosed == 0)
								{
									tmApp.tm_mday--;
									mktime(&tmApp);
								}
								/*printf ("La data scelta ha valori: giorno %i mese %i anno %i\n", tm2.tm_mday, tm2.tm_mon, tm2.tm_year);
								printf ("La data massima ha valori: giorno %i mese %i anno %i\n", tmApp.tm_mday, tmApp.tm_mon, tmApp.tm_year);*/
								sprintf(buffer, "%02d-%02d-%d", tmApp.tm_mday, tmApp.tm_mon, tmApp.tm_year);
								tmApp.tm_hour = 0;
								tmApp.tm_min = 0;
								tmApp.tm_sec = 0;
								t = mktime(&tmApp);
								//printf("Il valore di t2 è %ld e il valore di t è %ld\n", t2, t);
								if (difftime(t2, t) > 0)
								{
									printf("\nSeconda data maggiore della data massima inseribile.\n\n");
									memset(buffer, 0, strlen(buffer));
									memset(bufferApp1, 0, strlen(bufferApp1));
									memset(bufferApp2, 0, strlen(bufferApp2));
									break;
								}
							}
							printf("Seconda data controllata con successo... \n\n");

							tm.tm_hour = 0;
							tm.tm_min = 0;
							tm.tm_sec = 0;
							tm2.tm_hour = 0;
							tm2.tm_min = 0;
							tm2.tm_sec = 0;
							t = mktime(&tm);
							t2 = mktime(&tm2);
							if (difftime(t, t2) > 0) printf("\nErrore nelle date inserite come paramentro: la prima deve essere antecedente alla seconda!\n\n");

							// CONTROLLO PRESENZA CALCOLO GIà RICHIESTO
							port = atoi(argv[1]);
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
							//printf("Ora in comando2 c'è scitto %s, in bufferApp1 %s e in bufferApp2 %s\n\n", comando2, bufferApp1, bufferApp2);
							sprintf(nomeFile, "%s%s_%s.txt", comando2, bufferApp1, bufferApp2);
							fd1 = fopen(nomeFile, "r");
							if (fd1 == NULL)
							{
								// CASO IN CUI NON ABBIAMO GIà CALCOLATO IN PRECEDENZA
									//CONTROLLIAMO SE ABBIAMO TUTTE LE ENTRY
								app = 0; //Questa variabile la utilizzo per ristabilire la prima data dopo aver controllato la presenza di tutte le entry
								t = mktime(&tm);
								t2 = mktime(&tm2);
								while (difftime(t, t2) <= 0)
								{
									memset(path, 0, strlen(path));
									sprintf(path, "%02d-%02d-%d.txt", tm.tm_mday, tm.tm_mon, tm.tm_year);
									fd1 = fopen(path, "r");
									if (fd1 == NULL)
									{
										break;									
									}
									else fclose(fd1);
									tm.tm_mday++;
									t = mktime(&tm);
									app++;
								}
								if (difftime(t, t2) <= 0) //Se è vera vuol dire che dal while di prima siamo usciti perchè abbiamo scoperto una entry che non abbiamo.
														  //A questo punto chiediamo direttamente il dato aggregato ai nostri vicini. Se non ce l'hanno preocederemo a chiedere le entry.
														  //Per questo motivo da qui fino a quel momento non utilizzo più le variabili di tempo t, t2, tm, tm2, in modo tale da iniziare a chiedere
														  //direttamente dalla prima entry che non ho trovato se dovesse essere necessario
								{
									//CONTROLLO SE SIAMO CONNESSI
									if (connected == 0)
									{
										printf("Non siamo connessi al server. Poichè abbiamo bisogno di entry da altri peer non è possibile calcolare la richiesta!\n\n");
										memset(buffer, 0, strlen(buffer));
										memset(bufferApp1, 0, strlen(bufferApp1));
										memset(bufferApp2, 0, strlen(bufferApp2));
										goto begin;
									}
									//CHIEDIAMO PREVENTIVAMENTE AL SERVER SE CI SONO STATI CAMBIAMENTI DI NEIGHBORS
									srv_addr = bu_srv_addr;
									ret = askForChanges(listenerUDP, neigh_addr, srv_addr, &numNeighbors, &hop);
									if (ret < 0)
									{
										printf("Il server ci ha risposto in maniera errata.. Prova a richiedere il dato\n\n");
											break;
									}
	
									printf("Inizio a chiedere ai neighbors...\n");
									
									//PRIMA CHIEDIAMO AI NEIGHBORS (REQ_DATA, REPLY_DATA)
									for (i = 0; i < numNeighbors; i++)
									{
										printf("Richiesta al neighbor numero %i\n", i+1);
										addrlen = sizeof(peer_addr);
										new_sd = socket(AF_INET, SOCK_STREAM, 0);
										peer_addr = neigh_addr[i];
										ret = connect(new_sd, (struct sockaddr*)&peer_addr, addrlen);
										if (ret < 0)
										{
											perror("Errore in fase di connessione con il peer vicino: ");
											exit(-1);
										}
										
										nbytes = strlen(nomeFile) + strlen(REQ_DATA) + 2;
										memset(buffer, 0, strlen(buffer));
										sprintf(buffer, "%i", nbytes);
										nbytes = COM_LEN;
										ret = send(new_sd, buffer, nbytes, 0);
										if (ret < 0)
										{
											perror("Errore in fase di invio: ");
											exit(-1);
										}
										nbytes = atoi(buffer);
										memset(buffer, 0, strlen(buffer));
										sprintf(buffer, "%s %s", REQ_DATA, nomeFile);
										ret = send(new_sd, buffer, nbytes, 0);
										if (ret < 0)
										{
											perror("Errore in fase di invio: ");
											exit(-1);
										}
	
										nbytes = COM_LEN;
										memset(buffer, 0, strlen(buffer));
										ret = recv(new_sd, buffer, nbytes, 0);
										if (ret < 0)
										{
											perror("Errore in fase di ricezione: ");
											exit(-1);
										}
										nbytes = atoi(buffer);
										memset(buffer, 0, strlen(buffer));
										ret = recv(new_sd, buffer, nbytes, 0);
										if (ret < 0)
										{
										perror("Errore in fase di ricezione");
											exit(-1);
										}
										//CONTROLLO IL REPLY_DATA
										memset(bufferApp1, 0, strlen(bufferApp1));
										memset(bufferApp2, 0, strlen(bufferApp2));
										sscanf(buffer, "%s %s", bufferApp1, bufferApp2);
										printf("Il vicino ci ha risposto: %s\n", buffer);
										//printf("Ora in buffer1 c'è scritto %s, in buffer2 c'è scritto %s\n", bufferApp1, bufferApp2);
										if (strcmp(bufferApp1, REPLY_DATA) != 0) 
										{
											printf("Il neighbor ha sbagliato a rispondere. Non abbiamo ricevuto un reply data.\n");
										}	
										else
										{
											if (strcmp(bufferApp2, "")==0) printf("Il neighbor non ha il dato richiesto...\n");
											else 
											{
												printf("Il neighbor %i ha il dato richiesto: è %s\nLo salvo nella cartella calcoli_get\n\n", i+1, bufferApp2);
												
												fd1 = fopen(nomeFile, "w");
												fprintf(fd1, "%s", bufferApp2);
												fclose(fd1);
												goto begin;
											}
										}
									}
									// CONFIGURAZIONE DIRECTORY CORRENTE
									port = atoi(argv[1]);
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
									
									//MI PROCURO TUTTE LE ENTRY MANCANTI. SE NON RIESCO A TROVARNE QUALCUNA DICO QUALI SONO E RIFIUTO LA RICHIESTA
									while (difftime(t, t2) <= 0)
									{
										memset(path, 0, strlen(path));
										sprintf(path, "%02d-%02d-%d.txt", tm.tm_mday, tm.tm_mon, tm.tm_year);
										fd1 = fopen(path, "r");
										if (fd1 == NULL)
										{
											printf("Uso la floodForEntries...\n\n");
											ret = floodForEntries(path, my_addr.sin_port, neigh_addr, numNeighbors, hop);
											if (ret == -1)
											{
												printf("Purtroppo il dato del giorno %02d-%02d-%d non lo abbiamo e non si trova in rete. Non possiamo eseguire la richiesta...\n\n",
														tm.tm_mday, tm.tm_mon, tm.tm_year);
												goto begin;
											}
										}
										else fclose(fd1);
										tm.tm_mday++;
										t = mktime(&tm);
										app++;
									}
								}
								
								// SE SIAMO ARRIVATI FIN QUI VUOL DIRE CHE ABBIAMO OTTENUTO TUTTI I DATI DI CUI ABBIAMO BISOGNO
								printf("Ora abbiamo tutti dati di cui abbiamo bisogno per calcolare il dato aggregato...\n\n");
								tm.tm_mday -= app;
								t = mktime(&tm);
								//printf("In comando2 c'è scritto: %s\n\n", comando2);
									//CASO IN CUI SI è CHIESTO IL TOTALE
								if (strcmp(comando2, "totaleGuarigioni") == 0 || strcmp(comando2, "totaleNuoviCasi") == 0 || strcmp(comando2, "totaleTamponi") == 0)
								{
									//printf("è un operazione di totale...\n\n");
									app = 0;
									conta = 0;
									while (difftime(t, t2) <= 0)
									{
										sprintf(path, "%02d-%02d-%d.txt", tm.tm_mday, tm.tm_mon, tm.tm_year);
										//printf("Chiamo la get che va a prendere il dato nel file del giorno che mi interessa...\n");	

										if (strcmp(comando2, "totaleGuarigioni") == 0) ret = getGuarigioni(path, &app);
										else if (strcmp(comando2, "totaleNuoviCasi") == 0) ret = getNuoviCasi(path, &app);
										else ret = getTamponi(path, &app);
										if (ret < 0)
										{
											printf("Ci deve essere stato un errore nel floodForEntries perchè il file richiesto non esiste ancora...\n\n");
											goto begin;
										}
										conta += app;

										tm.tm_mday++;
										t = mktime(&tm);
									}
									
									// ABBIAMO FINITO, ORA SU CONTA C'è IL RISULTATO, QUINDI CREIAMO IL FILE E LO INSERIAMO DENTRO
										// PRIMA RICAMBIO LA DIRECTORY PER INSERIRE IL FILE NELLA CARTELLA GIUSTA
									port = atoi(argv[1]);
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
									printf("Stiamo per aprire il file...\n\n");
									printf("In nome file c'è scritto %s\n", nomeFile);
									fd1 = fopen(nomeFile, "w");
									printf("File aperto\n");
									fprintf(fd1, "%i", conta);
									printf("File sovrascritto con successo...");
									fclose(fd1);
									printf("\nIl tipo di conteggio richiesto è: %s\nIl periodo è %s\nIl risultato è %i\n\n", comando2, comando3, conta);
								}
									//CASO IN CUI SI è CHIESTA LA VARIAZIONE
								else if (strcmp(comando2, "variazioneGuarigioni") == 0 || strcmp(comando2, "variazioneNuoviCasi") == 0 || strcmp(comando2, "variazioneTamponi") == 0)
								{
									app = 0;
									conta = 0;
			
									memset(buffer, 0, strlen(buffer));
									memset(path, 0, strlen(path));
									sprintf(path, "%02d-%02d-%d.txt", tm.tm_mday, tm.tm_mon, tm.tm_year);

									if (strcmp(comando2, "variazioneGuarigioni") == 0) ret = getGuarigioni(path, &app);
									else if (strcmp(comando2, "variazioneNuoviCasi") == 0) ret = getNuoviCasi(path, &app);
									else ret = getTamponi(path, &app);
									if (ret < 0)
									{
										printf("Ci deve essere stato un errore nel floodForEntries perchè il file richiesto non esiste ancora...\n\n");
										goto begin;
									}
									pre = app;
									tm.tm_mday++;
									t = mktime(&tm);

									while(difftime(t, t2) <= 0)
									{
										memset(path, 0, strlen(path));
										sprintf(path, "%02d-%02d-%d.txt", tm.tm_mday, tm.tm_mon, tm.tm_year);

										if (strcmp(comando2, "variazioneGuarigioni") == 0) ret = getGuarigioni(path, &app);
										else if (strcmp(comando2, "variazioneNuoviCasi") == 0) ret = getNuoviCasi(path, &app);
										else ret = getTamponi(path, &app);
										if (ret < 0)
										{
											printf("Ci deve essere stato un errore nel floodForEntries perchè il file richiesto non esiste ancora...\n\n");
											goto begin;
										}
										conta = app - pre;
										pre = app;
										sprintf(bufferApp1, "%i/", conta);
										strcat(buffer, bufferApp1);
										memset(bufferApp1, 0, strlen(bufferApp1));
	
										tm.tm_mday++;
										t = mktime(&tm);
									}
									// ABBIAMO FINITO, ORA SU BUFFER C'è IL RISULTATO, QUINDI CREIAMO IL FILE E LO INSERIAMO DENTRO
										// PRIMA RICAMBIO LA DIRECTORY PER INSERIRE IL FILE NELLA CARTELLA GIUSTA
									port = atoi(argv[1]);
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
									printf("Stiamo per aprire il file...\n\n");
									printf("In nome file c'è scritto %s\n", nomeFile);
									fd1 = fopen(nomeFile, "w");
									printf("File aperto\n");
									fprintf(fd1, "%s", buffer);
									printf("File sovrascritto con successo...");
									fclose(fd1);
									printf("\nIl tipo di conteggio richiesto è: %s\nIl periodo è %s\nIl risultato è %s\n\n", comando2, comando3, buffer);
								}
							}
							else
							{
								//CASO IN CUI ABBIAMO GIà IL FILE CON IL CALCOLO DELL'AGGREGATO
								fscanf(fd1, "%s", buffer);
								if (strcmp(buffer, "") == 0)
								{
									printf("Errore: File che dovrebbe contenere il conto è vuoto\n\n");
									break;
								}

								printf("\nIl tipo di conteggio richiesto è: %s\nIl periodo è %s\nIl risultato è %s\n\n", comando2, comando3, buffer);
								fclose(fd1);
							}
							break;
						case 4: //STOP
							//EVENTUALMENTE CONTATTIAMO IL DS PER COMUNICARGLI LA VOLONTA DI DISISCRIVERSI
							if (connected == 0)
							{
								printf("Non siamo registrati al DS...\n'");
								break;
							}
							// RIPULISCO E CONFIGURO LA STRUTTURA DATI DEL DS
							memset(&srv_addr, 0, sizeof(srv_addr));
							srv_addr.sin_family = AF_INET;
							port = atoi(comando3);
							srv_addr.sin_port = htons(port);
							inet_pton(AF_INET, comando2, &srv_addr.sin_addr);
							
							addrlen = sizeof(srv_addr);
							strcpy(buffer, REQUEST);
							nbytes = REQ_DIM;
							printf("Mi appresto a chiamare il server...\n");
							ret = sendto(listenerUDP, buffer, nbytes, 0, (struct sockaddr*)&srv_addr, addrlen);
							if (ret < 0)
							{
								perror("Errore in fase di invio join richiesto al Discovery Server: ");
								exit(-1);
							}
		
							nbytes = REQ_DIM;
							ret = recvfrom(listenerUDP, buffer, nbytes, 0, (struct sockaddr*)&srv_addr, &addrlen);
							if (ret < 0)
							{
								perror("Errore in fase di ricezione dati: ");
								exit(-1);	
							}
							printf("Ho ricevuto in ingresso la risposta del server: è %s...\n", buffer);	

							strcpy(buffer, REQ_STOP);
							nbytes = REQ_DIM;
							ret = sendto(listenerUDP, buffer, nbytes, 0, (struct sockaddr*)&srv_addr, addrlen);
							if (ret < 0)
							{
								perror("Errore in fase di invio dati: ");
								exit(-1);	
							}
							printf("Ho inviato la richiesta di stop al server...\n");
	
							nbytes = REQ_DIM;
							ret = recvfrom(listenerUDP, buffer, nbytes, 0, (struct sockaddr*)&srv_addr, &addrlen);
							if (strcmp(buffer, REQ_ACC) == 0) printf("Richiesta accettata dal server: siamo disconnessi...\n");
							else printf("Il server DS non ci riconosce... Comunicare al servizio clienti il problema...\n");
							connected = 0;
							break;
	
						case 5: //HELP
							printf("\n\n********COVID MANAGER PEER*********\n");
							printf("		LISTA COMANDI:		\n\n");
							printf("start indirizzoIP porta: contatta il discovery server per comunicargli la volontà di entrare nel nel network;\n\n");
							printf("add tipo quantita: aggiunge un valore quantità al tipo specificato nel registro in vigore. I tipi possono essere 'nuoviCasi', 'tamponi' e 'guarigioni';\n\n");
							printf("get aggr periodo: fa tutto il necessario per ottenere il dato aggr relativo al periodo. Nel caso in cui non sia possbile calolcolarlo ce lo fa sapere.\n");
							printf("	I valori accettabili di aggr possono essere:\n	totaleGuarigioni, totaleNuoviCasi, totaleTamponi, variazioneGuarigioni, variazioneNuoviCasi, variazioneTamponi.\n");
							printf("	Il periodo deve essere espresso in forma dd-mm-yyyy:dd-mm-yyyy\n\n");
							printf("**********************************\n\n");
							break;
						default:
							printf("Il comando inserito non è corretto: riprovare con un atro comando.\n");
							break;
					}
					fflush(stdin);
				}
				else //GESTORE MESSAGGI PEER TO PEER
				{
					nbytes = COM_LEN;
					ret = recv(i, buffer, nbytes, 0);
					if (ret < 0)
					{
						perror("Errore in fase di ricezione: ");					
						exit(-1);
					}
	
					nbytes = atoi(buffer);
					ret = recv(i, buffer, nbytes, 0);
					if (ret < 0)
					{
						perror("Errore in fase di ricezione: ");
						exit(-1);
					}

					// CONTROLLIAMO LA PRIMA PAROLA PER VEDERE CHE COSA VUOLE
					memset(bufferApp1, 0, strlen(bufferApp1));
					sscanf(buffer, "%s", bufferApp1);
					if (strcmp(bufferApp1, FLOOD_FOR_ENTRIES) == 0)
					{
						// CONTROLLIAMO PREVENTIVAMENTE SE SONO CAMBIATI I NEIGHBORS
						ret = -1;
						while(ret < 0)
						{
							srv_addr = bu_srv_addr;
							ret = askForChanges(listenerUDP, neigh_addr, srv_addr, &numNeighbors, &hop);
							if (ret < 0) sleep(5);
						}
						
						pid = fork();
						if (pid < 0)
						{
							perror("Errore in fase di fork: ");
							exit(-1);
						}
						if (pid == 0)
						{
							
							//CHIUDO I DUE LISTENER NEL FIGLIO
							close(listenerUDP);
							close(listenerTCP);
							printf("\nArrivata una richiesta di flooding da parte di un vicino...\n");
							floodForEntriesManager(i, buffer, atoi(argv[1]), neigh_addr, numNeighbors);
							printf("Fine gestione richiesta di flooding...\n\n");
							close(i);
							exit(0);
						}
					}
					else if (strcmp(bufferApp1, REQ_DATA) == 0)
					{
						// CONTROLLIAMO PREVENTIVAMENTE SE SONO CAMBIATI I NEIGHBORS
						ret = -1;
						printf("Chiediamo al server se ci sono stati cambiamenti di neighbor...\n");
						while(ret < 0)
						{
							srv_addr = bu_srv_addr;
							ret = askForChanges(listenerUDP, neigh_addr, srv_addr, &numNeighbors, &hop);
							if (ret < 0) sleep(5);
						}
						
						pid = fork();
						if (pid < 0)
						{
							perror("Errore in fase di fork: ");
							exit(-1);
						}
						if (pid == 0)
						{
							//CHIUDO I DUE LISTENER NEL FIGLIO
							close(listenerUDP);
							close(listenerTCP);
							printf("\nArrivata una richiesta di un dato aggregato da parte di un vicino...\n");
							requestManager(i, buffer, atoi(argv[1]));
							close(i);
							exit(0);
						}
					}
					else if(strcmp(bufferApp1, DAILY_DATA) == 0)
					{
						if (alreadyClosed == 0 || alreadyClosed == 2) printf("Non è il momento di ricevere dati giornalieri...\n\n");
						else
						{
							pid = fork();
							if (pid < 0)
							{
								perror("Errore in fase di fork: ");
								exit(-1);
							}
							if (pid == 0)
							{
								
								//CHIUDO I DUE LISTENER NEL FIGLIO
								close(listenerUDP);
								close(listenerTCP);
								printf("\nSono arrivati dati giornalieri da parte di un vicino...\n");
								dailyDataManager(i, buffer, atoi(argv[1]), neigh_addr, numNeighbors);
								close(i);
								exit(0);
							}
						} 
					}
					else printf("Richiesta di tipo sconociuto fatta da un peer..\n\n");

					close(i);
					FD_CLR(i, &master);
				}
			}
		}
	}
	close(listenerUDP);
	close(listenerTCP);
	return 0;
}
