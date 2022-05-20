#include <arpa/inet.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <inttypes.h>
#include <sys/stat.h>

#define MAX_PEER 40
#define DIM_PORT 5
#define DIM_HOP 4
#define COM_LEN 10
#define BUF_LEN 1024
#define MAX_LEN_CMD 100
#define MAX_NEIGHBORS 10
#define TIMEOUT_START 10

#define SELECT_SEC_TO_WAIT 5 //Secondi per il quale la select rimane bloccata se nessun descrittore è pronto. Mi serve perchè devo fare dei controlli su alreadyClosed
#define TIME_TO_WAIT 10 //Secondi da aspettare dopo aver ricevuto la richiesta di chiusura del register da parte del DS. Durante questo intervallo il register odierno non è utilizzabile
#define FLOOD_FOR_ENTRIES "flood_for_entries" //Usato per indicare che si tratta di un messaggio di flooding
#define REPLY_FOR_ENTRIES "reply_for_entries" //Usato per indicare che si tratta di una risposta ad una richiesta di flooding
#define NOT_FOUND "not_found" //Usato nella reply for entries: Vuol dire che non abbiamo trovato ciò che cercavamo
#define REQ_DIM 8 //Tutti i messaggi di richiesta e risposta mandati tra server e peer sono di questa dimensione (a parte la comunicazione dei neighbors)
#define REQUEST "request_" //Usato dal peer per richiedere al server un servizio
#define REQ_TYPE "req_type" //Usato dal server per chiedere al client di farsi dire che tipo di richiesta vuole fare (Handshake, gli comunica anche il socket ad esso associato)
#define REQ_JOIN "req_join" //Richiesta di iscrizione all'elenco dei peer nel sistema da parte del peer stesso
#define REQ_DEN -1 //Richiesta di join rifiutata
#define REQ_NACC "req_nacc" //Richiesta di disiscrizione rifiutata
#define REQ_CNG "req_chng" //Richiesta mandata dal client per chiedere se i neighbors sono cambiati o meno
#define REQ_STOP "req_stop" //Richiesta di disiscrizione dall'elenco dei peers da parte di un peer
#define REQ_ACC "req_acce" //Utilizzato dal server per indicare di aver accettato ed eliminato la struttura dati di un peer che non vuole più essere registrato
#define REQ_CLOSE "reqclose" //Utilizzato dal server per richiedere ai peer la chiusura del register odierno
#define ACK_CLOSE "ackclose" //Ack mandato dal peer che fa sapere al server di aver capito di dover chiudere il register
#define NACK_CLOSE "nack_clo" // Nack mandato dal peer che fa sapere al server di aver già ricevuto in precedenza una richiesta di chiusura da parte sua
#define REQ_ESC "req_esc_" //Utilizzato dal server per richiedere la chiusura ai peer
#define REQ_DATA "req_data" //Usato per indicare una richiesta di un dato aggregato
#define REPLY_DATA "reply_data" //Usato per indicare una risposta alla richiesta di un dato aggregato
#define DAILY_DATA "daily_data" //Usato per indicare che il messaggio inviato si riferisce ai dati giornalieri di un peer
#define ACNG1 1 //Messaggio mandato dal server in seguito ad una richiesta di cambiamenti di neighbors avvenuti: significa che ci sono stati cambiamenti
#define ACNG2 2 //Messaggio mandato dal server in seguito ad una richiesta di cambiamenti di neighbors avvenuti: significa che ci sono stati cambiamenti
#define NCNG -1 //Messaggio mandato dal server in seguito ad una richiesta di cambiamenti di neighbors avvenuti: significa che non ce ne sono stati
#define START "start" //Comando da tastiera: chiede di effettuare una REQ_JOIN
#define ADD "add" //Comando da tastiera: Aggiunge un field al file giornaliero
#define GET "get" //Comando da tastiera: Fa delle operazioni di statistiche sui file che il peer possiede
#define STOP "stop" //Comando da tastier: L'utente chiede di contattare il server per uscire dalla lista dei peer registrati
#define ACK "ack" //Messaggio mandato da un peer che ha ricevuto il daily data

//COMANDI INPUT PER IL SERVER
#define HELP "help" //Lista dei comandi
#define SHWPEERS "showpeers" //Mostra i peer registrati al network
#define SHWNEIGH "showneighbor" //Mostra i peer del network con allegato i loro vicini
#define ESC "esc" //Server per uscire dopo aver chiesto ai peerdi uscire
#define CLOSE "close" //Comando per il server per chiedere ai peer di chiudere i registri

#define FIRST_DAY "10-04-2021" //Primo giorno permesso per la richiesta di dati aggregati

struct cv_peer
{
	uint32_t p_addr;
	uint16_t p_port;
	int changes;
};
