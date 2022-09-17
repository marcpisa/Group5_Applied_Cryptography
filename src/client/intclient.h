#include "../util.h"
#include <openssl/pem.h>
#include <openssl/evp.h>

int createSocket();
int loginClient(int* sock, unsigned char* session_key1, unsigned char* session_key2, char* username, struct sockaddr_in srv_addr, X509_STORE* ca_store);
int logoutClient(int sock, int* nonce, unsigned char* session_key2, struct sockaddr_in srv_addr);
int listClient(int sock, char*** file_list, unsigned char* session_key1, unsigned char* session_key2, int* nonce, struct sockaddr_in srv_addr);
int renameClient(int sock, char* filename, char* new_filename, unsigned char* session_key1, unsigned char* session_key2, int* nonce, struct sockaddr_in srv_addr);
int deleteClient(int sock, char* filename, unsigned char* session_key1, unsigned char* session_key2, int* nonce, struct sockaddr_in srv_addr);
int downloadClient(int sock, char* filename, struct sockaddr_in srv_addr);
int uploadClient(int sock, char* filename, struct sockaddr_in srv_addr);
int shareClient(int sock, char* filename, char* peername, struct sockaddr_in srv_addr);
int shareReceivedClient(int sd, char* rec_mex);