#include "../util.h"
#include <openssl/pem.h>
#include <openssl/evp.h>

int createSocket();
int loginClient(int* sock, unsigned char** session_key1, unsigned char** session_key2, char* username, struct sockaddr_in srv_addr, int port, X509_STORE* ca_store);
int logoutClient(int sock, unsigned int* nonce, unsigned char* session_key2);
int listClient(int sock, unsigned char* session_key1, unsigned char* session_key2, unsigned int* nonce);
int renameClient(int sock, char* filename, char* new_filename, unsigned char* session_key1, unsigned char* session_key2, unsigned int* nonce);
int deleteClient(int sock, char* filename, unsigned char* session_key1, unsigned char* session_key2, unsigned int* nonce);
int downloadClient(int sock, char* filename, unsigned char* session_key1, unsigned char* session_key2, unsigned int* nonce);
int uploadClient(int sock, char* filename, unsigned char* session_key1, unsigned char* session_key2, unsigned int* nonce);
int shareClient(int sock, char* filename, char* peername, unsigned int* nonce, unsigned char* session_key1, unsigned char* session_key2);
int shareReceivedClient(int sd, char* rec_mex, unsigned int* nonce_sc, unsigned char* session_key1, unsigned char* session_key2);