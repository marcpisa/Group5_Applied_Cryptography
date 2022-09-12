#include "../util.h"
#include <openssl/pem.h>
#include <openssl/evp.h>

int createSocket();
int loginClient(unsigned char* session_key1, unsigned char* session_key2, char* username, struct sockaddr_in srv_addr, X509_STORE* ca_store);
int logoutClient(int* nonce, unsigned char* session_key2, struct sockaddr_in srv_addr);
int listClient(char* username, struct sockaddr_in srv_addr);
int renameClient(char* username,char* filename, char* new_filename, unsigned char* session_key1, unsigned char* session_key2, int* nonce, struct sockaddr_in srv_addr);
int deleteClient(char* username, char* filename, unsigned char* session_key1, unsigned char* session_key2, int* nonce, struct sockaddr_in srv_addr);
int downloadClient(char* username, char* filename, struct sockaddr_in srv_addr);
int uploadClient(char* username, char* filename, struct sockaddr_in srv_addr);
int shareClient(char* username, char* filename, char* peername, struct sockaddr_in srv_addr);
int shareReceivedClient(int sd, char* rec_mex);