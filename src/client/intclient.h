#include "../util.h"
#include <openssl/pem.h>
#include <openssl/evp.h>

int createSocket();
int loginClient(int* sock, char* session_key1, char* session_key2, char* username, struct sockaddr_in srv_addr, X509_STORE* ca_store);
int logoutClient(int sock, unsigned int* nonce, char* session_key2);
int listClient(int sock, char*** file_list, char* session_key1, char* session_key2, unsigned int* nonce);
int renameClient(int sock, char* filename, char* new_filename, char* session_key1, char* session_key2, unsigned int* nonce);
int deleteClient(int sock, char* filename, char* session_key1, char* session_key2, unsigned int* nonce);
int downloadClient(int sock, char* filename, char* session_key1, char* session_key2, unsigned int* nonce);
int uploadClient(int sock, char* username, char* filename);
int shareClient(int sock, char* username, char* filename, char* peername);
int shareReceivedClient(int sd, char* rec_mex);