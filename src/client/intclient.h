#include "../util.h"
#include <openssl/pem.h>
#include <openssl/evp.h>

int createSocket();
int loginClient(int* sock, unsigned char* session_key1, unsigned char* session_key2, char* username, struct sockaddr_in srv_addr, X509_STORE* ca_store);
int logoutClient(int sock, int* nonce, unsigned char* session_key2);
int listClient(int sock, char*** file_list, unsigned char* session_key1, unsigned char* session_key2, int* nonce);
int renameClient(int sock, char* filename, char* new_filename, unsigned char* session_key1, unsigned char* session_key2, int* nonce);
int deleteClient(int sock, char* filename, unsigned char* session_key1, unsigned char* session_key2, int* nonce);
int downloadClient(int sock, char* filename, unsigned char* session_key1, unsigned char* session_key2, int* nonce);
int uploadClient(int sock, char* username, char* filename);
int shareClient(int sock, char* username, char* filename, char* peername);
int shareReceivedClient(int sd, char* rec_mex);