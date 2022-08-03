#include "../util.h"

int createSocket();
int loginClient(char* session_key1, char* session_key2, char* username, struct sockaddr_in srv_addr, X509_STORE* ca_store);