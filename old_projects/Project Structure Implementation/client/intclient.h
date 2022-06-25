#include "utilclient.h"
int createSocket();
int listClient(char* username, struct sockaddr_in srv_addr);
int renameClient();
int deleteClient();
int downloadClient();
int uploadClient();
int shareClient();