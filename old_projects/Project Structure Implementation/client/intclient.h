#include "utilclient.h"
int createSocket();
int listClient(char* username, struct sockaddr_in srv_addr);
int renameClient(char* username,char* filename, char* new_filename, struct sockaddr srv_addr);
int deleteClient();
int downloadClient();
int uploadClient();
int shareClient();