#include "utilclient.h"
int createSocket();
int loginClient();
int logoutClient();
int listClient(char* username, struct sockaddr_in srv_addr);
int renameClient(char* username,char* filename, char* new_filename, struct sockaddr_in srv_addr);
int deleteClient(char* username, char* filename, struct sockaddr_in srv_addr);
int downloadClient(char* username, char* filename, struct sockaddr_in srv_addr);
int uploadClient();
int shareClient();