#include "../util.h"
int createSocket();
int loginClient();
int logoutClient();
int listClient(char* username, struct sockaddr_in srv_addr);
int renameClient(char* username,char* filename, char* new_filename, struct sockaddr_in srv_addr);
int deleteClient(char* username, char* filename, struct sockaddr_in srv_addr);
int downloadClient(char* username, char* filename, struct sockaddr_in srv_addr);
int uploadClient(char* username, char* filename, struct sockaddr_in srv_addr);
int shareClient(char* username, char* filename, char* peername, struct sockaddr_in srv_addr);
int shareReceivedClient(int sd, char* rec_mex);