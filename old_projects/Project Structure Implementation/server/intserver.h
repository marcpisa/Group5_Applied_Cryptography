#include "utilserver.h"
int createSocket();
int listServer(int sd, char* rec_mex);
int renameServer(int sd, char *rec_mex);
int deleteServer(int sd, char *rec_mex);
int downloadServer();
int uploadServer();
int shareServer();