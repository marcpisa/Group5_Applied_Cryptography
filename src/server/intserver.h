#include "../util.h"

int createSocket();
int loginServer(int sd, char* rec_mex, unsigned char* session_key1, unsigned char* session_key2);
int logoutServer();
int listServer(int sd, char* rec_mex);
int renameServer(int sd, char* rec_mex);
int deleteServer(int sd, char* rec_mex);
int downloadServer(int sd, char* rec_mex);
int uploadServer(int sd, char* rec_mex);
int shareServer(int sd, char* rec_mex);