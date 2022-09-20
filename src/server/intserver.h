#include "../util.h"

#ifndef USER_STAT_H
#define USER_STAT_H

typedef struct user_stat {
    char username[25];
    int connected;
} user_stat;

#endif

int createSocket();
int loginServer(int sd, char* rec_mex, char* session_key1, char* session_key2);
int logoutServer(char* rec_mex, unsigned int* nonce, char* session_key2);
int listServer(int sd, char* rec_mex, char* username, unsigned int* nonce, char* session_key1, char* session_key2);
int renameServer(int sd, char* rec_mex, unsigned int* nonce, char* session_key1, char* session_key2);
int deleteServer(int sd, char* rec_mex, unsigned int* nonce, char* session_key1, char* session_key2);
int downloadServer(int sock, char* rec_mex, char* username, unsigned int* nonce, char* session_key1, char* session_key2);
int uploadServer(int sd, char* rec_mex);
int shareServer(int sd, char* rec_mex);