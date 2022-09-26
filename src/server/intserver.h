#include "../util.h"

#ifndef USER_STAT_H
#define USER_STAT_H

typedef struct user_stat {
    char username[25];
    int connected;
} user_stat;

#endif

int createSocket();
int loginServer(int sd, char* rec_mex);
int logoutServer(char* rec_mex, unsigned int* nonce, unsigned char* session_key2);
int listServer(int sd, char* rec_mex, char* path_documents, unsigned int* nonce, unsigned char* session_key1, unsigned char* session_key2);
int renameServer(int sd, char* rec_mex, unsigned int* nonce, unsigned char* session_key1, unsigned char* session_key2);
int deleteServer(int sd, char* rec_mex, unsigned int* nonce, unsigned char* session_key1, unsigned char* session_key2);
int downloadServer(int sock, char* rec_mex, unsigned int* nonce, unsigned char* session_key1, unsigned char* session_key2);
int uploadServer(int sock, char* rec_mex, unsigned int* nonce, unsigned char* session_key1, unsigned char* session_key2);
int shareServer(int sd, char* rec_mex, unsigned int* nonce_cs, unsigned int* nonce_sc, unsigned char* session_key1, unsigned char* session_key2);