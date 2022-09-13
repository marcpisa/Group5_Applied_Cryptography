#include "../util.h"

#ifndef USER_STAT_H
#define USER_STAT_H

typedef struct user_stat {
    char username[25];
    int connected;
} user_stat;

#endif

int createSocket();
int loginServer(int sd, char* rec_mex, user_stat** user_list, unsigned char* session_key1, unsigned char* session_key2);
int logoutServer(int sd, char* rec_mex, user_stat** user_list, int* nonce, unsigned char* session_key1, unsigned char* session_key2);
int listServer(int sd, char* rec_mex, int* nonce, unsigned char* session_key1, unsigned char* session_key2);
int renameServer(int sd, char* rec_mex, int* nonce, unsigned char* session_key1, unsigned char* session_key2);
int deleteServer(int sd, char* rec_mex, int* nonce, unsigned char* session_key1, unsigned char* session_key2);
int downloadServer(int sd, char* rec_mex);
int uploadServer(int sd, char* rec_mex);
int shareServer(int sd, char* rec_mex);