#include <arpa/inet.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <dirent.h>

#define SELECT_SEC_TO_WAIT 5
#define MAX_LEN_CMD 100
#define BUF_LEN 1024
#define COM_LEN 10
#define MAX_LEN_USR 20
#define COMM_NUMB 8

#define LOGIN "login"
#define LOGOUT "logout"
#define RENAME "rename"
#define DOWNLOAD "download"
#define UPLOAD "upload"
#define LIST "list"
#define SHARE "share"
#define DELETE "delete"

#define LIST_REQ "list_req"
#define LIST_RESP "list_res"