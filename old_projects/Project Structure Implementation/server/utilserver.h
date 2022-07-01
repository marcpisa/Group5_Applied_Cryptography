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
#include <inttypes.h>
#include <sys/stat.h>

#define SELECT_SEC_TO_WAIT 5
#define MAX_LEN_CMD 100
#define BUF_LEN 1024
#define COM_LEN 16
#define MAX_LEN_USR 20
#define COMM_NUMB 8
#define SERVER_PORT 9425
#define CHUNK_SIZE 512
#define LOCALHOST "127.0.0.1"
#define MAIN_FOLDER_SERVER "/home/marc/Documents/database"
#define MAIN_FOLDER_CLIENT "/home/marc/Documents/download"

#define LOGIN "login"
#define LOGOUT "logout"
#define RENAME "rename"
#define DOWNLOAD "download"
#define UPLOAD "upload"
#define LIST "list"
#define SHARE "share"
#define DELETE "delete"

#define LOGIN_REQUEST "logi_req"
#define LOGOUT_REQUEST "logo_req"
#define LIST_REQUEST "list_req"
#define LIST_RESPONSE "list_res"
#define RENAME_REQUEST "renm_req"
#define RENAME_ACCEPTED "renm_acc"
#define RENAME_DENIED "renm_den"
#define DELETE_REQUEST "dele_req"
#define DELETE_ACCEPTED "dele_acc"
#define DELETE_DENIED "dele_den"
#define DOWNLOAD_REQUEST "down_req"
#define DOWNLOAD_ACCEPTED "down_acc"
#define DOWNLOAD_DENIED "down_den"
#define DOWNLOAD_CHUNK "down_cnk"
#define DOWNLOAD_FINISHED "down_fin"
#define UPLOAD_REQUEST "upld_req"
#define SHARE_REQUEST "shre_req"

