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
#include <inttypes.h>
#include <sys/stat.h>
#include <math.h>
#include <dirent.h>
//#include <conio.h>

#define SELECT_SEC_TO_WAIT 5
#define MAX_LEN_CMD 100
#define BUF_LEN 1024
#define COM_LEN 16
#define MAX_LEN_USR 20
#define MAX_LEN_FILENAME 20
#define COMM_NUMB 8
#define PORT_SIZE 6
#define CHUNK_SIZE 512
#define SERVER_PORT 9420
#define LOCALHOST "127.0.0.1"
#define MAIN_FOLDER_SERVER "../../database"  // When you test the software on your pc change this variable
#define MAIN_FOLDER_CLIENT "../../download"  // When you test the software on your pc change this variable
#define INFO_FOLDER_SERVER "../../database/info" // When you test the software on your pc change this variable

#define LOGIN "login"
#define LOGOUT "logout"
#define RENAME "rename"
#define DOWNLOAD "download"
#define UPLOAD "upload"
#define LIST "list"
#define SHARE "share"
#define DELETE "delete"
#define HELP "help"

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
#define UPLOAD_ACCEPTED "upld_acc"
#define UPLOAD_DENIED "upld_den"
#define UPLOAD_CHUNK "upld_cnk"
#define UPLOAD_FINISHED "upld_fin"
#define SHARE_REQUEST "shre_req"
#define SHARE_ACCEPTED "shre_acc"
#define SHARE_PERMISSION "shre_per"
#define SHARE_DENIED "shre_den"

#define RED   "\x1B[31m"
#define GRN   "\x1B[32m"
#define RESET "\x1B[0m"

#define MAX_SIZE_USERNAME 25
#define MAX_SIZE_REQUEST 20

#define DH_PUBKEY_SIZE 20    // 160 bit
#define DH_PRIVKEY_SIZE 128  // 1024 bit
#define IV_LEN EVP_CIPHER_iv_length(EVP_aes_128_cbc())
#define HASH_LEN EVP_MD_size(EVP_sha256())
#define BLOCK_SIZE EVP_CIPHER_block_size(EVP_aes_128_cbc())