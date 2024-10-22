#include <arpa/inet.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <math.h>
#include <dirent.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/err.h>
//#include <conio.h>

#define MAX_LEN_CMD 100
#define BUF_LEN 3*1024
#define COM_LEN 16
#define MAX_LEN_FILENAME 20
#define MAX_LEN_USERNAME 20
#define COMM_NUMB 10
#define PORT_SIZE 6

#define CHUNK_SIZE 512 
#define BLOCK_SIZE EVP_CIPHER_block_size(EVP_aes_128_cbc()) 
#define ENCR_CHUNK_LEN CHUNK_SIZE+BLOCK_SIZE // This is correct if CHUNK_SIZE is a multiple of 16
#define IV_LEN EVP_CIPHER_iv_length(EVP_aes_128_cbc())
#define HASH_LEN EVP_MD_size(EVP_sha256())
#define SIGN_LEN 256

#define SERVER_PORT 25020
#define LOCALHOST "127.0.0.1"

#define TYPE_LEN 8
#define DH_PUBKEY_SIZE 625
#define NUM_USER 4
#define LEN_SIZE 11
#define REST_SIZE 11
#define MAX_CERT_LEN 2048
#define BLANK_SPACE 1

#define MAIN_FOLDER_SERVER "../../database/"
#define MAIN_FOLDER_CLIENT "../../download/"
#define INFO_FOLDER_SERVER "../info/"

#define KILO 1024
#define MEGA 1048576
#define GIGA 1073741824

#define LOGIN "login"
#define LOGOUT "logout"
#define RENAME "rename"
#define DOWNLOAD "download"
#define UPLOAD "upload"
#define LIST "list"
#define SHARE "share"
#define DELETE "delete"
#define HELP "help"
#define EXIT "exit"

#define LOGIN_REQUEST "logi_req"
#define SEND_PORT "snd_port"
#define LOGOUT_REQUEST "logo_req"
#define LOGOUT_DENIED "logo_den"
#define LOGOUT_ACCEPTED "logo_acc"
#define LIST_REQUEST "list_req"
#define LIST_RESPONSE "list_res"
#define LIST_DENIED "list_den"
#define LIST_ACCEPTED "list_acc"
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


#define RED "\x1B[31m"
#define GRN "\x1B[32m"
#define RESET "\x1B[0m"

#define DELIM ' '

void from_B_to_H(char** dimension, char* bytes);
int username_sanitization(const char *username);
int select_case_command(const char *input);
void rec_buffer_sanitization(char *received_buff, char *buff1[]);
int filename_sanitization(const char *file_name);
void exit_with_failure(char *err, int perror_enable);
size_t str_ssplit(unsigned char *a_str, const unsigned char a_delim);
unsigned char *pubkey_to_byte(EVP_PKEY *pub_key, int *pub_key_len);
EVP_PKEY *pubkey_to_PKEY(unsigned char *public_key, int len);
EVP_PKEY *save_read_PUBKEY(char *path_pubkey, EVP_PKEY *my_prvkey);
void encrypt_AES_128_CBC(unsigned char **out, int *out_len, unsigned char *in, unsigned int inl, unsigned char *iv, unsigned char *key);
void decrypt_AES_128_CBC(unsigned char **out, unsigned int *out_len, unsigned char *in, unsigned int inl, unsigned char *iv, unsigned char *key);
unsigned char *hash_SHA256(char *msg);
unsigned char *sign_msg(char *path_key, unsigned char *msg_to_sign, int msg_len, unsigned int *signature_len, int server);
int verify_signature(unsigned char *exp_digsig, int len_exp_digsig, unsigned char *msg_to_ver, int len_msg_ver, EVP_PKEY *pub_rsa_key);
unsigned char *cert_to_byte(X509 *cert, int *cert_len);
unsigned char *key_derivation(EVP_PKEY *prvkey, EVP_PKEY *peer_pubkey, size_t *secretlen);
unsigned char *read_cert(char *path_cert, int *cert_len);
unsigned char *gen_dh_keys(char *path_pubkey, EVP_PKEY **my_prvkey, int *pubkey_len);
EVP_PKEY *get_client_pubkey(char *path_cert_client_rsa);
void issue_session_keys(unsigned char *K, int K_len, unsigned char **session_key1, unsigned char **session_key2);
EVP_PKEY* get_ver_server_pubkey(unsigned char* cert, int cert_len, X509_STORE* ca_store);
unsigned char *hmac_sha256(unsigned char *key, int keylen, unsigned char *msg, int msg_len, unsigned int *out_len);

void operation_denied(int sock, char* reason, char* req_denied, unsigned char* key1, unsigned char* key2, unsigned int* nonce);
void operation_succeed(int sock, char* req_accepted, unsigned char* key2, unsigned int* nonce);
int check_reqden_msg (char* req_denied, unsigned char* msg, unsigned int nonce, unsigned char* session_key1, unsigned char* session_key2);
int check_reqacc_msg(char* req_accepted, unsigned char* msg, unsigned int nonce, unsigned char* session_key2);

int build_msg_2(unsigned char** buffer, void* param1, unsigned int param1_len, void* param2, unsigned int param2_len);
int build_msg_3(unsigned char** buffer, void* param1, unsigned int param1_len, void* param2, unsigned int param2_len, void* param3, unsigned int param3_len);
int build_msg_4(unsigned char** buffer, void* param1, unsigned int param1_len, void* param2, unsigned int param2_len, void* param3, unsigned int param3_len, void* param4, unsigned int param4_len);
int build_msg_5(unsigned char** buffer, void* param1, unsigned int param1_len, void* param2, unsigned int param2_len, void* param3, unsigned int param3_len, void* param4, unsigned int param4_len, void* param5, unsigned int param5_len);
int build_msg_6(unsigned char** buffer, void* param1, unsigned int param1_len, void* param2, unsigned int param2_len, void* param3, unsigned int param3_len, void* param4, unsigned int param4_len, void* param5, unsigned int param5_len, void* param6, unsigned int param6_len);

void free_n(int n, ...);
int build_msg(unsigned char** buffer, char* type, int len_payload, unsigned char* payload, unsigned char* hash, unsigned char* iv);
int parse_msg(unsigned char* rec_msg, int len_msg, char* type, int* len_payload, unsigned char** payload, unsigned char* hash, unsigned char* iv);
int concat_5(unsigned char** buffer, void* param1, unsigned int param1_len, void* param2, unsigned int param2_len, void* param3, unsigned int param3_len, void* param4, unsigned int param4_len, void* param5, unsigned int param5_len);


void free_2(void* param1, void* param2);
void free_3(void* param1, void* param2, void* param3);
void free_4(void* param1, void* param2, void* param3, void* param4);
void free_5(void* param1, void* param2, void* param3, void* param4, void* param5);
void free_6(void* param1, void* param2, void* param3, void* param4, void* param5, void* param6);
