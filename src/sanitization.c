//IS THE SANIFICATION PROCESS DONE AT CLIENT LEVEL OR AT SERVER LEVEL???

//#include "server/utilserver.h"

//static char *commands[] = {LOGIN, LOGOUT, LIST, RENAME, DELETE, DOWNLOAD, UPLOAD, SHARE};
static char allowed_chars[] = {"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-./"};
static char username_allowed_chars[] = {"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-"};

/*Sanitization of commands input: only commands defined are allowed.
RETURN:
    0 -> command invalid or input 
    i+1 -> command valid returning id of command
*//*
int input_sanitization_commands(const char* input[]) {

    int i;
    for (i = 0; i < COMM_NUMB; i++) {
        if (strncmp(commands[i], input, COM_LEN) == 0) return i + 1;
    }
    return 0;
}*/

/*Sanitization of file_name inserted by the client.
RETURN:
    0 -> file_name with denied characters or error during canonization
    -1 -> unathorized path for file_name
    1 -> file_name valid
*//*
int file_name_sanitization(const char* file_name[], const char* root_dir[], char* canon_file_name) {

    char buf[BUF_LEN];

    if(strspn(file_name, allowed_chars) < strlen(file_name)) return 0;
    canon_file_name = realpath(file_name, buf);
    if(!canon_file_name) return 0;
    if(strncmp(canon_file_name, root_dir, strlen(root_dir)) != 0) return -1;
    return 1;
}*/

/* Sanitize the username using a whitelist, the accepted characters
 * are [abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-]
 * Return 0 if sanitize fails, 1 otherwise
 */
int username_sanitization(const char* username) {
    if(strspn(username, username_allowed_chars) < strlen(username)) return 0;
    return 1;
}