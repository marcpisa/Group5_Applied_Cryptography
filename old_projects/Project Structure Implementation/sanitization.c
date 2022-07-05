#include "server/utilserver.h"

/* These can be put in the server file

static char *commands[] = {LOGIN, LOGOUT, LIST, RENAME, DELETE, DOWNLOAD, UPLOAD, SHARE};
static cahr *client_list[] = {mark_hoffman, andrea_giuliani43, tpacini, fr75_rubino}

#define MAX_LENG_USERNAME

*/
static char allowed_chars[] = {"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-./"};


/*Sanitization of commands input: only commands defined are allowed.
RETURN:
    0 -> command invalid or input 
    i+1 -> command valid returning id of command
*/
int input_sanitization_commands(const char* input[], const char* commands[]) {

    int i;
    for (i = 0; i < COMM_NUMB; i++) {
        if (strncmp(commands[i], strlwr(input), COM_LEN) == 0) return i + 1;
    }
    return 0;
}

/*Sanitization of file_name sent by the client.
RETURN:
    0 -> file_name with denied characters or error during canonization
    -1 -> unathorized path for file_name
    1 -> file_name valid
*/
int file_name_sanitization(const char* file_name[], const char* root_dir[], char* canon_file_name) {

    char buf[BUF_LEN];

    if(strspn(file_name, allowed_chars) < strlen(file_name)) return 0;
    canon_file_name = realpath(file_name, buf);
    if(!canon_file_name) return 0;
    if(strncmp(canon_file_name, root_dir, strlen(root_dir)) != 0) return -1;
    return 1;
}

// Only search inside the list of clients at the server side
int username_sanitization(const char* input[], const char* client_list[]) {
    int i;
    for (i = 0; i < COMM_NUMB; i++) {
        if (strncmp(commands[i], input, MAX_LENG_USERNAME) == 0) return i + 1;
    }
    return 0;
}
