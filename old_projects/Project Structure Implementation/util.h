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
#include <search.h>

#define SELECT_SEC_TO_WAIT 5
#define MAX_LEN_CMD 100
#define MAX_CANONICA_LEN 1024
#define COM_LEN 10
#define COMM_NUMB 8