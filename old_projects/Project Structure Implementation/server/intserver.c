#include "intserver.h"

int createSocket()
{
    int sock;
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return -1;
    }
    return sock;
}

int LoginClient()
{

}

int LogoutClient()
{

}

int listServer(int sd, char* rec_mex)
{
    char bufferSupp1[BUF_LEN];
    char bufferSupp2[BUF_LEN];
    struct dirent *files;
    int ret;

    // REMEMBER TO SANITIZE PROPERLY THE BUFFER (VERY IMPORTANT)

    // HERE WE NEED TO DECRYPT AND CHECK IF THE MESSAGE IS OKAY

    memset(bufferSupp1, 0, strlen(bufferSupp1));
    memset(bufferSupp2, 0, strlen(bufferSupp2));
    sscanf(rec_mex, "%s %s", bufferSupp1, bufferSupp2); //in bufferSupp2 we have the username
    chdir("C:Documents/CloudProject");
    ret = chdir(bufferSupp2);
    if (ret == -1)
    {
        printf("Error: username doesn't exists...\n");
        exit(1);
    }
    chdir("..");

    // WE ARE ASSUMING THAT WE DON'T NEED MORE THAN ONE MESSAGE TO LIST THE FILES
    memset(bufferSupp1, 0, strlen(bufferSupp1));
    while(files = readdir(bufferSupp2) != NULL) //the folder we are checking has the same name of the username. So we take the list from that name
    {
        strcat(bufferSupp1, files->d_name);
        strcat(bufferSupp1, "/");
    }

    memset(bufferSupp2, 0, strlen(bufferSupp2));
    sprintf(bufferSupp2, "%s %s" LIST_RESP, bufferSupp1);

    // HERE WE SHOULD REMEMBER TO ENCRYPT THE BUFFER PROPERLY

    ret = send(i, bufferSupp2, strlen(bufferSupp2), 0);
    if (ret == -1)
    {
        printf("Read operation gone bad\n");
        // Change this later to manage properly the session
        exit(1);
    }
    return 1;
}

int renameServer()
{

}

int deleteServer()
{

}


int downloadServer()
{

}

int uploadServer()
{

}

int shareServer()
{

}