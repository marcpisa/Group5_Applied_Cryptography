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
    char bufferSupp2[BUF_LEN+10]; // I'm creating a buffer a little longer to have the capacity to contain buffSupp1. We could fix the problem later, putting the end_string character at the end of the list
    DIR* d;
    struct dirent *files;
    int ret;
    printf("I received a message from a client saying: %s\n\n", rec_mex);
    // REMEMBER TO SANITIZE PROPERLY THE BUFFER (VERY IMPORTANT)

    // HERE WE NEED TO DECRYPT AND CHECK IF THE MESSAGE IS OKAY

    memset(bufferSupp1, 0, BUF_LEN);
    memset(bufferSupp2, 0, BUF_LEN);
    sscanf(rec_mex, "%s %s", bufferSupp1, bufferSupp2); //in bufferSupp2 we have the username
    printf("The username is %s, the length of the username is %li\n\n", bufferSupp2, strlen(bufferSupp2));

    if (chdir("/home/marc/Documents/database") == -1)
	{
		printf("I'm having some problem with the change directory to the main folder of the software...\n\n");
	}

    ret = chdir(bufferSupp2);
    if (ret == -1)
    {
        printf("Error: username doesn't exists...\n");
        exit(1);
    }

    // WE ARE ASSUMING THAT WE DON'T NEED MORE THAN ONE MESSAGE TO LIST THE FILES
    d = opendir(".");
    memset(bufferSupp1, 0, strlen(bufferSupp1));
    if(d)
    {
        while((files = readdir(d)) != NULL) //the folder we are checking has the same name of the username. So we take the list from that name
        {
            strcat(bufferSupp1, files->d_name);
            strcat(bufferSupp1, "/");
        }
    }
    

    memset(bufferSupp2, 0, strlen(bufferSupp2));
    sprintf(bufferSupp2, "%s %s", LIST_RESPONSE, bufferSupp1);
    printf("I'm sendinf %s to the client...\n\n", bufferSupp2);
    // HERE WE SHOULD REMEMBER TO ENCRYPT THE BUFFER PROPERLY

    ret = send(sd, bufferSupp2, strlen(bufferSupp2), 0);
    if (ret == -1)
    {
        printf("Send operation gone bad\n");
        // Change this later to manage properly the session
        exit(1);
    }
    return 1;
}


int renameServer(int sd, char* rec_mex)
{
    char bufferSupp1[BUF_LEN];
    char bufferSupp2[BUF_LEN];
    char bufferSupp3[BUF_LEN];
    char bufferSupp4[BUF_LEN];
    int ret;

    // REMEMBER TO SANITIZE PROPERLY THE BUFFER (VERY IMPORTANT)

    // HERE WE NEED TO DECRYPT AND CHECK IF THE MESSAGE IS OKAY

    memset(bufferSupp1, 0, strlen(bufferSupp1));
    memset(bufferSupp2, 0, strlen(bufferSupp2));
    sscanf(rec_mex, "%s %s %s %s", bufferSupp1, bufferSupp2, bufferSupp3, bufferSupp4); //The format of the message received is: type_mex, username, filename, new_filename

    //SANITIZE AND CHECK THE CORRECTNESS OF THE FILENAMES ON BUFFERSUPP3 AND BUFFERSUPP4, otherwise send a message of error to the client
    chdir("C:Documents/CloudProject");
    ret = chdir(bufferSupp2);
    if (ret == -1)
    {
        printf("Error: username doesn't exists...\n");
        exit(1);
    }

    // CHECK IF THE FILE EXISTS, otherwise send a message of error to the client

    ret = rename(bufferSupp3, bufferSupp4);
    if (ret != 0) 
    {
        printf("Something bad happened during the rename operation\n\n");
        exit(1);
    }
    memset(bufferSupp1, 0, strlen(bufferSupp1));
    memset(bufferSupp2, 0, strlen(bufferSupp2));
    memset(bufferSupp3, 0, strlen(bufferSupp3));
    memset(bufferSupp4, 0, strlen(bufferSupp4));
    sprintf(bufferSupp1, "%s", RENAME_ACCEPTED); //Format of the message sent is: type_mex
    ret = send(sd, bufferSupp1, strlen(bufferSupp1), 0);
    if (ret == -1)
    {
        printf("Send operation gone bad\n");
        // Change this later to manage properly the session
        exit(1);
    }
    return 1;
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