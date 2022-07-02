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

int LoginServer()
{

}

int LogoutServer()
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

    if (chdir(MAIN_FOLDER_SERVER) == -1)
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
    //printf("We received the message %s", rec_mex);
    sscanf(rec_mex, "%s %s %s %s", bufferSupp1, bufferSupp2, bufferSupp3, bufferSupp4); //The format of the message received is: type_mex, username, filename, new_filename
    //printf("The username is %s, the old_filename is %s, the new_filename is %s\n\n", bufferSupp2, bufferSupp3, bufferSupp4);
    //SANITIZE AND CHECK THE CORRECTNESS OF THE FILENAMES ON BUFFERSUPP3 AND BUFFERSUPP4, otherwise send a message of error to the client
    chdir(MAIN_FOLDER_SERVER);
    ret = chdir(bufferSupp2);
    if (ret == -1)
    {
        printf("Error: username doesn't exists...\n");
        exit(1);
    }

    // CHECK IF THE FILE EXISTS, otherwise send a message of error to the client

    ret = rename(bufferSupp3, bufferSupp4);
    if (ret == -1) 
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


int deleteServer(int sd, char* rec_mex)
{
    char bufferSupp1[BUF_LEN];
    char bufferSupp2[BUF_LEN];
    char bufferSupp3[BUF_LEN];
    int ret;

    // REMEMBER TO SANITIZE PROPERLY THE BUFFER (VERY IMPORTANT)

    // HERE WE NEED TO DECRYPT AND CHECK IF THE MESSAGE IS OKAY

    memset(bufferSupp1, 0, strlen(bufferSupp1));
    memset(bufferSupp2, 0, strlen(bufferSupp2));
    memset(bufferSupp3, 0, strlen(bufferSupp3));
    sscanf(rec_mex, "%s %s %s", bufferSupp1, bufferSupp2, bufferSupp3);
    //SANITIZE AND CHECK THE CORRECTNESS OF THE FILENAMES ON BUFFERSUPP3
    chdir("/home/marc/Documents/database");
    ret = chdir(bufferSupp2);
    if (ret == -1)
    {
        printf("Error: username doesn't exists...\n");
        exit(1);
    }

    // CHECK IF THE FILE EXISTS, otherwise send a message of error to the client

    ret = remove(bufferSupp3);
    if (ret == -1) 
    {
        printf("Something bad happened during the rename operation\n\n");
        exit(1);
    }
    memset(bufferSupp1, 0, strlen(bufferSupp1));
    memset(bufferSupp2, 0, strlen(bufferSupp2));
    memset(bufferSupp3, 0, strlen(bufferSupp3));
    sprintf(bufferSupp1, "%s", DELETE_ACCEPTED); //Format of the message sent is: type_mex
    ret = send(sd, bufferSupp1, strlen(bufferSupp1), 0);
    if (ret == -1)
    {
        printf("Send operation gone bad\n");
        // Change this later to manage properly the session
        exit(1);
    }
    return 1;
}


int downloadServer(int sd, char* rec_mex)
{
    // We received a message with this format: download_request username filenameù
    char buffer[BUF_LEN];
    char bufferSupp1[BUF_LEN];
    char bufferSupp2[BUF_LEN];
    char bufferSupp3[BUF_LEN];
    char payload[CHUNK_SIZE+1];
    char username[MAX_LEN_USR];
    char filename[MAX_LEN_FILENAME];
    struct stat st;
    int i, nchunk, ret;
    FILE* fd;

    sscanf(rec_mex, "%s %s %s", bufferSupp1, username, filename); // bufferSupp2 = username, bufferSupp3 = filename
    chdir(MAIN_FOLDER_SERVER);
    ret = chdir(username);
    if (ret == -1)
    {
        printf("Error: username doesn't exists...\n");
        exit(1);
    }
    if (!(fd = fopen(filename, "r")))
    {
        printf("File %s doesn't exist...\n\n", filename);
        return -1;
    }
    stat(filename, &st);
    nchunk = ceil(st.st_size/CHUNK_SIZE);

    memset(bufferSupp1, 0, strlen(bufferSupp1));
    memset(bufferSupp2, 0, strlen(bufferSupp2));
    memset(bufferSupp3, 0, strlen(bufferSupp3));
    sprintf(bufferSupp1, "%s %d", DOWNLOAD_ACCEPTED, nchunk); //Format of the message sent is: type_mex n_chunk
    ret = send(sd, bufferSupp1, strlen(bufferSupp1), 0);
    if (ret == -1)
    {
        printf("Send operation gone bad\n");
        // Change this later to manage properly the session
        exit(1);
    }
    for (i = 0; i < nchunk; i++)
    {
        memset(bufferSupp1, 0, strlen(bufferSupp1));
        memset(payload, 0, strlen(payload));
        ret = fread(payload, CHUNK_SIZE, 1, fp);
        if (ret == -1)
        {
            printf("Problem during the reading of the file to downlaod... \n\n");
            return -1;
        }
        sprintf(bufferSupp1, "%s %d %s", DOWNLOAD_CHUNK, nchunk, payload); //Format of the message sent is: type_mex n_chunk
        ret = send(sd, bufferSupp1, strlen(bufferSupp1), 0);
        if (ret == -1)
        {
            printf("Send operation gone bad\n");
            // Change this later to manage properly the session
            exit(1);
        }
    }
    memset(bufferSupp1, 0, strlen(bufferSupp1));
    ret = read(sd, buffer, strlen(buffer));
    sscanf(buffer, "%s %s %s", bufferSupp1, bufferSupp2, bufferSupp3);
    if (!(strcmp(bufferSupp1, DOWNLOAD_FINISHED)==0) || !(strcmp(bufferSupp2, username)==0) || !(strcmp(bufferSupp3, filename)==0))
    {
        printf("Error in the last message sent: message of end download\n\n");
        return -1;
    }
    printf("We have completed successfully the donwload operation!\n\n");
    return 1;
}


int uploadServer()
{
    int sock, ret, nchunk, i;
    char buffer[BUF_LEN];
    FILE* f1;
    char bufferSupp1[BUF_LEN];
    char bufferSupp2[BUF_LEN];
    char bufferSupp3[BUF_LEN];
    sock = createSocket();

    if (chdir(MAIN_FOLDER_CLIENT) == -1)
	{
		printf("I'm having some problem with the change directory to the main folder of the software...\n\n");
	}
    f1 = fopen(filename, "r");
    if (f1 == NULL) printf("Starting the download...\n\n");
    else
    {
        fclose(f1);
        printf("Filename already exists. Download request over...\n\n");
        return -1;
    }

    if (connect(sock, (struct sockaddr*)&srv_addr, sizeof(srv_addr)) < 0) 
    {
        printf("\nConnection Failed \n");
        exit(1);
    }
}

int shareServer()
{

}