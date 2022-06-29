#include "intclient.h"

int createSocket()
{
    int sock;
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
    {
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

int listClient(char* username, struct sockaddr_in srv_addr)
{
    
    int sock, ret;
    char buffer[BUF_LEN];
    sock = createSocket();

    if (connect(sock, (struct sockaddr*)&srv_addr, sizeof(srv_addr)) < 0) 
    {
        printf("\nConnection Failed \n");
        exit(1);
    }

    
    // SET LIST REQUEST BUFFER
    memset(buffer, 0, BUF_LEN);
    sprintf(buffer, "%s %s", LIST_REQ, username);
    buffer[BUF_LEN-1] = '\0';

    // HERE ADD CRYPTOGRAPHIC FUNCTION TO SET PROPERLY THE BUFFER
    printf("I'm sending %s\n", buffer);
    ret = send(sock, buffer, BUF_LEN, 0);
    if (ret == -1)
    {
        printf("Send operation gone bad\n");
        // Change this later to manage properly the session
        exit(1);
    }
    memset(buffer, 0, strlen(buffer));
    printf("List request message sent\n");
    ret = read(sock, buffer, BUF_LEN);
    if (ret == -1)
    {
        printf("Read operation gone bad\n");
        // Change this later to manage properly the session
        exit(1);
    }

    // HERE USE DECRYPTION TO UNDERSTAND WHAT YOU RECEIVE

    // END COMMUNICATION

    printf("%s\n", buffer);
    return 1;
}

int renameClient(char* username,char* filename, char* new_filename, struct sockaddr_in srv_addr)
{
    int sock, ret;
    char buffer[BUF_LEN];
    char bufferSupp1[BUF_LEN];
    char bufferSupp2[BUF_LEN];
    sock = createSocket();

    if (connect(sock, (struct sockaddr*)&srv_addr, sizeof(srv_addr)) < 0) 
    {
        printf("\nConnection Failed \n");
        exit(1);
    }


    //Add: show message when filename is to long to user --> check server side though. 

    // SANITIZE FILENAME AND NEW_FILENAME (VERY IMPORTANT)

    // SET RENAME REQUEST BUFFER
    memset(buffer, 0, strlen(buffer));
    printf("The new filename is %s\n\n", new_filename);
    sprintf(buffer, "%s %s %s %s", RENAME_REQUEST, username, filename, new_filename);
    printf("I'm sending to the server the mex %s\n\n", buffer);

    // HERE ADD CRYPTOGRAPHIC FUNCTION TO SET PROPERLY THE BUFFER

    ret = send(sock, buffer, strlen(buffer), 0);
    if (ret == -1)
    {
        printf("Send operation gone bad\n");
        // Change this later to manage properly the session
        exit(1);
    }
    memset(buffer, 0, strlen(buffer));
    printf("Rename request message sent\n");
    ret = read(sock, buffer, BUF_LEN);
    if (ret == -1)
    {
        printf("Read operation gone bad\n");
        // Change this later to manage properly the session
        exit(1);
    }

    // DECRYPT BUFFER TO UNDERSTAND WHAT IT IS WRITTEN

    sscanf(buffer, "%s %s", bufferSupp1, bufferSupp2); // The two values are the message type and eventually the reason why the request went bad
    
    // SANITIZE THE BUFFER

    if (strcmp(bufferSupp1, RENAME_DENIED) == 0)
    {
        printf("The rename request has been denied: %s\n\n", bufferSupp2);
        return 1;
    }
    else 
        if (strcmp(bufferSupp1, RENAME_ACCEPTED) == 0)
        {
           printf("The rename request has been accepted!\n\n");
           return 1;
        }
        else
        {
            printf("We don't know what the server said...\n\n");
            return -1;
        }
}



int deleteClient(char* username, char* filename, struct sockaddr_in srv_addr)
{        
    int sock, ret;
    char buffer[BUF_LEN];
    sock = createSocket();

    if (connect(sock, (struct sockaddr*)&srv_addr, sizeof(srv_addr)) < 0) 
    {
        printf("\nConnection Failed \n");
        exit(1);
    }

    
    // SET DELETE REQUEST BUFFER
    memset(buffer, 0, BUF_LEN);
    sprintf(buffer, "%s %s %s", DELETE_REQUEST, username, filename);
    buffer[BUF_LEN-1] = '\0';

    // HERE ADD CRYPTOGRAPHIC FUNCTION TO SET PROPERLY THE BUFFER
    ret = send(sock, buffer, BUF_LEN, 0);
    if (ret == -1)
    {
        printf("Send operation gone bad\n");
        // Change this later to manage properly the session
        exit(1);
    }
    printf("Delete request message sent\n");
    memset(buffer, 0, strlen(buffer));
    ret = read(sock, buffer, BUF_LEN);
    if (ret == -1)
    {
        printf("Read operation gone bad\n");
        // Change this later to manage properly the session
        exit(1);
    }

    // HERE USE DECRYPTION TO UNDERSTAND WHAT YOU RECEIVE

    // END COMMUNICATION

    printf("%s\n", buffer);
    return 1;
}

int downloadClient(char* username, char* filename, struct sockaddr_in srv_addr)
{
    int sock, ret, nchunk, i;
    char buffer[BUF_LEN];
    FILE* f1;
    char bufferSupp1[BUF_LEN];
    char bufferSupp2[BUF_LEN];
    char bufferSupp3[BUF_LEN];
    sock = createSocket();

    if (chdir("/home/marc/Documents/donwnload") == -1)
	{
		printf("I'm having some problem with the change directory to the main folder of the software...\n\n");
	}
    f1 = fopen(filename, "r");
    if (f1 = -1) printf("Starting the download...\n\n");
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

    // SANITIZE FILENAME(VERY IMPORTANT)

    // SET DOWNLOAD REQUEST BUFFER
    memset(buffer, 0, strlen(buffer));
    sprintf(buffer, "%s %s %s", DOWNLOAD_REQUEST, username, filename);

    // HERE ADD CRYPTOGRAPHIC FUNCTION TO SET PROPERLY THE BUFFER

    ret = send(sock, buffer, strlen(buffer), 0);
    if (ret == -1)
    {
        printf("Send operation gone bad\n");
        // Change this later to manage properly the session
        exit(1);
    }
    memset(buffer, 0, strlen(buffer));

    // I'm going to receive a messsage with this format: download_accepted username number_of_chunk

    ret = read(sock, buffer, BUF_LEN);
    if (ret == -1)
    {
        printf("Read operation gone bad\n");
        // Change this later to manage properly the session
        exit(1);
    }
    sscanf(buffer, "%s %s %s", bufferSupp1, bufferSupp2, bufferSupp3); // bufferSupp3 = number_of_chunk
    nchunk = atoi(bufferSupp3);

    f1 = fopen(filename, "w");
    for (i; i < nchunk; i++)
    {
        memset(buffer, 0, strlen(buffer));
        // I'm receveing a message with this format: download_chunk n_chunk payload
        ret = read(sock, buffer, BUF_LEN);
        if (ret == -1)
        {
            printf("Read operation gone bad\n");
            // Change this later to manage properly the session
            exit(1);
        }
        sscanf(buffer, "%s %s %s", bufferSupp1, bufferSupp2, bufferSupp3);
        // Now take the bufferSupp3 and append it to the file. When the loop is over we close the file and we got what we neededs
    }
}

int uploadClient()
{

}

int shareClient()
{
    
}