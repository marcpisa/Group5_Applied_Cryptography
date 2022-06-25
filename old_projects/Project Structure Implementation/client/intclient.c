#include "intclient.h"

int createSocket()
{
    int sock;
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return -1;
    }
    return sock;
}

int LoginClient(...)
{

}

int LogoutClient(...)
{

}

int listClient(char* username, struct sockaddr_in srv_addr, )
{
    
    int sock, ret;
    char buffer[BUF_LEN];
    sock = createSocket();

    if (connect(sock, (struct sockaddr*)&srv_addr,
                sizeof(srv_addr))
        < 0) {
        printf("\nConnection Failed \n");
        exit(1);
    }

    
    // SET LIST REQUEST BUFFER
    memset(buffer, 0, strlen(buffer));
    sprintf(buffer, "%s %s", LIST_REQ, username);

    // HERE ADD CRYPTOGRAPHIC FUNCTION TO SET PROPERLY THE BUFFER

    ret = send(sock, buffer, strlen(buffer), 0);
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
}

int renameClient(...)
{

}

int deleteClient(...)
{

}

int downloadClient(...)
{

}

int uploadClient(...)
{

}

int shareClient(...)
{
    
}