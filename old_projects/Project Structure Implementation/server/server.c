#include "intserver.h"

int main(int argc, char* argv[])
{
    // *********** VARIABLES ************
    
    // Socket management variables
    int ret, pid, listenerTCP, len, i, nbytes, fdmax, new_sd, s;
    uint32_t addr_app;
    fd_set master;
    fd_set read_fds;
    socklen_t addrlen;
    struct sockaddr_in srv_addr, cl_addr;
    
    // Buffers
    char buffer[BUF_LEN];
    char bufferSupp1[BUF_LEN];
    char bufferSupp2[BUF_LEN];
    char bufferSupp3[BUF_LEN];
    char command1[BUF_LEN];


    // Timeout varible for the select function
    struct timeval tv;

    // ********** END VARIABLES *********

    if (argc != 1)
    {
        printf("Error during boot phase: number of arguments is wrong...\n\n");
        exit(-1);
    }

    printf("\n+++++++++++ FILE CLOUD SERVER +++++++++++\n");
    printf("File Cloud Server booted correctly...\n");

    // SOCKET DECLARATION
    listenerTCP = socket(AF_INET, SOCK_STREAM, 0);
    if (listenerTCP == -1)
    {
        perror("Error during the declaration of the socket: ");
        exit(-1);
    }
    printf("\nServer' socket created correctly!\n");

    //SOCKET CONFIGURATION
    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(SERVER_PORT);
    srv_addr.sin_addr.s_addr = INADDR_ANY;

    // BIND PHASE OF THE SOCKET
    addrlen = sizeof(srv_addr);
    ret = bind(listenerTCP, (struct sockaddr*)&srv_addr, addrlen);
    if (ret < 0)
    {
        perror("Error during bind phase: ");
        exit(-1);
    }
    printf("Bind of the socket with address %i and port %i correctly executed", srv_addr.sin_addr.s_addr, SERVER_PORT);
    
    ret = listen(listenerTCP, 10);
    if (ret < 0)
    {
        perror("Error during listen function execution: ");
        exit(-1);
    }
    printf("Bind phase correctly executed: port %i used!\n\n", SERVER_PORT);

    // CONFIGURATION DATA STRUCTURES FOR THE SELECT FUNCTION
    FD_ZERO(&master);
    FD_ZERO(&read_fds);
    FD_SET(fileno(stdin), &master);
    FD_SET(listenerTCP, &master);
    if (listenerTCP > fileno(stdin)) fdmax = listenerTCP;
    else fdmax = fileno(stdin);
    printf("I'm using the select function to attend for more than one event...\n\n");
    while(1)
    {
        //printf("Another turn of select has been done. It means that the software is behaving correctly..\n\n");
        read_fds = master;
        select (fdmax+1, &read_fds, NULL, NULL, &tv);
        for (i = 0; i <= fdmax; i++)
        {
            if (FD_ISSET(i, &read_fds))
            {
                if (i == listenerTCP)
                {
                    //Here it means that I received a message from the server
                    // so i store the information about the server address and
                    // call the accept function. The accept function send
                    // a response to the server.
                    addrlen = sizeof(cl_addr);
                    new_sd = accept(listenerTCP, (struct sockaddr*)&cl_addr, &addrlen);
                    FD_SET(new_sd, &master);
                    if (new_sd > fdmax) fdmax = new_sd;
                    printf("We received and accepted a client connection request...\n\n");
                }
                else if (i == fileno(stdin))
                {
                    //INPUT HANDLING AND SANITIZATION (Here we must study the theory and fix it)
                    strcpy(command1, "");
                    fgets(buffer, COM_LEN, stdin);
                    sscanf(buffer, "%s", command1);
                    if (strcmp(command1, "exit") == 0)
                    {
                        printf("Done!\n\n");
                        close(listenerTCP);
                        continue;
                    }
                    else printf("Unexpected input given...\n\n");
                }
                else //Manager for the accepted communications
                {
                    nbytes = BUF_LEN;
                    ret = recv(i, buffer, nbytes, 0);
                    if (ret < 0)
                    {
                        perror("Errore in fase di ricezione: ");
                        close(listenerTCP);
                        exit(-1);
                    }

                    // We check the first keyword to understand what the Client wants us to do
                    memset(bufferSupp1, 0, strlen(bufferSupp1)); //we clean the mem
                    //Remember to sanitize the buffers
                    sscanf(buffer, "%s", bufferSupp1);
                    
                    
                    // ************ LOGIN REQUEST MANAGER ***********
                    if (strcmp(bufferSupp1, LOGIN_REQUEST) == 0)
                    {
                        // Using fork function we are choosing a multiprocess approach
                        // for the management of requests from clients and to avoid
                        // deadlock conditions on the listener socket.
                        pid = fork();
                        if (pid < 0)
                        {
                            perror("Error during fork execution: ");
                            exit(-1);
                        }
                        if (pid == 0)
                        {
                            //We are in the son part of code
                            close(listenerTCP);
                            printf("\nA login request has came up...\n\n");
                            // LOGIN MANAGER: SERVER SIDE
                            
                            // Do stuff

                            printf("End of login request management!\n\n");
                            close(i);
                            exit(0);
                        }
                    }


                    //************ LOGOUT REQUEST MANAGER ************
                    else if (strcmp(bufferSupp1, LOGOUT_REQUEST) == 0)
                    {
                        // Using fork function we are choosing a multiprocess approach
                        // for the management of requests from clients and to avoid
                        // deadlock conditions on the listener socket.
                        pid = fork();
                        if (pid < 0)
                        {
                            perror("Error during fork execution: ");
                            exit(-1);
                        }
                        if (pid == 0)
                        {
                            //We are in the son part of code
                            close(listenerTCP);
                            printf("\nA logout request has came up...\n\n");
                            // LOGOUT MANAGER: SERVER SIDE
                            
                            // Do stuff

                            printf("End of logout request management!\n\n");
                            close(i);
                            exit(0);
                        }
                    }


                    // ************* LIST REQUEST MANAGER ***************
                    else if (strcmp(bufferSupp1, LIST_REQUEST) == 0)
                    {
                        // Using fork function we are choosing a multiprocess approach
                        // for the management of requests from clients and to avoid
                        // deadlock conditions on the listener socket.
                        pid = fork();
                        if (pid < 0)
                        {
                            perror("Error during fork execution: ");
                            exit(-1);
                        }
                        if (pid == 0)
                        {
                            //We are in the son part of code
                            close(listenerTCP);
                            printf("\nA list request has came up...\n\n");
                            // LIST MANAGER: SERVER SIDE
                            
                            ret = listServer(i, buffer);
                            if (ret == -1)
                            {
                                printf("Something bad happened during the management of the client list request...\n\n");
                                exit(1);
                            }
                            else printf("I managed a list request and all was good!\n\n");

                            //END COMMUNICATION

                            printf("End of list request management!\n\n");
                            close(i);
                            exit(0);
                        }
                    }


                    //*************** RENAME REQUEST MANAGER *****************
                    else if (strcmp(bufferSupp1, RENAME_REQUEST) == 0)
                    {
                        // Using fork function we are choosing a multiprocess approach
                        // for the management of requests from clients and to avoid
                        // deadlock conditions on the listener socket.
                        pid = fork();
                        if (pid < 0)
                        {
                            perror("Error during fork execution: ");
                            exit(-1);
                        }
                        if (pid == 0)
                        {
                            //We are in the son part of code
                            close(listenerTCP);
                            printf("\nA rename request has came up...\n\n");
                            // RENAME MANAGER: SERVER SIDE
                            
                            ret = renameServer(i, buffer);
                            if (ret == -1)
                            {
                                printf("Something bad happened during the management of the client rename request...\n\n");
                                exit(1);
                            }

                            printf("End of rename request management!\n\n");
                            close(i);
                            exit(0);
                        }
                    }


                    // **************** DELETE REQUEST MANAGER ******************
                    else if (strcmp(bufferSupp1, DELETE_REQUEST) == 0)
                    {
                        // Using fork function we are choosing a multiprocess approach
                        // for the management of requests from clients and to avoid
                        // deadlock conditions on the listener socket.
                        pid = fork();
                        if (pid < 0)
                        {
                            perror("Error during fork execution: ");
                            exit(-1);
                        }
                        if (pid == 0)
                        {
                            //We are in the son part of code
                            close(listenerTCP);
                            printf("\nA delete request has came up...\n\n");
                            // DELETE MANAGER: SERVER SIDE
                            
                            // Do stuff

                            printf("End of delete request management!\n\n");
                            close(i);
                            exit(0);
                        }
                    }


                    // *************** DOWNLOAD REQUEST MANAGER ****************
                    else if (strcmp(bufferSupp1, DOWNLOAD_REQUEST) == 0)
                    {
                        // Using fork function we are choosing a multiprocess approach
                        // for the management of requests from clients and to avoid
                        // deadlock conditions on the listener socket.
                        pid = fork();
                        if (pid < 0)
                        {
                            perror("Error during fork execution: ");
                            exit(-1);
                        }
                        if (pid == 0)
                        {
                            //We are in the son part of code
                            close(listenerTCP);
                            printf("\nA download request has came up...\n\n");
                            // DOWNLOAD MANAGER: SERVER SIDE
                            
                            // Do stuff

                            printf("End of download request management!\n\n");
                            close(i);
                            exit(0);
                        }
                    }


                    // *************** UPLOAD REQUEST MANAGER ***************
                    else if (strcmp(bufferSupp1, UPLOAD_REQUEST) == 0)
                    {
                        // Using fork function we are choosing a multiprocess approach
                        // for the management of requests from clients and to avoid
                        // deadlock conditions on the listener socket.
                        pid = fork();
                        if (pid < 0)
                        {
                            perror("Error during fork execution: ");
                            exit(-1);
                        }
                        if (pid == 0)
                        {
                            //We are in the son part of code
                            close(listenerTCP);
                            printf("\nAn upload request has came up...\n\n");
                            // UPLOAD MANAGER: SERVER SIDE
                            
                            // Do stuff

                            printf("End of upload request management!\n\n");
                            close(i);
                            exit(0);
                        }
                    }


                    // **************** SHARE REQUEST MANAGER ****************
                    else if (strcmp(bufferSupp1, SHARE_REQUEST) == 0)
                    {
                        // Using fork function we are choosing a multiprocess approach
                        // for the management of requests from clients and to avoid
                        // deadlock conditions on the listener socket.
                        pid = fork();
                        if (pid < 0)
                        {
                            perror("Error during fork execution: ");
                            exit(-1);
                        }
                        if (pid == 0)
                        {
                            //We are in the son part of code
                            close(listenerTCP);
                            printf("\nA share request has came up...\n\n");
                            // SHARE MANAGER: SERVER SIDE
                            
                            // Do stuff

                            printf("End of share request management!\n\n");
                            close(i);
                            exit(0);
                        }
                    }


                    else printf("Unknown type of request by the Client...");
                    // Here we can also send a message to the client saying that we didn't understand what it wants
                    close(i);
                    FD_CLR(i, &master);
                }
            }
        }
    }
    close(listenerTCP);
    return 0;
}
