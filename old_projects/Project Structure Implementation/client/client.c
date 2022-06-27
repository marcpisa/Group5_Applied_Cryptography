#include "intclient.h"
//#include "../sanitization.c"

int main(int argc, char* argv[])
{
    //********** VARIABLES ************

    // Variables for socket management
    int connected = 0; // Variable to know if I already logged on the Server
    fd_set read_fds, master;
    int new_sd, listenerTCP, nbytes, ret, fdmax, pid, port, s;
    struct sockaddr_in my_addr, srv_addr;
    socklen_t addrlen;

    //Buffers
    char buffer[COM_LEN];
    char command1[MAX_LEN_CMD];
    char command2[MAX_LEN_CMD];
    char command3[MAX_LEN_CMD];
    char username[MAX_LEN_USR];

    // Timeout Variables
    struct timeval tv;

    // Variables for file management
    FILE* fd1;

    //********* END VARIABLES *********

    if (argc != 2)
    {
        printf("Error at the boot phase of the Client. The number of arguments is wrong...\n");
        exit(-1);
    }
    printf("\n+++++++++++ FILE CLOUD MANAGER +++++++++++\n");
    printf("File Cloud Manager booted correctly...\n");

    // CHECKING USERNAME LENGTH
    if (strlen(argv[2]) > MAX_LEN_USR)
    {
        printf("Username too long... max length %i\n", MAX_LEN_USR);
        exit(1);
    }

    // Set the value of the max interval that the select function wait for an action to do
    tv.tv_sec = SELECT_SEC_TO_WAIT;
	tv.tv_usec = 0;

    // SOCKET TCP DECLARATION
    listenerTCP = socket(AF_INET, SOCK_STREAM, 0);
    if (listenerTCP == -1)
    {
        perror("Error during declaration of socket TCP: ");
        exit(-1);
    }
    printf("\nSocket TCP correctly allocated!\n");

    //SOCKET CONFIGURATION
    port = atoi(argv[1]);
    memset(&my_addr, 0, sizeof(my_addr));
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(port);
    my_addr.sin_addr.s_addr = INADDR_ANY;
    addrlen = sizeof(my_addr);

    // BIND PHASE OF THE SOCKET
    ret = bind(listenerTCP, (struct sockaddr*)&my_addr, addrlen);
    if (ret < 0)
    {
        perror("Error during bind phase of TCP socket: ");
        exit(-1);
    }
    ret = listen(listenerTCP, 10);
    if (ret < 0)
    {
        perror("Error during listen function execution: ");
        exit(-1);
    }
    printf("Bind phase correctly executed: port %i used!\n\n", port);

    // CONFIGURATION SET FOR THE SELECT FUNCTION
    FD_ZERO(&master);
    FD_ZERO(&read_fds);
    FD_SET(fileno(stdin), &master);
    FD_SET(listenerTCP, &master);
    if (listenerTCP > fileno(stdin)) fdmax = listenerTCP;
    else fdmax = fileno(stdin);

    while(1)
    {
        read_fds = master;
        select(fdmax+1, &read_fds, NULL, NULL, &tv);
        printf("Please, write a command..\n\n");
        for (int i = 0; i <= fdmax; i++)
        {
            if (FD_ISSET(i, &read_fds))
            {
                if (i == listenerTCP)
                {
                    //Here it means that I received a message from the server
                    // so i store the information about the server address and
                    // call the accept function. The accept function send
                    // a response to the server.
                    addrlen = sizeof(srv_addr);
                    new_sd = accept(listenerTCP, (struct sockaddr*)&srv_addr, &addrlen);
                    FD_SET(new_sd, &master);
                    if (new_sd > fdmax) fdmax = new_sd;
                }
                else if (i == fileno(stdin))
                {
                    //INPUT HANDLING AND SANITIZATION (Here we must study the theory and fix it)
                    strcpy(command1, ""); strcpy(command2, ""); strcpy(command3, "");
                    fgets(buffer, COM_LEN, stdin);
                    sscanf(buffer, "%s %s %s", command1, command2, command3);
                    if (strcmp(command1, "") == 0)
                    {
                        printf("Input Error: Data inserted not valid\n\n");
                        continue;
                    }
                    /* To use the switch we consider these combinations:
                    LOGIN = 1;
                    LOGOUT = 2;
                    LIST = 3;
                    RENAME = 4;
                    DELETE = 5;
                    DOWNLOAD = 6;
                    UPLOAD = 7;
                    SHARE = 8;
                    WRONG COMMAND = 0;*/

                    //s = input_sanitization_commands(command1);
                    
                    //This part will be deleted when the sanitization part is over
                    if (strcmp(command1, LOGIN) == 0) s = 1;
                    else if (strcmp(command1, LOGOUT) == 0) s = 2;
                    else if (strcmp(command1, LIST) == 0) s = 3;
                    else if (strcmp(command1, RENAME) == 0) s = 4;
                    else if (strcmp(command1, DELETE) == 0) s = 5;
                    else if (strcmp(command1, DOWNLOAD) == 0) s = 6;
                    else if (strcmp(command1, UPLOAD) == 0) s = 7;
                    else if (strcmp(command1, SHARE) == 0) s = 8;
                    else s = 0;

                    switch(s)
                    {
                        case 1: //*********** LOGIN **************

                        // Stuff to do

                            break;

                        case 2: //*********** LOGOUT ************

                            if (connected == 0)
                            {
                                printf("Not active connection. Login please!\n\n");
                                break;
                            }
                            // Stuff to do
                        
                            break;

                        case 3: //************ LIST *************
                        
                            // Stuff to do
                            if (connected == 0)
                            {
                                printf("Not active connection. Login please!\n\n");
                                break;
                            }

                            ret = listClient(username, srv_addr);
                            if (ret == 1) {printf("Something bad happend\n\n"); exit(1);}
                        
                            break;
                        
                        case 4: //*********** RENAME ************
                            if (connected == 0)
                            {
                                printf("Not active connection. Login please!\n\n");
                                break;
                            }

                            ret = renameClient(username, command1, command2, srv_addr);
                            if (ret == -1)
                            {
                                printf("Error during the rename operation request!\n\n");
                                exit(1);
                            }
                            break;

                        case 5: //*********** DELETE **********
                            if (connected == 0)
                            {
                                printf("Not active connection. Login please!\n\n");
                                break;
                            }
                            // Stuff to do

                            break;

                        case 6: //*********** DOWNLOAD ************
                            if (connected == 0)
                            {
                                printf("Not active connection. Login please!\n\n");
                                break;
                            }
                            // Stuff to do

                            break;

                        case 7: //*********** UPLOAD *************
                            if (connected == 0)
                            {
                                printf("Not active connection. Login please!\n\n");
                                break;
                            }
                            // Stuff to do

                            break;

                        case 8: //********** SHARE ************
                            if (connected == 0)
                            {
                                printf("Not active connection. Login please!\n\n");
                                break;
                            }
                            //Stuff to do

                            break;

                        default:
                            printf("Command inserted is wrong: retry...\n\n");
                            break;
                    }
                    fflush(stdin);
                }
                else //MANAGER FOR AN ACCEPTED COMMUNICATION
                {
                    // Here are stuff concerning the "share" function. We have to manage
                    // the request to share files (second Client part)
                    close (i);
                    FD_CLR(i, &master);
                }
            }
        }
    }
    close(listenerTCP);
    return 0;
}
