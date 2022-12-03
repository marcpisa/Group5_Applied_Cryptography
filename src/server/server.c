#include "intserver.h"

int main()
{
    //*********** VARIABLES ************
    int exit_flag = 0;
    user_stat* user_list;
    FILE* fp;
    char* line;
    int index = 0;

    // Socket management variables
    int ret, pid, listenerTCP, i, fdmax, new_sd;
    //uint32_t addr_app;
    fd_set master;
    fd_set read_fds;
    socklen_t addrlen;
    struct sockaddr_in srv_addr, cl_addr;
    
    // Buffers
    char received_buffer[BUF_LEN];
    char remote_comm[BUF_LEN];
    char local_comm[BUF_LEN];
    char* username;

    // Timeout varible for the select function
    struct timeval tv;   

    // Recover the user list
    user_list = (user_stat*) malloc(NUM_USER*sizeof(user_stat));
    fp = fopen("../user_list.txt", "r");
    if (!fp) exit_with_failure("Open user_list.txt failed", 1);
    line = (char*) malloc(MAX_LEN_USERNAME*sizeof(char));
    if (!line) exit_with_failure("Malloc line failed", 1);

    while (getline(&line, NULL, fp) != -1) {
        memcpy((user_list+index)->username, line, strlen(line));
        (user_list+index)->connected = 0;
        index += 1;
    }

    fclose(fp);
    free(line);

    // Allocate username
    username = (char*) malloc((MAX_LEN_USERNAME+1)*sizeof(char));
    if (!username) exit_with_failure("Malloc username failed", 1);


    // ********** END VARIABLES *********

    printf("\n+++++++++++ FILE CLOUD SERVER +++++++++++\n");

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
    
    while(!exit_flag)
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
                    //sanitization not necessary because the command is checked in next if blocks.
                    strcpy(local_comm, "");
                    fgets(received_buffer, COM_LEN, stdin);
                    sscanf(received_buffer, "%s", local_comm);
                    if (strcmp(local_comm, "exit") == 0)
                    {
                        printf("Done!\n\n");
                        exit_flag = 1;
                        close(listenerTCP);
                        continue;
                    }
                    else printf("Unexpected input given...\n\n");
                }
                else //Manager for the accepted communications
                {
                    memset(received_buffer, 0, BUF_LEN); // ???
                    //printf("Now the buffer contains %s\n\n", buffer);
                    ret = recv(i, received_buffer, BUF_LEN, 0);
                    if (ret < 0)
                    {
                        perror("Error during recv operation: ");
                        close(listenerTCP);
                        exit(-1);
                    }
                    // We check the first keyword to understand what the Client wants us to do
                    memset(remote_comm, 0, BUF_LEN);
                    memcpy(remote_comm, received_buffer, str_ssplit((unsigned char*) received_buffer, DELIM));
                    // ************ LOGIN REQUEST MANAGER ***********
                    if (strcmp(remote_comm, LOGIN_REQUEST) == 0)
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
                            printf("\nA login request has come up.\n\n");
                            // LOGIN MANAGER: SERVER SIDE

                            ret = loginServer(i, received_buffer);
                            if (ret == -1)
                            {
                                printf("Something bad happened during the management of the client login request...\n\n");
                                exit(1);
                            }
                            else printf("The operation has been carried out and the user has logged out!\n");

                            printf("Closing thread...!\n\n");
                            close(i);
                            exit(0);
                        }
                    }
                    else if (strcmp(remote_comm, LOGOUT_REQUEST) == 0 ||
                             strcmp(remote_comm, LIST_REQUEST) == 0 ||
                             strcmp(remote_comm, RENAME_REQUEST) == 0 ||
                             strcmp(remote_comm, DELETE_REQUEST) == 0 ||
                             strcmp(remote_comm, DOWNLOAD_REQUEST) == 0 ||
                             strcmp(remote_comm, UPLOAD_REQUEST) == 0 ||
                             strcmp(remote_comm, SHARE_REQUEST) == 0
                             ) printf("We received a request about an operation but the user is not logged yet... Something bad happened...\n\n");

                    else printf("Unknown type of request by the Client...\n");
                    memset(received_buffer, 0, BUF_LEN);
                    close(i);
                    FD_CLR(i, &master);
                }
            }
        }
    }
    
    close(listenerTCP);
    
    free(user_list);
    free(username);
    
    return 0;
}
