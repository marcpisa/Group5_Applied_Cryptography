#include "intclient.h"

int main(int argc, char* argv[])
{
    //********** VARIABLES ************
    // Socket management
    int connected = 0; // Variable to know if I already logged on the Server
    fd_set read_fds, master;
    int connectedSock;
    int new_sd, listenerTCP, ret, fdmax, port, s;
    struct sockaddr_in my_addr, srv_addr, srv_addr2;
    socklen_t addrlen;
    int exit_flag = 0;

    //Buffers
    char buffer[BUF_LEN];
    char command1[MAX_LEN_CMD];
    char command2[MAX_LEN_CMD];
    char command3[MAX_LEN_CMD];
    char username[MAX_LEN_USERNAME];

    // Others
    unsigned int nonce_cs = 0;
    unsigned int nonce_sc = 0;
    X509_STORE* ca_store;
    X509* cert_serv = NULL;;
    BIO* bio_cert;
    char* path_cert_serv = "../cert.pem";

    // Cryptographic operation
    unsigned char* session_key1 = NULL;
    unsigned char* session_key2 = NULL;
    
    //********* END VARIABLES *********

    if (argc != 3) { 
        printf("Error, the number of arguments is wrong... (./clientPr username port_num)\n");
        exit(-1);
    }
    
    printf("\n+++++++++++ FILE CLOUD MANAGER +++++++++++\n");
    
    // Checking username length and sanitize it
    if (strlen(argv[1]) > MAX_LEN_USERNAME)
    {
        printf("Username too long (MAX: %i)\n", MAX_LEN_USERNAME);
        exit(-1);
    }
    if (!username_sanitization(argv[1]))
    {
        printf("Username contains invalid chars (a-z | _ | -)\n");
        exit(-1);
    } 
    strcpy(username, argv[1]);
    if(strspn(argv[2], "0123456789") < strlen(argv[2])) 
    {
        printf("Port contains invalid chars (0-9)\n");
        exit(-1);
    }

    // CA store configuration
    ca_store = X509_STORE_new();
    bio_cert = BIO_new_file(path_cert_serv, "rb");
    if (!bio_cert) exit_with_failure("BIO_new_file failed", 1);

    PEM_read_bio_X509(bio_cert, &cert_serv, NULL, NULL);
    if (!cert_serv) exit_with_failure("PEM_read_bio_X509 failed", 1);
    ret = X509_STORE_add_cert(ca_store, cert_serv);
    if (ret != 1) exit_with_failure("X509_STORE_add_cert failed", 1);

    X509_free(cert_serv);
    BIO_free(bio_cert);


    // CONFIGURATION OF THE SERVER INFO
    memset(&srv_addr, 0, sizeof(srv_addr));
	srv_addr.sin_family = AF_INET; // IPv4
	port = SERVER_PORT;
	srv_addr.sin_port = htons(port); // port to connect to
	inet_pton(AF_INET, LOCALHOST, &srv_addr.sin_addr);

    // SOCKET TCP DECLARATION
    listenerTCP = socket(AF_INET, SOCK_STREAM, 0);
    if (listenerTCP == -1)
    {
        perror("Error during declaration of socket TCP: ");
        exit(-1);
    }
    printf("\nSocket TCP correctly allocated!\n");

    // SOCKET CONFIGURATION
    port = atoi(argv[2]); 
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
    printf(RED "Write 'help' to see the manual.\n" RESET ); 
    
    printf("Please, write a command..\n\n");

    // CONFIGURATION SET FOR THE SELECT FUNCTION
    FD_ZERO(&master);
    FD_ZERO(&read_fds);
    FD_SET(fileno(stdin), &master);
    FD_SET(listenerTCP, &master);
    if (listenerTCP > fileno(stdin)) fdmax = listenerTCP;
    else fdmax = fileno(stdin);
    
    while(!exit_flag)
    {
        read_fds = master;
        select(fdmax+1, &read_fds, NULL, NULL, 0);
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
                    addrlen = sizeof(srv_addr2);
                    new_sd = accept(listenerTCP, (struct sockaddr*)&srv_addr2, &addrlen);
                    
                    FD_SET(new_sd, &master);
                    if (new_sd > fdmax) fdmax = new_sd;
                }
                else if (i == fileno(stdin))
                {
                    //INPUT HANDLING AND SANITIZATION (Here we must study the theory and fix it)
                    strcpy(command1, ""); strcpy(command2, ""); strcpy(command3, "");
                    fgets(buffer, 3*COM_LEN+3, stdin);
                    fflush(stdin);

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
                    HELP = 9
                    EXIT = 10;
                    WRONG COMMAND = 0;*/


        


                    s = select_case_command(command1);
                    switch(s)
                    {
                        case 1: //*********** LOGIN **************
                            if (connected == 1)
                            {
                                printf("Connection already established. Login impossible operation!\n\n");
                                break;
                            }

                            ret = loginClient(&connectedSock, &session_key1, &session_key2, username, srv_addr, port, ca_store);
                            
                            if (ret == -1){
                                printf("Login failed.\n\n");
                                if(session_key1 != NULL && session_key2 != NULL)
                                {
                                    free(session_key1);
                                    free(session_key2);
                                }
                            } 
                            else 
                            {
                                if (chdir(MAIN_FOLDER_CLIENT) == -1)
                                {
                                    printf("Main folder of the client unaccessible...\n\n");
                                    exit_flag = 1;
                                }
                                printf("Login succedded.\n\n");
                                connected = 1;

                                
                            }
                            
                        
                            break;

                        case 2: //*********** LOGOUT ************

                            if (connected == 0)
                            {
                                printf("Not active connection. Login please!\n\n");
                                break;
                            }

                            ret = logoutClient(connectedSock, &nonce_cs, session_key2);
                            
                            if (ret != -1)
                            {
                                printf("Logout succeeded.\n\n");
                                connected = 0;
                                nonce_cs = 0;
                                nonce_sc = 0;

                                if (session_key1 != NULL && session_key2 != NULL) 
                                {
                                    free(session_key1);
                                    free(session_key2);
                                }
                                
                                // CONFIGURATION OF THE SERVER INFO
                                memset(&srv_addr, 0, sizeof(srv_addr));
	                            srv_addr.sin_family = AF_INET; // IPv4
	                            srv_addr.sin_port = htons(SERVER_PORT); // port to connect to
	                            inet_pton(AF_INET, LOCALHOST, &srv_addr.sin_addr);

                                // Back to src/client folder (from download)
                                if (chdir("../src/client") == -1)
                                {
                                    printf("src/client folder unaccessible...\n\n");
                                    exit_flag = 1;
                                }

                            }
                            else printf("Logout failed.\n\n");
                        
                            break;

                        case 3: //************ LIST *************
                            if (connected == 0)
                            {
                                printf("Not active connection. Login please!\n\n");
                                break;
                            }

                            ret = listClient(connectedSock, session_key1, session_key2, &nonce_cs);
                            
                            if (ret == -1) printf("Error during the list request!\n\n");
                            else printf("\n");

                            break;
                        
                        case 4: //*********** RENAME ************
                            if (connected == 0)
                            {
                                printf("Not active connection. Login please!\n\n");
                                break;
                            }
                            
                            // Sanitization and check length filename and new_filename
                            if (strlen(command2) > MAX_LEN_FILENAME || strlen(command3) > MAX_LEN_FILENAME) 
                            {
                                printf("Filename or new_filename too long. (Max len: %d)\n\n", MAX_LEN_FILENAME);
                                break;
                            } 
                            ret = filename_sanitization (command2);
                            if (ret == 0) 
                            {
                                printf("Filename sanitization failed.\n\n");
                                break;
                            }
                            ret = filename_sanitization (command3);
                            if (ret == 0) 
                            {
                                printf("Filename sanitization failed.\n\n");
                                break;
                            }

                            // Handle rename request
                            ret = renameClient(connectedSock, command2, command3, session_key1, session_key2, &nonce_cs);
                            
                            if (ret == -1) printf("Error during the rename operation request!\n\n");
                            else printf("\n");
                            
                            break;

                        case 5: //*********** DELETE **********
                            
                            if (connected == 0)
                            {
                                printf("Not active connection. Login please!\n\n");
                                break;
                            }

                            // Check length and filename sanitization
                            if (strlen(command2) > MAX_LEN_FILENAME) 
                            {
                                printf("Filename too long. (Max len: %d)\n\n", MAX_LEN_FILENAME);
                                break;
                            } 
                            ret = filename_sanitization (command2);
                            if (ret == 0) 
                            {
                                printf("Filename sanitization failed.\n\n");
                                break;
                            }

                            ret = deleteClient(connectedSock, command2, session_key1, session_key2, &nonce_cs);
                            if (ret == -1) printf("Error during the delete operation request!\n\n");
                            else printf("\n");
                            
                            break;

                        case 6: //*********** DOWNLOAD ************
                            if (connected == 0)
                            {
                                printf("Not active connection. Login please!\n\n");
                                break;
                            }

                            ret = downloadClient(connectedSock, command2, session_key1, session_key2, &nonce_cs); // format of the input given to the input stream: download filename

                            if (ret == -1) printf("Error during the download operation request!\n\n");
                            else printf("\n");

                            break;

                        case 7: //*********** UPLOAD *************
                            if (connected == 0)
                            {
                                printf("Not active connection. Login please!\n\n");
                                break;
                            }
                            
                            // Check length and filename sanitization
                            if (strlen(command2) > MAX_LEN_FILENAME) 
                            {
                                printf("Filename too long. (Max len: %d)\n\n", MAX_LEN_FILENAME);
                                break;
                            } 
                            ret = filename_sanitization (command2);
                            if (ret == 0) 
                            {
                                printf("Filename sanitization failed.\n\n");
                                break;
                            }
                            ret = uploadClient(connectedSock, command2, session_key1, session_key2, &nonce_cs);
                            
                            if (ret == -1) printf("Error during the upload operation request!\n\n");
                            else printf("\n");

                            break;

                        case 8: //********** SHARE ************
                            if (connected == 0)
                            {
                                printf("Not active connection. Login please!\n\n");
                                break;
                            }

                            //printf("In command2 we have %s and in command3 we have %s\n\n", command2, command3);
                            if (strcmp(command2, "")==0)
                            {
                                printf("The filename is missing... Retry\n\n");
                                break;
                            }
                            if (strcmp(command3, "")==0)
                            {
                                printf("The peername is missing... Retry\n\n");
                                break;
                            }

                            if (strlen(command2) > MAX_LEN_FILENAME || strlen(command3) > MAX_LEN_USERNAME)
                            {
                                printf("Input given is too long. Error.\n\n");
                                break;
                            }
                            else if (!filename_sanitization(command2) || !username_sanitization(command3))
                            {
                                printf("Sanitization fails. Error.\n\n");
                                break;
                            }

                            ret = shareClient(connectedSock, command2, command3, &nonce_cs, session_key1, session_key2);

                            if (ret == -1) printf("Error during the share operation request!\n\n");
                            else printf("\n");

                            break;
                        
                        case 9: //************HELP***************//
                            printf(GRN "This is the manual with the following commands:\n\n"); 
                            printf("Login: 'login' \n");        
                            printf("Logout: 'logout' \n"); 
                            printf("List all files: 'list'\n");
                            printf("Rename files: 'rename old_filename new_filename'\n"); 
                            printf("Delete file: 'delete filename'\n"); 
                            printf("Download file: 'download filename'\n");  
                            printf("Upload file: 'upload file_location'\n");  
                            printf("Share file with other user: 'share filename username'\n"); 
                            printf("Accept / Decline Share: 'yes / no'\n" RESET);
                            printf("\n"); 
                            break; 

                        case 10: //********** EXIT ***********//
                                if(connected == 1)
                                {
                                    ret = logoutClient(connectedSock, &nonce_cs, session_key2);
                            
                                    if (ret != -1)
                                    {
                                        printf("Logging out...\n\n");
                                        connected = 0;
                                    }
                                    else printf("Logout failed.\n\n");

                                    if (session_key1 != NULL && session_key2 != NULL) 
                                    {
                                        free(session_key1);
                                        free(session_key2);
                                    }
                                }

                                printf("Exiting the program.\n");
                                exit_flag = 1;

                                break;

                        default:
                            printf("Command inserted is wrong: retry...\n\n");
                            break;
                    }
                    fflush(stdin);
                }
                else //MANAGER FOR AN ACCEPTED COMMUNICATION
                {
                    memset(buffer, 0, BUF_LEN);
                    ret = recv(i, buffer, BUF_LEN, 0);
                    if (ret == -1)
                    {
                        printf("Error during recieve function!\n\n");
                        exit(1);
                    }

                    ret = shareReceivedClient(i, buffer, &nonce_sc, session_key1, session_key2);
                    if (ret == -1) printf("Error during received share request!\n\n");
                    close(i);
					FD_CLR(i, &master);
                    fflush(stdin);
                }
            }
        }
    }
    close(listenerTCP);
    X509_STORE_free(ca_store);
    
    return 0;
}
