#include "intserver.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <sys/sendfile.h>
#include <openssl/x509.h>
#include <openssl/rand.h>

/*********************************************
 *                 INTERFACES
 ********************************************/
int createSocket()
{
    int sock;
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return -1;
    }
    return sock;
}

int loginServer(int sd, char* rec_mex, unsigned char* session_key1, unsigned char* session_key2)
{
    unsigned char* buffer;
    unsigned char* msg_to_sign;
    char* temp;
    unsigned char* bufferSupp1;
    unsigned char* bufferSupp2;
    char* path_pubkey = "../dh_server_pubkey.pem";
    char* path_cert_rsa = "cert.pem";
    char* path_rsa_key = "rsa_prvkey.pem";
    char* path_cert_client_rsa;
    int ret;
    int msg_len;
    char username [MAX_LEN_USERNAME];
    size_t offset, old_offset;
    size_t K_len;

    // Certificate
    unsigned char* cert_byte;
    int cert_len = 0;
    EVP_PKEY* pub_rsa_client;

    // Digital Signature variables
    unsigned char* signature;
    unsigned int signature_len;
    int msg_to_sign_len;

    // Diffie-Hellman variables
    EVP_PKEY* dh_pubkey = NULL;
    EVP_PKEY* my_prvkey = NULL;
    EVP_PKEY* peer_pubkey;
    
    unsigned char* pubkey_byte = NULL;
    unsigned char* K;
    
    int pubkey_len = 0;
    unsigned int len_username;

    /*********************
     * END VARIABLES
     ********************/
    
    /* Generate private and certificate for public key
     * Private key
     *      openssl genrsa -aes128 -out rsa_prvkey.pem 2048
     * Public key
     *      openssl rsa -pubout -in rsa_prvkey.pem -out rsa_pubkey.pem
     * Certificate
     *      openssl req -new -x509 -key rsa_prvkey.pem -out cert.pem -days 360
     */
    
    // Generate DH asymmetric key(s)
    pubkey_byte = gen_dh_keys(path_pubkey, &my_prvkey, &dh_pubkey, &pubkey_len);




    /* ---- Parse the first message (login request message + username + DH pubkey) ---- */
    bufferSupp1 = (unsigned char*) malloc(sizeof(unsigned char)*MAX_LEN_USERNAME);
    if (!bufferSupp1) exit_with_failure("Malloc bufferSupp1 failed", 1);
    bufferSupp2 = (unsigned char*) malloc(sizeof(unsigned char)*pubkey_len);
    if (!bufferSupp2) exit_with_failure("Malloc bufferSupp2 failed", 1);

    offset = str_ssplit((unsigned char*) rec_mex, DELIM); // login request already parsed
    if (offset != (unsigned int) strlen(LOGIN_REQUEST)) exit_with_failure("Wrong login req. length", 0);
    old_offset = offset+BLANK_SPACE;

    offset = str_ssplit(&*((unsigned char*) rec_mex+old_offset), DELIM);
    memcpy(bufferSupp1, &*(rec_mex+old_offset), offset); // username
    memcpy(&*(bufferSupp1+offset), "\0", 1);
    len_username = offset;
    old_offset += offset+BLANK_SPACE;

    memcpy(bufferSupp2, &*(rec_mex+old_offset), pubkey_len); // dh pubkey

    
    //printf("%d %d %d\n", pubkey_len_rec, iv_len, signature_len);
    //for(int i = 0; i < 1218; i++) { printf("%c", *(rec_mex+i)); }
    //printf("\n\n"); 

    // Sanitize and check username
    if (!username_sanitization((char*) bufferSupp1)) exit_with_failure("Username sanitization fails.\n", 0);
    

    // SERVER SHOULD CHECK IF THE USER IS ALREADY ONLINE

    ret = chdir(MAIN_FOLDER_SERVER);
    if (ret == -1) exit_with_failure("No such directory.\n", 0);
    ret = chdir((char*) bufferSupp1);
    if (ret == -1) exit_with_failure("Error: username doesn't exists...\n", 0);
  
    memset(username, 0, MAX_LEN_USERNAME);
    memcpy(username, bufferSupp1, len_username);

    // Retrieve the client pubkey (from the client cert., already owned by the server)
    path_cert_client_rsa = (char*) malloc(sizeof(char)*(5+len_username+4+1));
    memcpy(path_cert_client_rsa, "cert_", 5);
    memcpy(&*(path_cert_client_rsa+5), username, strlen(username));
    memcpy(&*(path_cert_client_rsa+5+strlen(username)), ".pem\0", 4+1);
    pub_rsa_client = get_client_pubkey(path_cert_client_rsa);
    
    // Calculate K = g^a^b mod p, established key
    peer_pubkey = pubkey_to_PKEY(bufferSupp2, pubkey_len);
    K = key_derivation(my_prvkey, peer_pubkey, &K_len);

    // Obtain the two session keys from the established key
    issue_session_keys(K, K_len, &session_key1, &session_key2);
    
    printf("First message is correct. Preparing the response...\n");

    free(bufferSupp1);
    free(path_cert_client_rsa);
    EVP_PKEY_free(my_prvkey);
    EVP_PKEY_free(peer_pubkey);




    /* --- Send response (DH pubkey, signature, len. cert. and cert.) --- */
    // Prepare the digital signature
    msg_to_sign_len = pubkey_len+BLANK_SPACE+pubkey_len;
    msg_to_sign = (unsigned char*) malloc(sizeof(unsigned char)*msg_to_sign_len);
    if (!msg_to_sign) exit_with_failure("Malloc msg_to_sign failed", 1);
    
    memcpy(msg_to_sign, bufferSupp2, pubkey_len); // peer pubkey is still inside bufferSupp2
    memcpy(&*(msg_to_sign+pubkey_len), " ", BLANK_SPACE);
    memcpy(&*(msg_to_sign+pubkey_len+BLANK_SPACE), pubkey_byte, pubkey_len);
    
    ret = chdir("../../src");
    if (ret == -1) exit_with_failure("No such directory.\n", 0);
    signature = sign_msg(path_rsa_key, msg_to_sign, msg_to_sign_len, &signature_len);
 
    // Serialize the certificate
    cert_byte = read_cert(path_cert_rsa, &cert_len);

    // Come back to the user directory
    ret = chdir("../database/");
    if (ret == -1) exit_with_failure("No such directory.\n", 0);
    ret = chdir(username);
    if (ret == -1) exit_with_failure("No such directory.\n", 0);

    // Calculating message length and allocate memory for it
    msg_len = pubkey_len+BLANK_SPACE+SIGN_LEN+BLANK_SPACE+LEN_SIZE+BLANK_SPACE+cert_len+1;
    buffer = (unsigned char*) malloc(sizeof(unsigned char)*msg_len);
    if (!buffer) exit_with_failure("Malloc buffer failed", 1);
    temp = (char*) malloc(sizeof(char)*LEN_SIZE);
    if (!temp) exit_with_failure("Malloc temp failed", 1);

    // Compose the message
    memcpy(buffer, pubkey_byte, pubkey_len); // g^b
    memcpy(&*(buffer+pubkey_len), " ", BLANK_SPACE);
    memcpy(&*(buffer+pubkey_len+BLANK_SPACE), signature, SIGN_LEN); // dig. sig.
    memcpy(&*(buffer+pubkey_len+BLANK_SPACE+SIGN_LEN), " ", BLANK_SPACE);

    sprintf(temp, "%d", cert_len);
    memcpy(&*(buffer+pubkey_len+BLANK_SPACE+SIGN_LEN+BLANK_SPACE), temp, LEN_SIZE); // len cert    

    memcpy(&*(buffer+pubkey_len+BLANK_SPACE+SIGN_LEN+BLANK_SPACE+LEN_SIZE), " ", BLANK_SPACE);
    memcpy(&*(buffer+pubkey_len+BLANK_SPACE+SIGN_LEN+BLANK_SPACE+LEN_SIZE+BLANK_SPACE), \
    cert_byte, cert_len); // cert.

    memcpy(&*(buffer+msg_len-1), "\0", 1);


    //printf("%s\n", buffer);
    printf("I'm sending to the client the response.\n");
    ret = send(sd, buffer, msg_len, 0); 
    if (ret == -1) exit_with_failure("Send failed: ", 1);

    free(bufferSupp2);
    free(temp);
    free(buffer);
    free(pubkey_byte);
    free(cert_byte);
    free(signature);

    EVP_PKEY_free(dh_pubkey);




    /* Parse the client message and verify the fields */
    msg_len = SIGN_LEN;
    buffer = (unsigned char*) malloc(sizeof(unsigned char)*msg_len);
    if (!buffer) exit_with_failure("Malloc buffer failed", 1);
    bufferSupp1 = (unsigned char*) malloc(sizeof(unsigned char)*(SIGN_LEN+1));
    if (!bufferSupp1) exit_with_failure("Malloc bufferSupp1 failed", 1);

    ret = recv(sd, buffer, msg_len, 0);
    if (ret == -1) exit_with_failure("Receive failed: ", 1);
 
    memcpy(bufferSupp1, buffer, SIGN_LEN); // username
    memcpy(&*(bufferSupp1+SIGN_LEN), "\0", 1);

    // Verify signature
    ret = verify_signature(msg_to_sign, msg_to_sign_len, bufferSupp1, SIGN_LEN, pub_rsa_client);
    if (ret != 1) exit_with_failure("Signature verification failed.\n", 0);
    
    
    free(buffer);
    free(msg_to_sign);
    free(K);
    EVP_PKEY_free(pub_rsa_client);

    
    
    // FUNCTIONAL PART
    // Now that we have the cryptographic elements to have a secure communication with the client we are able to receive function messages
    
    printf("I managed a login request and all was good!\n\n");
    
    //printf("Now the buffer contains %s\n\n", buffer);
    while (1)
    {
        memset(buffer, 0, BUF_LEN);
        ret = recv(sd, buffer, BUF_LEN, 0);
        if (ret < 0)
        {
            perror("Error during recv operation: ");
            exit(-1);
        }
        // We check the first keyword to understand what the Client wants us to do
        memset(bufferSupp1, 0, BUF_LEN);
        memcpy(bufferSupp1, buffer, str_ssplit((unsigned char*) buffer, DELIM));


        // ************ LOGIN REQUEST MANAGER ***********
        if (strcmp(bufferSupp1, LOGIN_REQUEST) == 0)
        {
            printf("\nWe received a login request but this client is already logged... Something bad happened...\n\n");
        }


        //************ LOGOUT REQUEST MANAGER ************
        else if (strcmp(bufferSupp1, LOGOUT_REQUEST) == 0)
        {
            printf("\nA logout request has came up...\n\n");
            // LOGOUT MANAGER: SERVER SIDE
                            
            // Do stuff

            printf("End of logout request management!\n\n");
            close(sd);
            exit(0);
        }


        // ************* LIST REQUEST MANAGER ***************
        else if (strcmp(bufferSupp1, LIST_REQUEST) == 0)
        {
            printf("\nA list request has came up...\n\n");
            // LIST MANAGER: SERVER SIDE
                            
            ret = listServer(sd, buffer);
            if (ret == -1)
            {
                printf("Something bad happened during the management of the client list request...\n\n");
                exit(1);
            }
            else printf("I managed a list request and all was good!\n\n");
        }


        //*************** RENAME REQUEST MANAGER *****************
        else if (strcmp(bufferSupp1, RENAME_REQUEST) == 0)
        {
            printf("\nA rename request has came up...\n\n");
            // RENAME MANAGER: SERVER SIDE
                            
            ret = renameServer(sd, buffer);
            if (ret == -1)
            {
                printf("Something bad happened during the management of the client rename request...\n\n");
                exit(1);
            }
            else printf("End of rename request management!\n\n");
        }


        // **************** DELETE REQUEST MANAGER ******************
        else if (strcmp(bufferSupp1, DELETE_REQUEST) == 0)
        {
            printf("\nA delete request has came up...\n\n");
            // DELETE MANAGER: SERVER SIDE
                            
            ret = deleteServer(sd, buffer);
            if (ret == -1)
            {
                printf("Something bad happened during the management of the client delete request...\n\n");
                exit(1);
            }
            else printf("I managed a delete request and all was good!\n\n");
        }

        
        // *************** DOWNLOAD REQUEST MANAGER ****************
        else if (strcmp(bufferSupp1, DOWNLOAD_REQUEST) == 0)
        {
            printf("\nA download request has came up...\n\n");

            // DOWNLOAD MANAGER: SERVER SIDE
                            
            ret = downloadServer(sd, buffer);
            if (ret == -1)
            {
                printf("Something bad happened during the management of the client download request...\n\n");
                exit(1);
            }
            else printf("I managed a download request and all was good!\n\n");
        }


        // *************** UPLOAD REQUEST MANAGER ***************
        else if (strcmp(bufferSupp1, UPLOAD_REQUEST) == 0)
        {
            printf("\nAn upload request has came up...\n\n");
            // UPLOAD MANAGER: SERVER SIDE
                            
            ret = uploadServer(sd, buffer);
            if (ret == -1)
            {
                printf("Something bad happened during the management of the client upload request...\n\n");
                exit(1);
            }
            else printf("I managed an upload request and all was good!\n\n");
        }


        // **************** SHARE REQUEST MANAGER ****************
        else if (strcmp(bufferSupp1, SHARE_REQUEST) == 0)
        {
            printf("\nA share request has came up...\n\n");
            // SHARE MANAGER: SERVER SIDE
                            
            ret = shareServer(sd, buffer);
            if (ret == -1)
            {
                printf("Something bad happened during the management of the client share request...\n\n");
                exit(1);
            }
            else printf("I managed a share request and all was good!\n\n");
        }

        else printf("Unknown type of request by the Client...\n");  
    }
    close(sd);

    return 1;
}


int logoutServer(int sd, char* rec_mex, int* nonce, unsigned char* session_key2)
{
    unsigned int digest_len;
    int ret;
    unsigned int msg_to_hash_len;

    size_t offset;

    char* temp;
    unsigned char* bufferSupp1;
    unsigned char* bufferSupp2;
    unsigned char* bufferSupp3;
    unsigned char* msg_to_hash;
    unsigned char* digest; 


    /* ---- Parse the first client message (request + hash + iv) ---- */
    temp = (char*) malloc(sizeof(char)*LEN_SIZE);
    if (!temp) exit_with_failure("Malloc temp failed", 1);   
    bufferSupp1 = (unsigned char*) malloc(sizeof(unsigned char)*strlen(LOGOUT_REQUEST));
    if (!bufferSupp1) exit_with_failure("Malloc bufferSupp1 failed", 1);
    bufferSupp2 = (unsigned char*) malloc(sizeof(unsigned char)*HASH_LEN);   
    if (!bufferSupp2) exit_with_failure("Malloc bufferSupp2 failed", 1);
    bufferSupp3 = (unsigned char*) malloc(sizeof(unsigned char)*IV_LEN);   
    if (!bufferSupp3) exit_with_failure("Malloc bufferSupp3 failed", 1);

    offset = str_ssplit((unsigned char*) rec_mex, DELIM);
    memcpy(bufferSupp1, rec_mex, strlen(LOGOUT_REQUEST)); // logout req.
    if (offset != (unsigned int)strlen(LOGOUT_REQUEST)) exit_with_failure("Incorrect logout req. length", 0);
    offset += BLANK_SPACE;

    memcpy(bufferSupp2, &*((unsigned char*) rec_mex+offset), HASH_LEN); // hash
    offset += HASH_LEN+BLANK_SPACE;
    
    memcpy(bufferSupp3, &*((unsigned char*) rec_mex+offset), IV_LEN); // iv


    // Check hash correctness
    msg_to_hash_len = strlen(LOGOUT_REQUEST)+BLANK_SPACE+IV_LEN+BLANK_SPACE+LEN_SIZE;
    msg_to_hash = (unsigned char*) malloc(sizeof(unsigned char)*msg_to_hash_len);
    if (!msg_to_hash) exit_with_failure("Malloc msg_to_hash failed", 1);
    
    memcpy(msg_to_hash, LOGOUT_REQUEST, strlen(LOGOUT_REQUEST)); // logout req.
    memcpy(&*(msg_to_hash+strlen(LOGOUT_REQUEST)), " ", BLANK_SPACE);
    memcpy(&*(msg_to_hash+strlen(LOGOUT_REQUEST)+BLANK_SPACE), bufferSupp3, IV_LEN); // iv
    memcpy(&*(msg_to_hash+strlen(LOGOUT_REQUEST)+BLANK_SPACE+IV_LEN), " ", BLANK_SPACE);
    sprintf(temp, "%d", *nonce);
    memcpy(&*(msg_to_hash+strlen(LOGOUT_REQUEST)+BLANK_SPACE+IV_LEN+BLANK_SPACE), temp, LEN_SIZE); // nonce

    digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len);   
    ret = CRYPTO_memcmp(digest, bufferSupp2, HASH_LEN);
    if (ret == -1) exit_with_failure("Wrong logout request hash", 0);
    *nonce = *nonce+1;

    free(bufferSupp1);
    free(bufferSupp2);
    free(bufferSupp3);
    free(temp);
    free(digest);
    free(msg_to_hash);

    return 1;

}

int listServer(int sd, char* rec_mex)
{
    //char bufferSupp1[BUF_LEN];

    char *buffer_mex_field[2]; //buffer_mex_field[0] ---> contains the request type, buffer_mex_field[1] ---> contains the username
    char buffer_response[BUF_LEN+10]; // I'm creating a buffer a little longer to have the capacity to contain buffSupp1. We could fix the problem later, putting the end_string character at the end of the list
    DIR* d;
    struct dirent *files;
    int ret;
    printf("I received a message from a client saying: %s\n\n", rec_mex);

    // HERE WE NEED TO DECRYPT AND CHECK IF THE MESSAGE IS OKAY

    //memset(bufferSupp1, 0, BUF_LEN);
    //memset(bufferSupp2, 0, BUF_LEN);

    rec_buffer_sanitization(rec_mex, buffer_mex_field);

    //sscanf(rec_mex, "%s %s", bufferSupp1, bufferSupp2); //in bufferSupp2 we have the username
    
    printf("The username is %s, the length of the username is %li\n\n", buffer_mex_field[1], strlen(buffer_mex_field[1]));

    if (chdir(MAIN_FOLDER_SERVER) == -1)
	{
        printf("I'm having some problem with the change directory to the main folder of the software...\n\n");
	}

    ret = chdir(buffer_mex_field[1]);
    if (ret == -1)
    {
        printf("Error: username doesn't exists...\n");
        exit(1);
    }

    // WE ARE ASSUMING THAT WE DON'T NEED MORE THAN ONE MESSAGE TO LIST THE FILES
    d = opendir(".");
    memset(buffer_response, 0, strlen(buffer_response));
    strcat(buffer_response, LIST_RESPONSE);
    strcat(buffer_response, " ");
    if(d)
    {
        while((files = readdir(d)) != NULL) //the folder we are checking has the same name of the username. So we take the list from that name
        {
            strcat(buffer_response, files->d_name);
            strcat(buffer_response, " ");
        }
    }
    

    //memset(bufferSupp2, 0, strlen(bufferSupp2));
    //sprintf(bufferSupp2, "%s %s", LIST_RESPONSE, bufferSupp1);

    printf("I'm sendinf %s to the client...\n\n", buffer_response);
    // HERE WE SHOULD REMEMBER TO ENCRYPT THE BUFFER PROPERLY

    ret = send(sd, buffer_response, strlen(buffer_response), 0);
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
    char bufferSupp1[0][BUF_LEN];
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
    chdir(MAIN_FOLDER_SERVER);;
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

    // ENCRYPT THE MESSAGE SENT

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
    char username[MAX_LEN_USERNAME];
    char filename[MAX_LEN_FILENAME];
    struct stat st;
    int i, j, nchunk, ret, start_payload, rest;
    FILE* fd;

    memset(filename, 0, strlen(filename));
    memset(username, 0, strlen(username));
    memset(bufferSupp1, 0, strlen(bufferSupp1));

    sscanf(rec_mex, "%s %s %s", bufferSupp1, username, filename); // bufferSupp2 = username, bufferSupp3 = filename
    chdir(MAIN_FOLDER_SERVER);

    // SANITIZATION OF THE USERNAME AND THE FILENAME

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
    printf("The size of the file is %ld\n\n", st.st_size);
    nchunk = (st.st_size/CHUNK_SIZE)+1;
    rest = st.st_size - (nchunk-1)*CHUNK_SIZE; // This is the number of bits of the final chunk

    printf("The number of chunk is %i\n\n", nchunk);    

    memset(bufferSupp1, 0, strlen(bufferSupp1));
    memset(bufferSupp2, 0, strlen(bufferSupp2));
    memset(bufferSupp3, 0, strlen(bufferSupp3));
    sprintf(bufferSupp1, "%s %d %d", DOWNLOAD_ACCEPTED, nchunk, rest); //Format of the message sent is: type_mex n_chunk
    printf("I'm sending %s\n\n", bufferSupp1);
    //ENCRYPT THE MESSAGE SENT
    ret = send(sd, bufferSupp1, BUF_LEN, 0);
    if (ret == -1)
    {
        printf("Send operation gone bad\n");
        // Change this later to manage properly the session
        exit(1);
    }

    printf("I'm starting to send chunks\n");
    for (i = 0; i < nchunk; i++)
    {
        memset(payload, 0, strlen(payload));
        if (i == nchunk-1)
        {
            for (j = 0; j < rest; j++)
            {
                if (fgets(payload+j, 2, fd) == NULL)
                {
                    payload[j] = '\0';
                    printf("File over!");
                    break;
                }
            }
        }
        else
        {
            for (j = 0; j < CHUNK_SIZE; j++)
            {
                if (fgets(payload+j, 2, fd) == NULL)
                {
                    payload[j] = '\0';
                    printf("File over!");
                    break;
                }
            }
        }
        sprintf(bufferSupp1, "%s %s ", DOWNLOAD_CHUNK, filename); //Format of the message sent is: type_mex filename payload
        start_payload = MEX_TYPE_LEN + strlen(filename) + 2;
	if (i == nchunk-1) for (j = 0; j < rest; j++) bufferSupp1[start_payload+j] = payload[j];
	else for (j = 0; j < CHUNK_SIZE; j++) bufferSupp1[start_payload+j] = payload[j];
        
        printf("We are sending %s\n\n", bufferSupp1);

        //ENCRYPT THE MESSAGE SENT

        ret = send(sd, bufferSupp1, BUF_LEN, 0);
        if (ret == -1)
        {
            printf("Send operation gone bad\n");
            // Change this later to manage properly the session
            exit(1);
        }
    }
    memset(buffer, 0, strlen(buffer));
    ret = recv(sd, buffer, BUF_LEN, 0);
    if (ret == -1)
    {
        printf("Send operation gone bad!\n\n");
        exit(1);
    }
    printf("I'm receiving %s\n\n", buffer);

    // DECRYPT THE BUFFER

    sscanf(buffer, "%s %s %s", bufferSupp1, bufferSupp2, bufferSupp3);
    if (!(strcmp(bufferSupp1, DOWNLOAD_FINISHED)==0) || !(strcmp(bufferSupp2, username)==0) || !(strcmp(bufferSupp3, filename)==0))
    {
        printf("Error in the last message sent: message of end download\n\n");
        return -1;
    }
    printf("We have completed successfully the donwload operation!\n\n");
    return 1;
   
}


int uploadServer(int sd, char* rec_mex)
{
    int ret, nchunk, i, j, k, r, position, rest;
    char buffer[BUF_LEN];
    FILE* f1;
    char bufferSupp1[BUF_LEN];
    char bufferSupp2[BUF_LEN];
    char bufferSupp3[BUF_LEN];
    char filename[MAX_LEN_FILENAME];
    char username[MAX_LEN_USERNAME];

    printf("I received %s\n\n", rec_mex);
    sscanf(rec_mex, "%s %s %s %s %s", bufferSupp1, username, filename, bufferSupp2, bufferSupp3);
    printf("The number of chunk of the file is %i", nchunk); // ??

    rest = atoi(bufferSupp3);
    nchunk = atoi(bufferSupp2);

    // SANITIZATION OF THE USERNAME AND THE FILENAME

    if (chdir(MAIN_FOLDER_SERVER) == -1)
	{
		printf("I'm having some problem with the change directory to the main folder of the software...\n\n");
        return -1;
	}
    if (chdir(username) == -1)
    {
        printf("I'm having some problem with the change directory to the main folder of the software...\n\n");
        return -1;
    }
    f1 = fopen(filename, "r");
    if (f1 == NULL) 
    {
        printf("Starting the upload...\n\n");
        memset(buffer, 0, strlen(buffer));
        memset(bufferSupp2, 0, strlen(bufferSupp2));
        memset(bufferSupp1, 0, strlen(bufferSupp1));
        sprintf(buffer, "%s %s %s", UPLOAD_ACCEPTED, username, filename);
        printf("I'm sending %s\n\n", buffer);
        ret = send(sd, buffer, strlen(buffer), 0);
        if (ret == -1)
        {
          //  print("Some problem with send operation...\n\n");
            return -1;
        }
    }
    else
    {
        printf("File with this name already exists: refusing upload operation...\n\n");
        fclose(f1);
        printf("Filename already exists. Download request over...\n\n");
        memset(buffer, 0, strlen(buffer));
        memset(bufferSupp2, 0, strlen(bufferSupp2));
        memset(bufferSupp1, 0, strlen(bufferSupp1));
        sprintf(buffer, "%s %s %s", UPLOAD_DENIED, username, filename);
        printf("I'm sending %s\n\n", buffer);
        ret = send(sd, buffer, strlen(buffer), 0);
        if (ret == -1) printf("Had some problem with the send operation...\n\n");
        return -1;
    }


   f1 = fopen(filename, "w");
    for (i = 0; i < nchunk; i++)
    {
        printf("We are receiving the chunk number %i...\n\n", i);
        memset(buffer, 0, strlen(buffer));
        // I'm receveing a message with this format: download_chunk n_chunk payload
        ret = recv(sd, buffer, BUF_LEN, 0);
        if (ret == -1)
        {
            printf("Receive operation gone bad\n");
            // Change this later to manage properly the session
            exit(1);
        }
        //sscanf(buffer, "%s %s %s", bufferSupp1, bufferSupp2, bufferSupp3); // we receive: donwload_chunk filename payload
        memset(bufferSupp1, 0, strlen(bufferSupp1));
        memset(bufferSupp2, 0, strlen(bufferSupp2));
        memset(bufferSupp3, 0, strlen(bufferSupp3));
        sscanf(buffer, "%s %s", bufferSupp1, bufferSupp2);
        k = strlen(bufferSupp1);
        r = strlen(bufferSupp2);
        printf("In bufferSupp1 we have %s and the size of the field is %i, the bufferSupp2 contains %s and the size is %i\n\n", bufferSupp1, k, bufferSupp2, r);
        position = strlen(bufferSupp1) + strlen(bufferSupp2) + 2;
        printf("The position of the buffer where we start to take the payload is %i\n\n", position);
	if (i == nchunk-1)
	{
	     for (j = 0; j < rest; j++)
             {
                 bufferSupp3[j] = buffer[position+j];
             }
	}
	else
	{
	     for (j = 0; j < CHUNK_SIZE; j++)
             {
                 bufferSupp3[j] = buffer[position+j];
             }
	}
        

        printf("The payload received is %s\n\n", bufferSupp3);
        
        
        // Now take the bufferSupp3 and append it to the file. When the loop is over we close the file and we got what we neededs
        printf("Now we append %s to the file...\n\n", bufferSupp3);
	if (i == nchunk-1)
	{
	      for (j = 0; j < rest; j++)
              {
                 fprintf(f1, "%c", bufferSupp3[j]);
              }
	}
	else
	{
	      for (j = 0; j < CHUNK_SIZE; j++)
              {
                 fprintf(f1, "%c", bufferSupp3[j]);
              }
	}
        //fwrite(bufferSupp3, 1, strlen(bufferSupp3), f1); //I append the payload to the file
        memset(bufferSupp1, 0, strlen(bufferSupp1));
        memset(bufferSupp2, 0, strlen(bufferSupp2));
        memset(bufferSupp3, 0, strlen(bufferSupp3));
    }
    fclose(f1);
    memset(buffer, 0, strlen(buffer));
    sprintf(buffer, "%s %s %s", DOWNLOAD_FINISHED, username, filename);
    printf("I'm sending %s\n\n", buffer);
    ret = send(sd, buffer, BUF_LEN, 0);
    if (ret == -1)
    {
        printf("Send operation gone bad\n");
        // Change this later to manage properly the session
        exit(1);
    }
    printf("Download completed!\n\n");
    return 1;
}

int shareServer(int sd, char* rec_mex)
{
    int sock, ret, i, receiverport;
    char buffer[BUF_LEN];
    char ch;
    FILE* f1;
    FILE* f2;
    struct sockaddr_in rec_addr;
    socklen_t addrlen;
    char bufferSupp1[BUF_LEN];
    char bufferSupp2[BUF_LEN];
    char bufferSupp3[BUF_LEN];
    char filename[MAX_LEN_FILENAME];
    char sharername[MAX_LEN_USERNAME];
    char receivername[MAX_LEN_USERNAME];

    printf("I received %s\n\n", rec_mex);
    sscanf(rec_mex, "%s %s %s %s", bufferSupp1, sharername, receivername, filename);
    printf("The sharername is %s\n", sharername);
    printf("The receivernane is %s\n", receivername);
    printf("The filename is %s\n", filename);
    
    // SANITIZATION OF FILENAME, USERNAMES
    
    if (chdir(MAIN_FOLDER_SERVER) == -1)
	{
		printf("I'm having some problem with the change directory to the main folder of the software...\n\n");
        return -1;
	}
    if (chdir(sharername) == -1)
    {
        printf("I'm having some problem with the change directory to the main folder of the software...\n\n");
        return -1;
    }
    printf("The filename is %s\n\n", filename);
    f1 = fopen(filename, "r");
    if (f1 == NULL)
    {
        printf("The sharer doesn't have any file called %s\n\n", filename);
        memset(buffer, 0, strlen(buffer));
        sprintf(buffer, "%s %s %s %s", SHARE_DENIED, sharername, filename, receivername);
        ret = send(sd, buffer, strlen(buffer), 0);
        if (ret == -1)
        {
            printf("Something bad happened with the send function...\n\n");
            return -1;
        }
        return 1;
    }
    fclose(f1);

    // We should ask to the receiver whether it wants to allow the share operation
    // Create a folder where you store all the information about the listeners of the users logged

    if (chdir(INFO_FOLDER_SERVER) == -1)
    {
		printf("I'm having some problem with the change directory to the info folder of the software...\n\n");
        return -1;
	}
    memset(buffer, 0, strlen(buffer));
    sprintf(buffer, "%s.txt", receivername);
    if (!(f1 = fopen(buffer, "r")))
    {
        printf("The receiver %s is not online... Try it later\n\n", receivername);
        memset(buffer, 0, strlen(buffer));
        sprintf(buffer, "%s %s %s %s", SHARE_DENIED, sharername, filename, receivername);
        ret = send(sd, buffer, strlen(buffer), 0);
        if (ret == -1)
        {
            printf("Something bad happened with the send function...\n\n");
            return -1;
        }
        return 1;
    }
    memset(buffer, 0, strlen(buffer));
    ret = fread(buffer, PORT_SIZE, 1, f1);
    if (ret == -1)
    {
        printf("Problem during the reading of the file to downlaod... \n\n");
        return -1;
    }
    receiverport = atoi(buffer);

    memset(&rec_addr, 0, sizeof(rec_addr));
	rec_addr.sin_family = AF_INET;
	rec_addr.sin_port = htons(receiverport);
	inet_pton(AF_INET, LOCALHOST, &rec_addr.sin_addr);

    sock = createSocket();
    if (connect(sock, (struct sockaddr*)&rec_addr, sizeof(rec_addr)) < 0) 
    {
        printf("\nConnection Failed \n");
        exit(1);
    }

    memset(buffer, 0, strlen(buffer));
    sprintf(buffer, "%s %s %s", SHARE_PERMISSION, sharername, filename);
    ret = send(sock, buffer, strlen(buffer), 0);
    if (ret == -1)
    {
        printf("Something bad happened with the send function...\n\n");
        return -1;
    }
    memset(buffer, 0, strlen(buffer));
    memset(bufferSupp1, 0, strlen(bufferSupp1));
    memset(bufferSupp2, 0, strlen(bufferSupp2));
    memset(bufferSupp3, 0, strlen(bufferSupp3));
    ret = recv(sock, buffer, BUF_LEN, 0);
    if (ret == -1)
    {
        printf("Something bad happened with the receive function...\n\n");
        return -1;
    }
    sscanf(buffer, "%s %s %s", bufferSupp1, bufferSupp2, bufferSupp3);
    if (strcmp(bufferSupp1, SHARE_ACCEPTED)==0)
    {
        // COPY THE FILE IN THE FOLDER OF THE REICEIVER
        printf("The receiver is allowing the share operation...\n\n");

        memset(buffer, 0, strlen(buffer));
        strcat(buffer, "cp "); 
        strcat(buffer, MAIN_FOLDER_SERVER); 
        strcat(buffer, "/"); 
        strcat(buffer, sharername); 
        strcat(buffer, "/"); 
        strcat(buffer, filename); 
        strcat(buffer, " "); 
        strcat(buffer, MAIN_FOLDER_SERVER); 
        strcat(buffer, "/"); 
        strcat(buffer, receivername); 
        system(buffer); 

        memset(buffer, 0, strlen(buffer));
        sprintf(buffer, "%s %s %s %s", SHARE_ACCEPTED, sharername, filename, receivername);
        ret = send(sd, buffer, strlen(buffer), 0);
        if (ret == -1)
        {
            printf("Something bad happened with the send function...\n\n");
            return -1;
        }
        return 1;
    }


    if (strcmp(bufferSupp1, SHARE_DENIED)==0)
    {
        // THE SHARE OPERATION IS NOT ALLOWED, SEND A MESSAGE TO THE SHARER LETTING HIM KNOW IT
        printf("The receiver is denying the share operation...\n\n");
        memset(buffer, 0, strlen(buffer));
        sprintf(buffer, "%s %s %s %s", SHARE_DENIED, sharername, filename, receivername);
        ret = send(sd, buffer, strlen(buffer), 0);
        if (ret == -1)
        {
            printf("Something bad happened with the send function...\n\n");
            return -1;
        }
        return 1;
    }

    return -1;
}
