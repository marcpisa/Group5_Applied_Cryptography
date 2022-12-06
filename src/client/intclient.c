#include "intclient.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>

int createSocket()
{
    int sock;
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
    {
        printf("\n Socket creation error\n");
        return -1;
    }
    return sock;
}


int loginClient(int *sock, unsigned char** session_key1, unsigned char** session_key2, char* username, struct sockaddr_in srv_addr, int port, X509_STORE* ca_store) 
{
    /*********************
     * VARIABLES
     ********************/

    // Buffers
    int msg_len;
    unsigned char* p;
    unsigned char* buffer;
    char n_buff[LEN_SIZE];
    char port_buff[PORT_SIZE];
    unsigned char pk_buff[DH_PUBKEY_SIZE];
    unsigned char sgn_buff[SIGN_LEN];
    
    // Paths
    char path_pubkey[15+MAX_LEN_USERNAME+15];
    char path_rsa_key[15+MAX_LEN_USERNAME+9];

    // Digital signature
    unsigned char* exp_digsig;
    unsigned char* signature;
    int expected_len;
    unsigned int signature_len;

    size_t K_len;


    // Diffie-Hellman
    EVP_PKEY* my_prvkey = NULL;
    EVP_PKEY* peer_pubkey;
    unsigned char* K;
    unsigned char* pubkey_byte = NULL;
    int pubkey_len = 0;
    
    // Certificate
    X509* serv_cert = NULL;
    EVP_PKEY* pub_rsa_key_serv;
    int cert_len;

    int encr_len;
    int msg_to_hash_len;
    unsigned char* encr_msg;
    unsigned char* iv;
    unsigned char* msg_to_hash;
    unsigned char* digest;

    int ret;
    
    unsigned char* cert_buff;
    /*********************
     * END VARIABLES
     ********************/

    // Creation of socket
    *sock = createSocket();
    if (connect(*sock, (struct sockaddr*)&srv_addr, sizeof(srv_addr)) < 0) exit_with_failure("Connect failed", 1);

    // Compose the path for the current user
    memcpy(path_pubkey, "../../database/\0", 15+1);
    strncat(path_pubkey, username, strlen(username));
    strncat(path_pubkey, "/dh_pubkey.pem\0", 15);

    memcpy(path_rsa_key, "../../database/\0", 15+1);
    strncat(path_rsa_key, username, strlen(username));
    strncat(path_rsa_key, "/rsa.pem\0", 9);

    // Generate DH asymmetric key(s)
    pubkey_byte = gen_dh_keys(path_pubkey, &my_prvkey, &pubkey_len);   
    //printf("The pubkey len is %i\n\n", pubkey_len);
    if (pubkey_len != DH_PUBKEY_SIZE) exit_with_failure("Wrong pubkey len", 0);




    /* ---- 1st message: login request message + username + DH pubkey ---- */
    msg_len = TYPE_LEN+strlen(username)+pubkey_len+(BLANK_SPACE*2);
    buffer = (unsigned char*) malloc(msg_len*sizeof(unsigned char));
    if (!buffer) exit_with_failure("Malloc buffer failed", 1);

    p = buffer; 
    memcpy(p, LOGIN_REQUEST, strlen(LOGIN_REQUEST));
    p += strlen(LOGIN_REQUEST);
    memcpy(p, " ", BLANK_SPACE);
    p += BLANK_SPACE;
    memcpy(p, username, strlen(username));
    p += strlen(username);
    memcpy(p, " ", BLANK_SPACE);
    p += BLANK_SPACE;
    memcpy(p, (char*)pubkey_byte, pubkey_len);

    ret = send(*sock, buffer, msg_len, 0);
    
    free(buffer);
    if (ret == -1) 
    {  
        free(pubkey_byte);
        EVP_PKEY_free(my_prvkey);
        printf("Send failed.\n");
        return -1;
    } 
    else printf("Login request sent to server.\n");    




    /* ---- Obtain and parse response server (DH pubkey, signature, len. cert. and cert.) ----*/
    // Receive the message
    buffer = (unsigned char*) malloc(sizeof(unsigned char)*BUF_LEN);
    if (!buffer) exit_with_failure("Malloc buffer failed", 1);

    ret = recv(*sock, buffer, BUF_LEN, 0);
    if (ret == -1) 
    {
        free_n(2, buffer, pubkey_byte);
        EVP_PKEY_free(my_prvkey);
        printf("Receive failed.\n");
        return -1;
    } 
    //else printf("#2 Server response received.\n");
    msg_len = ret;


    // Parse the server response
    p = buffer; // set the pointer
    memset(pk_buff, 0, DH_PUBKEY_SIZE);
    memcpy(pk_buff, p, pubkey_len); // g^b
    p += pubkey_len+BLANK_SPACE; // move pointer

    memset(sgn_buff, 0, SIGN_LEN);
    memcpy(sgn_buff, p, SIGN_LEN); // dig.sig.
    p += SIGN_LEN+BLANK_SPACE;

    memset(n_buff, 0, LEN_SIZE);
    memcpy(n_buff, p, LEN_SIZE); // len cert
    cert_len = atoi(n_buff);
    p += LEN_SIZE+BLANK_SPACE;

    if (cert_len <= 0 || cert_len > (msg_len-LEN_SIZE-DH_PUBKEY_SIZE-SIGN_LEN)) 
    {
        free_n(2, buffer, pubkey_byte);
        EVP_PKEY_free(my_prvkey);
        printf("Incorrect certificate length.\n");
        return -1;
    }
    
    cert_buff = (unsigned char*) malloc(cert_len*sizeof(unsigned char));
    if (!cert_buff) exit_with_failure("cert_buff malloc failed", 1);
    memcpy(cert_buff, p, cert_len); // cert


    // Derive the established key and obtain the session keys
    peer_pubkey = pubkey_to_PKEY(pk_buff, pubkey_len);
    K = key_derivation(my_prvkey, peer_pubkey, &K_len);
    issue_session_keys(K, K_len, session_key1, session_key2);
   
    // Obtain the (verified) RSA public key
    pub_rsa_key_serv = get_ver_server_pubkey(cert_buff, cert_len, ca_store);
    

    // Generate the digital signature expected and verify it
    expected_len = (pubkey_len*2)+BLANK_SPACE;
    exp_digsig = (unsigned char*) malloc(expected_len*sizeof(unsigned char));
    if (!exp_digsig) exit_with_failure("Malloc exp_digsig failed", 1);

    p = exp_digsig;
    memcpy(p, pubkey_byte, pubkey_len);
    p += pubkey_len;
    memcpy(p, " ", BLANK_SPACE);
    p += BLANK_SPACE;
    memcpy(p, pk_buff, pubkey_len);

    ret = verify_signature(exp_digsig, expected_len, sgn_buff, SIGN_LEN, pub_rsa_key_serv);
      

    free_n(3, buffer, pubkey_byte, cert_buff);
    X509_free(serv_cert);
    EVP_PKEY_free(pub_rsa_key_serv);
    EVP_PKEY_free(my_prvkey);
    EVP_PKEY_free(peer_pubkey);
    
    if (ret != 1) 
    {
        free_n(2, K, exp_digsig);
        printf("Signature verification failed.\n");
        return -1;    
    }
    



    /* ---- Generate last message for the server (digital signature) ---- */
    msg_len = SIGN_LEN;
    buffer = (unsigned char*) malloc(BUF_LEN*sizeof(unsigned char));
    if (!buffer) exit_with_failure("Malloc buffer failed", 1);

    // Generate digital signature
    signature = sign_msg(path_rsa_key, exp_digsig, expected_len, &signature_len, 0);

    // Compose the message
    memcpy(buffer, signature, SIGN_LEN); // dig. sig.

    ret = send(*sock, buffer, BUF_LEN, 0); 

    free_n(4, K, exp_digsig, signature, buffer);
    if (ret == -1)
    {
        printf("Send failed.\n");
        return -1;
    } 
    //else printf("#3 Last key establishment message sent to the server.\n");
 




    /* ---- Send port to server ---- */
    // Generate iv
    iv = (unsigned char*) malloc(sizeof(unsigned char)*IV_LEN);
    if (!iv) exit_with_failure("Malloc iv failed", 1);
    ret = RAND_poll(); // Seed OpenSSL PRNG
    if (ret != 1) exit_with_failure("RAND_poll failed\n", 0);
    ret = RAND_bytes((unsigned char*)&iv[0], IV_LEN);
    if (ret != 1) exit_with_failure("RAND_bytes failed\n", 0);


    // Encrypt port and hash it
    memset(port_buff, 0, PORT_SIZE);
    sprintf(port_buff, "%d", port);
    encrypt_AES_128_CBC(&encr_msg, &encr_len, (unsigned char*) port_buff, PORT_SIZE, iv, *session_key1);

    msg_to_hash_len = concat_5(&msg_to_hash, encr_msg, encr_len, iv, IV_LEN, NULL, -1, NULL, -1, NULL, -1);
    if (msg_to_hash_len == -1)
    {
        free_n(3, iv , encr_msg, msg_to_hash);
        printf("Problem building the hash...\n");
        return -1;
    }

    digest = hmac_sha256(*session_key2, 16, msg_to_hash, msg_to_hash_len, NULL);    
    free(msg_to_hash);


    // Build the message
    msg_len = build_msg(&buffer, SEND_PORT, encr_len, encr_msg, digest, iv);
    if (msg_len == -1)
    {
        free_n(2, iv , encr_msg);
        printf("Problem building the message...\n");
        return -1;
    }

    ret = send(*sock, buffer, BUF_LEN, 0); 
    
    free_n(4, buffer, digest, iv, encr_msg);
    if (ret == -1) 
    {
        printf("Send failed.\n");
        return -1;   
    }
    //else printf("4# Port sent to the server.\n");

    return 1;
}

int logoutClient(int sock, unsigned int* nonce, unsigned char* session_key2)
{
    unsigned int digest_len;
    int ret;
    int msg_len;
    int msg_to_hash_len;

    char* temp;
    unsigned char* buffer;
    unsigned char* msg_to_hash;
    unsigned char* digest;


    /* ---- Create the first message (request + hash + iv) ---- */
    // Generating the hash of the request and the nonce
    temp = (char*) malloc(sizeof(char)*LEN_SIZE);
    if (!temp) exit_with_failure("Malloc temp failed", 1);

    sprintf(temp, "%d", *nonce);
    msg_to_hash_len = build_msg_2(&msg_to_hash, LOGOUT_REQUEST, strlen(LOGOUT_REQUEST),\
                                                temp, LEN_SIZE);
    if(msg_to_hash_len == -1) exit_with_failure("Something bad happened building the hash...", 0);

    digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len);    
    
    // Compose the message
    msg_len = build_msg_2(&buffer, LOGOUT_REQUEST, strlen(LOGOUT_REQUEST),\
                                   digest, HASH_LEN);
    if(msg_len== -1) exit_with_failure("Something bad happened building the message...", 0);

    printf("Sending Logout Request to the server\n");
    ret = send(sock, buffer, BUF_LEN, 0); 
    
    free_n(4, temp, buffer, msg_to_hash, digest);
    
    if (ret == -1) 
    {
        printf("Send failed.\n");
        return -1;   
    }

    return 1;
}

int listClient(int sock, unsigned char* session_key1, unsigned char* session_key2, unsigned int* nonce)
{
    unsigned char* iv;
    int index;
    int num_file;
    int tot_num_file;

    unsigned char* plaintext;
    int encr_len;
    unsigned int plain_len;
    
    unsigned char* msg_to_hash;
    unsigned char* digest;
    unsigned int digest_len;
    int msg_to_hash_len;
    
    size_t old_offset;

    int ret;
    int msg_len;
    char* temp;
    char* temp2;
    char *token;
    char** new_file_list;
    unsigned char* buffer;
    unsigned char* bufferSupp1;
    unsigned char* bufferSupp2;
    unsigned char* bufferSupp3;
    char** file_list;



    /* ---- Create the first message (req., hash(req, iv, nonce), iv) ---- */
    // Create the hash
    temp = (char*) malloc(sizeof(char)*LEN_SIZE);
    if (!temp) exit_with_failure("Malloc temp failed", 1);

    sprintf(temp, "%d", *nonce);
    msg_to_hash_len = build_msg_2(&msg_to_hash, LIST_REQUEST, strlen(LIST_REQUEST),\
                                                temp, LEN_SIZE);
    if (msg_to_hash_len == -1) exit_with_failure("Error during the building of the message", 1);
    
    digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len);   

    // Compose the message
    msg_len = build_msg_2(&buffer, LIST_REQUEST, strlen(LIST_REQUEST),
                                   digest, HASH_LEN);
    if (msg_len == -1) exit_with_failure("Error during the building of the message", 1);

    //printf("Sending List Request to Server.\n\n");
    ret = send(sock, buffer, BUF_LEN, 0); 

    free_4(temp, buffer, msg_to_hash, digest);

    if (ret == -1)
    {
        printf("Send failed.\n");
        return -1;
    } 
    
    *nonce += 1;




    /* ---- Parse the response (num_file, len. encr., encr. list, hash(num_file, encr. list, iv, nonce), iv) ---- */
    tot_num_file = 0;
    num_file = 0;
    index = -1;
    while (num_file != -1) 
    {
        buffer = (unsigned char*) malloc(sizeof(unsigned char)*BUF_LEN);
        if (!buffer) exit_with_failure("Malloc buffer failed", 1);

        ret = recv(sock, buffer, BUF_LEN, 0);
        if (ret == -1) 
        {
            free(buffer);
            printf("Receive failed.\n");
            return -1;
        }

        // Check if something failed server-side
        bufferSupp1 = (unsigned char*) malloc((strlen(LIST_DENIED)+1)*sizeof(unsigned char));
        if (!bufferSupp1) exit_with_failure("Malloc bufferSupp1 failed", 1); 

        memcpy(bufferSupp1, buffer, strlen(LIST_DENIED));
        memcpy(&*(bufferSupp1+strlen(LIST_DENIED)), "\0", 1);

        if (strcmp((char*) bufferSupp1, LIST_DENIED) == 0)
        {
            ret = check_reqden_msg(LIST_DENIED, buffer, *nonce, session_key1, session_key2);
            free_2(bufferSupp1, buffer);
            
            if (ret == -1) printf("Hash of the message not correct.\n");
            else 
            {
                printf("List denied.\n"); 
                *nonce += 1;
            }

            return 1;
        }

        free(bufferSupp1);


        // No operation denied, let's obtain the list
        temp = (char*) malloc(LEN_SIZE*sizeof(char));
        if (!temp) exit_with_failure("Malloc temp failed", 1);
        temp2 = (char*) malloc(LEN_SIZE*sizeof(char));
        if (!temp2) exit_with_failure("Malloc temp2 failed", 1);
        bufferSupp1 = (unsigned char*) malloc(2*CHUNK_SIZE*sizeof(unsigned char));
        if (!bufferSupp1) exit_with_failure("Malloc bufferSupp1 failed", 1);
        bufferSupp2 = (unsigned char*) malloc(HASH_LEN*sizeof(unsigned char));
        if (!bufferSupp2) exit_with_failure("Malloc bufferSupp2 failed", 1);
        iv = (unsigned char*) malloc(sizeof(unsigned char)*IV_LEN);
        if (!iv) exit_with_failure("Malloc iv failed", 1);

        // Parsing
        memcpy(temp, buffer, LEN_SIZE); // num_file
        num_file = atoi(temp);
        old_offset = LEN_SIZE+BLANK_SPACE;
        //if (num_file != 0) printf("Received chunk of filenames...\n");

        memcpy(temp2, &*(buffer+old_offset), LEN_SIZE); // encr. len.
        encr_len = atoi(temp2);
        old_offset += LEN_SIZE+BLANK_SPACE;

        memcpy(bufferSupp1, &*(buffer+old_offset), encr_len); // encr. list
        old_offset += encr_len+BLANK_SPACE;

        memcpy(bufferSupp2, &*(buffer+old_offset), HASH_LEN); // hash
        old_offset += HASH_LEN+BLANK_SPACE;

        memcpy(iv, &*(buffer+old_offset), IV_LEN); // iv

        bufferSupp3 = (unsigned char*)malloc(sizeof(unsigned char)*LEN_SIZE);
        if (!bufferSupp3) exit_with_failure("Malloc bufferSupp3 failed", 1);
        sprintf((char*)bufferSupp3, "%u", *nonce);
        
        // Check hash
        msg_to_hash_len = build_msg_4(&msg_to_hash, temp, LEN_SIZE,\
                                                    bufferSupp1, encr_len,\
                                                    iv, IV_LEN,\
                                                    bufferSupp3, LEN_SIZE);

        if (msg_to_hash_len == -1) exit_with_failure("Something bad happened building the hash...", 0);

        digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len); 
        ret = CRYPTO_memcmp(digest, bufferSupp2, HASH_LEN);

        free_3(bufferSupp3, temp, temp2);

        if (ret != 0)
        {
            operation_denied(sock, "Wrong hash", LIST_DENIED, session_key1, session_key2, nonce);
            printf("MAC received is not correct\n");
            free_6(buffer, digest, bufferSupp1, bufferSupp2, iv, msg_to_hash);
            return 1;
        }
        else if (num_file < 0 || num_file >= CHUNK_SIZE)
        {
            operation_denied(sock, "Incorrect num_file", LIST_DENIED, session_key1, session_key2, nonce);
            printf("Number of the file is too high...\n");
            free_6(buffer, digest, bufferSupp1, bufferSupp2, iv, msg_to_hash);
            return 1;
        }
        *nonce += 1;

        // Decrypt list
        decrypt_AES_128_CBC(&plaintext, &plain_len, bufferSupp1, encr_len, iv, session_key1);

        // Fill list array
        if ((tot_num_file == 0 && num_file != 0) || (num_file != 0))
        {
            if (tot_num_file == 0)
            {
                tot_num_file += num_file;
                file_list = (char**) malloc(tot_num_file*sizeof(char*));
                if (!file_list) exit_with_failure("Malloc file_list failed", 1);
            }
            else // File list is already been created, need to be expanded
            {
                // Extend the file list reallocating memory
                tot_num_file += num_file;
                new_file_list = realloc(file_list, tot_num_file*sizeof(char*));
                if (!new_file_list) exit_with_failure("Realloc failed", 1);
                else file_list = new_file_list;
            }
            
            token = strtok((char*) plaintext, " "); // BE CAREFUL THE LIST SERVER SIDE SHOULD HAVE THE END STRING CHARACTER
            while (token != NULL) {
                index += 1;
                // Create space for the filename
                *(file_list+index) = (char*) malloc((strlen(token)+1)*sizeof(char)); 
                if (!(*(file_list+index))) exit_with_failure("Malloc file_list+index failed", 1);

                memcpy(*(file_list+index), token, strlen(token)+1);

                //printf("Tok:%s\n", token);
                
                token = strtok(NULL, " ");
            }
        }
        else // num_file == 0
        {
            num_file = -1;
            if (!file_list) printf("No filenames are stored in the cloud.\n");
            else 
            {
                printf("Received the complete files list (%d filenames):\n", tot_num_file-2);
                printf("***********************\n");
                for (int i = 0; i <= index; i++)
                {
                    // Skip these two files
                    if (!strcmp(*(file_list+i), ".") || !strcmp(*(file_list+i), "..")) 
                    {
                        free(*(file_list+i));
                        continue;
                    }
                    
                    printf("%s\n", *(file_list+i));
                    free(*(file_list+i));
                }
                printf("************************\n");
                free(file_list);
            }
            
        }

        // Send success message
        operation_succeed(sock, LIST_ACCEPTED, session_key2, nonce);

        free_5(iv, buffer, bufferSupp1, bufferSupp2, msg_to_hash);
        free_2(digest, plaintext);
    }

    return 1;
}

int renameClient(int sock, char* filename, char* new_filename, unsigned char* session_key1, unsigned char* session_key2, unsigned int* nonce)
{
    unsigned char* iv;

    unsigned char* msg_to_encr;
    unsigned char* encr_msg;
    int msg_to_encr_len;
    int encr_len;
    
    unsigned char* msg_to_hash;
    unsigned char* digest;
    unsigned int digest_len;
    int msg_to_hash_len;

    int ret;
    int msg_len;
    char* temp;
    char* temp2;
    unsigned char* buffer;
    unsigned char* bufferSupp1;

    if (strcmp(filename,"")==0)
    {
        printf("Filename is missing. Retry...\n\n");
        return 1;
    }
    if (strcmp(new_filename,"")==0)
    {
        printf("New filename is missing. Retry...\n\n");
        return 1;
    }

    // Generate the IV
    iv = (unsigned char*) malloc(sizeof(unsigned char)*IV_LEN);
    if (!iv) exit_with_failure("Malloc iv failed", 1);
    ret = RAND_poll(); // Seed OpenSSL PRNG
    if (ret != 1) exit_with_failure("RAND_poll failed\n", 0);
    ret = RAND_bytes((unsigned char*)&iv[0], IV_LEN);
    if (ret != 1) exit_with_failure("RAND_bytes failed\n", 0);


    /* ---- Create the first message (request, len encr., encr(name + new_name), hash(request, encr, iv, nonce), iv) ---- */
    // Encrypt the two names
    msg_to_encr_len = build_msg_2(&msg_to_encr, filename, strlen(filename),\
                                                new_filename, (strlen(new_filename)+1));
    if (msg_to_encr_len == -1) exit_with_failure("Error during the building of the message", 1);

    encrypt_AES_128_CBC(&encr_msg, &encr_len, msg_to_encr, msg_to_encr_len, iv, session_key1);

    // Create the hash
    temp = (char*) malloc(sizeof(char)*LEN_SIZE);
    if (!temp) exit_with_failure("Malloc temp failed", 1);

    sprintf(temp, "%d", *nonce);
    msg_to_hash_len = build_msg_4(&msg_to_hash, RENAME_REQUEST, strlen(RENAME_REQUEST),\
                                                encr_msg, encr_len,\
                                                iv, IV_LEN,
                                                temp, LEN_SIZE);
    if (msg_to_hash_len == -1) exit_with_failure("Error during the building of a message...", 1);

    digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len); 

    // Compose the message
    temp2 = (char*) malloc(sizeof(char)*LEN_SIZE);
    if (!temp2) exit_with_failure("Malloc temp2 failed", 1);

    sprintf(temp2, "%d", encr_len); // Here we put the encryption length in string format
    msg_len = build_msg_5(&buffer, RENAME_REQUEST, strlen(RENAME_REQUEST),\
                                   temp2, LEN_SIZE,\
                                   encr_msg, encr_len,\
                                   digest, HASH_LEN,\
                                   iv, IV_LEN);
    if (msg_len == -1) exit_with_failure("Error during the building of a message", 1);


    //printf("Sending rename request to the server.\n");
    ret = send(sock, buffer, BUF_LEN, 0); 
    
    free_6(temp, buffer, msg_to_hash, digest, msg_to_encr, encr_msg);
    free_2(temp2, iv);
    
    if (ret == -1) 
    {
        printf("Send failed.\n");
        return -1;
    }
    *nonce += 1;
    


    /* ---- Parse the response ---- */
    buffer = (unsigned char*) malloc(sizeof(unsigned char)*BUF_LEN);
    if (!buffer) exit_with_failure("Malloc buffer failed", 1);

    ret = recv(sock, buffer, BUF_LEN,0);
    if (ret == -1) 
    {
        free(buffer);
        printf("Receive failed.\n");
        return -1;
    }
    //printf("Received the server's response.\n");

    bufferSupp1 = (unsigned char*) malloc(strlen(RENAME_DENIED)*sizeof(unsigned char)+1);
    if (!bufferSupp1) exit_with_failure("Malloc bufferSupp1 failed", 1);
    memcpy(bufferSupp1, buffer, strlen(RENAME_DENIED)); // denied or accepted same length
    *(bufferSupp1+strlen(RENAME_DENIED)) = '\0';

    // Parse the message based on the server response
    if (strcmp((char*) bufferSupp1, RENAME_DENIED) == 0)
    {
        ret = check_reqden_msg(RENAME_DENIED, buffer, *nonce, session_key1, session_key2);
       
    }
    else if (strcmp((char*) bufferSupp1, RENAME_ACCEPTED) == 0)
    {        
        ret = check_reqacc_msg(RENAME_ACCEPTED, buffer, *nonce, session_key2);
        if (ret != -1) printf("File renamed to %s!\n", new_filename);
    }
    else
    {
        printf("We don't know what the server said...\n\n");
        ret = -1;
    }

    free(buffer);
    free(bufferSupp1);

    if (ret != -1)  *nonce += 1;

    return ret;
}

int deleteClient(int sock, char* filename, unsigned char* session_key1, unsigned char* session_key2, unsigned int* nonce)
{       
    unsigned char* iv;
    unsigned char* encr_msg;
    int encr_len;
    
    unsigned char* msg_to_hash; 
    unsigned char* digest; 
    unsigned int digest_len; 
    int msg_to_hash_len;
    
    int msg_len;
    int ret;
    int len_fn;
    char* temp; 
    unsigned char* buffer;   
    unsigned char* bufferSupp1;
    char* bufferSupp2;
    
    if (strcmp(filename, "")==0)
    {
        printf("The filename field is missing. Retry...\n\n");
        return 1;
    }

    // Generate the IV 
    iv = (unsigned char*) malloc(sizeof(unsigned char)*IV_LEN); 
    if (!iv) exit_with_failure("Malloc iv failed", 1); 
    ret = RAND_poll(); 
    if (ret != 1) exit_with_failure("Rand_poll failed\n", 0); 
    ret = RAND_bytes((unsigned char*)&iv[0], IV_LEN); 
    if (ret != 1) exit_with_failure("RAND_bytes failed\n", 0); 




    /* ---- Send delete request (req., len. encr., encr. filename, hash(req, encr, iv, nonce), iv) ---- */
    len_fn = strlen(filename)+1;
    bufferSupp1 = (unsigned char*) malloc(len_fn*sizeof(unsigned char));
    if (!bufferSupp1) exit_with_failure("Malloc bufferSupp1 failed", 1);
    memcpy(bufferSupp1, filename, len_fn);
    
    
    encrypt_AES_128_CBC(&encr_msg, &encr_len, bufferSupp1, len_fn, iv, session_key1); 
    free(bufferSupp1);

    // Create hash
    temp = (char*) malloc(sizeof(char)*LEN_SIZE);
    if (!temp) exit_with_failure("Malloc temp failed", 1);
    bufferSupp2 = (char*)malloc(sizeof(char)*LEN_SIZE);
    if (!bufferSupp2) exit_with_failure("Malloc bufferSupp2 failed", 1);
 
    sprintf(bufferSupp2, "%u", *nonce);
    msg_to_hash_len = build_msg_4(&msg_to_hash, DELETE_REQUEST, strlen(DELETE_REQUEST),\
                                                encr_msg, encr_len,\
                                                iv, IV_LEN,\
                                                bufferSupp2, LEN_SIZE);
    if (msg_to_hash_len == -1) exit_with_failure("Something bad happened building the hash...", 0);

    digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len);    

    // Compose the message
    sprintf(temp, "%d", encr_len);
    msg_len = build_msg_5(&buffer, DELETE_REQUEST, strlen(DELETE_REQUEST),\
                                   temp, LEN_SIZE,\
                                   encr_msg, encr_len,\
                                   digest, HASH_LEN,\
                                   iv, IV_LEN);
    if(msg_len == -1) exit_with_failure("Error during the building of the message", 1);

    //printf("Sending delete request to the server.\n");
    ret = send(sock, buffer, BUF_LEN, 0); 
    
    free_6(temp, buffer, msg_to_hash, digest, encr_msg, iv);
    free(bufferSupp2);

    if (ret == -1)
    {
        printf("Send failed.\n");
        return -1;
    }

    *nonce += 1;



    
    // Here we receive the reply of the server
    buffer = (unsigned char*) malloc(sizeof(unsigned char)*BUF_LEN);
    if (!buffer) exit_with_failure("Malloc buffer failed", 1);

    ret = recv(sock, buffer, BUF_LEN,0);
    if (ret == -1) 
    {
        free(buffer);
        printf("Receive failed.\n");
        return -1;
    }
    //printf("Received the server's response.\n");

    bufferSupp1 = (unsigned char*) malloc((strlen(DELETE_DENIED)+1)*sizeof(unsigned char));
    if (!bufferSupp1) exit_with_failure("Malloc bufferSupp1 failed", 1);
    memcpy(bufferSupp1, buffer, strlen(DELETE_DENIED));
    memcpy(&*(bufferSupp1+strlen(DELETE_DENIED)), "\0", 1);

    if (strcmp((char*) bufferSupp1, DELETE_DENIED) == 0)
    {
        ret = check_reqden_msg(DELETE_DENIED, buffer, *nonce, session_key1, session_key2);
    }
    else if (strcmp((char*) bufferSupp1, DELETE_ACCEPTED) == 0)
    {        
        ret = check_reqacc_msg(DELETE_ACCEPTED, buffer, *nonce, session_key2);
        if (ret != -1) printf("File %s has been deleted!\n", filename);
    }
    else
    {
        printf("We don't know what the server said...\n\n");
        ret = -1;
    }

    free_2(buffer, bufferSupp1);

    if (ret != -1)  *nonce += 1;

    return ret;
}

int downloadClient(int sock, char* filename, unsigned char* session_key1, unsigned char* session_key2, unsigned int* nonce)
{
    unsigned char* iv;

    unsigned char* msg_to_encr;
    unsigned char* encr_msg;
    unsigned char* plaintext;
    unsigned int plain_len;
    unsigned int msg_to_encr_len;
    int encr_len;
    
    unsigned char* msg_to_hash;
    unsigned char* digest;
    unsigned int digest_len;
    int msg_to_hash_len;
    
    FILE* f1;

    int ret, i;
    int nchunk;
    int msg_len;
    char* temp;
    char* temp2;
    unsigned char* buffer;
    unsigned char* bufferSupp1;
    unsigned char* bufferSupp2;
    unsigned char* bufferSupp3;

    

    // Initialization of IV
    iv = (unsigned char*) malloc(sizeof(unsigned char)*IV_LEN);
    if (!iv) exit_with_failure("Malloc iv failed", 1);
    ret = RAND_poll(); // Seed OpenSSL PRNG
    if (ret != 1) exit_with_failure("RAND_poll failed\n", 0);
    ret = RAND_bytes((unsigned char*)&iv[0], IV_LEN);
    if (ret != 1) exit_with_failure("RAND_bytes failed\n", 0);

    f1 = fopen(filename, "r");
    if (f1)
    {
        printf("The filename already exists.\n");
        fclose(f1);
        return 1;
    }


    /* first message M1: download_request, len encr., encr(filename), hash(download_request, encr, iv, nonce), iv) ---- */    
    // Encrypt the two names
    msg_to_encr_len = strlen(filename)+1;
    msg_to_encr = (unsigned char*) malloc(msg_to_encr_len*sizeof(unsigned char));
    if (!msg_to_encr) exit_with_failure("Malloc msg_to_encr failed", 1);

    memcpy(msg_to_encr, filename, msg_to_encr_len); //Now on msg_to_encr there is the string to encrypt
    encrypt_AES_128_CBC(&encr_msg, &encr_len, msg_to_encr, msg_to_encr_len, iv, session_key1);

    // Create the hash
    temp = (char*) malloc(sizeof(char)*LEN_SIZE);
    if (!temp) exit_with_failure("Malloc temp failed", 1);
    temp2 = (char*) malloc(sizeof(char)*LEN_SIZE);
    if (!temp2) exit_with_failure("Malloc temp2 failed", 1);
    
    sprintf(temp, "%u", *nonce); // Now in temp there is the string version of the nonce
    msg_to_hash_len = build_msg_4(&msg_to_hash, DOWNLOAD_REQUEST, strlen(DOWNLOAD_REQUEST),\
                                                encr_msg, encr_len,\
                                                iv, IV_LEN,\
                                                temp, LEN_SIZE);
    if (msg_to_hash_len == -1) exit_with_failure("Error during the building of the message", 1);

    digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len);    

    // Now that we have both the encryption and the digest of the hash we can initialize the buffer and send the message
    sprintf(temp2, "%d", encr_len); //DONT KNOW IF IT WORKS IN ANY CASE
    msg_len = build_msg_5(&buffer, DOWNLOAD_REQUEST, strlen(DOWNLOAD_REQUEST),\
                                   temp2, LEN_SIZE,\
                                   encr_msg, encr_len,\
                                   digest, HASH_LEN,\
                                   iv, IV_LEN);
    if (msg_len == -1) exit_with_failure("Error during the building of the message", 1);
    // The message in the buffer now is: DOWNLOAD_REQUEST, len_encr, encr, hash, iv. We can send it now

    printf("Sending download request of %s to the server.\n", filename);
    ret = send(sock, buffer, BUF_LEN, 0); 
    if (ret == -1) exit_with_failure("Send failed", 1);
    
    *nonce += 1; // message sent, nonce increased for the answer or for other messages

    free_6(temp, buffer, msg_to_hash, digest, msg_to_encr, encr_msg);
    free_2(temp2, iv);




    /*--- Receiving server message ---- */
    //END OF THE COMMUNICATION OF THE FIRST MESSAGE, NOW WE SHOULD RECEIVE A RESPONSE FROM THE SERVER
    buffer = (unsigned char*) malloc(sizeof(unsigned char)*BUF_LEN);
    if (!buffer) exit_with_failure("Malloc buffer failed", 1);

    ret = recv(sock, buffer, BUF_LEN,0);
    if (ret == -1) exit_with_failure("Receive failed", 0);
    //printf("Received the server's response.\n");
    //printf("We received %s\n", (char*)buffer); HEAP OVERFLOW WITHOUT \0

    bufferSupp1 = (unsigned char*) malloc((strlen(DOWNLOAD_DENIED)+1)*sizeof(unsigned char));
    if (!bufferSupp1) exit_with_failure("Malloc bufferSupp1 failed", 1);
    memcpy(bufferSupp1, buffer, strlen(DOWNLOAD_DENIED)); // denied or accepted same length
    memcpy(&*(bufferSupp1+strlen(DOWNLOAD_DENIED)), "\0", 1);

    // Parse the message based on the server response
    if (strcmp((char*)bufferSupp1, DOWNLOAD_DENIED) == 0)
    {
        ret = check_reqden_msg(DOWNLOAD_DENIED, buffer, *nonce, session_key1, session_key2);
        if (ret == -1) printf("Something bad happened checking download_denied message...\n");
        else 
        {
            printf("Download denied from the server...\n");
            *nonce += 1;
        }

        free_2(bufferSupp1, buffer);
        return 1;
        
    }
    else if (strcmp((char*)bufferSupp1, DOWNLOAD_ACCEPTED) == 0)
    {        
        free(bufferSupp1);

        bufferSupp1 = (unsigned char*)malloc(sizeof(unsigned char)*LEN_SIZE); // Here we save the nchunk value of the message
        if (!bufferSupp1) exit_with_failure("Malloc bufferSupp1 for nchunk failed", 1);
        temp = (char*)malloc(sizeof(char)*REST_SIZE); // Here we save the number of bytes of the last chunk
        if (!temp) exit_with_failure("Malloc bufferSupp1 for nchunk failed", 1);
        bufferSupp2 = (unsigned char*) malloc(sizeof(unsigned char)*HASH_LEN);
        if (!bufferSupp2) exit_with_failure("Malloc bufferSupp2 failed", 1);
        //iv = (unsigned char*) malloc(sizeof(unsigned char)*IV_LEN);
        //if (!iv) exit_with_failure("Malloc iv failed", 1);

        //SETTING OF THE NCHUNK AND THE REST VARIABLE RECEIVED BY THE SERVER
        // the format of the message received should be: DOWNLOAD_ACCEPTED, nchunk, rest, hash, iv
        memcpy(bufferSupp1, &*(buffer+strlen(DOWNLOAD_ACCEPTED)+BLANK_SPACE), LEN_SIZE); //We put the nchunk value on bufferSupp1
        memcpy(temp, &*(buffer+strlen(DOWNLOAD_ACCEPTED)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE), REST_SIZE);
        nchunk = atoi((char*)bufferSupp1);
        //rest = atoi(temp);
        free(temp);
        if (nchunk == 0)
        {
            printf("The number of chunks is 0, this means that the file is empty. Download refused!\n\n");
            free_3(bufferSupp1, bufferSupp2, buffer);
            return 1;
        }

        //HERE WE TAKE THE HASH AND THE IV
        memcpy(bufferSupp2, &*(buffer+strlen(DOWNLOAD_ACCEPTED)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE+REST_SIZE+BLANK_SPACE), HASH_LEN); // hash
        //memcpy(iv, &*(buffer+strlen(DOWNLOAD_ACCEPTED)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE+REST_SIZE+BLANK_SPACE+HASH_LEN+BLANK_SPACE), IV_LEN); // iv

        // HERE WE SHOULD CHECK THE HASH
        temp = (char*) malloc(sizeof(char)*LEN_SIZE); //Here we save the nonce
        if (!temp) exit_with_failure("Malloc temp failed", 1);
        bufferSupp3 = (unsigned char*)malloc(sizeof(unsigned char)*REST_SIZE); // Here we save the rest value of the message
        if (!bufferSupp3) exit_with_failure("Malloc bufferSupp3 for nchunk failed", 1);

        sprintf(temp, "%u", *nonce); //nonce strring format
        memcpy(bufferSupp3, &*(buffer+strlen(DOWNLOAD_ACCEPTED)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE), REST_SIZE); //rest string format

        msg_to_hash_len = build_msg_4(&msg_to_hash, DOWNLOAD_ACCEPTED, strlen(DOWNLOAD_ACCEPTED),\
                                                    bufferSupp1, LEN_SIZE,\
                                                    bufferSupp3, REST_SIZE,\
                                                    temp, LEN_SIZE);
        if (msg_to_hash_len == -1) exit_with_failure("Error during the building of the message...", 1);

        digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len);

        ret = CRYPTO_memcmp(digest, bufferSupp2, HASH_LEN);
        free_6(digest, temp, buffer, msg_to_hash, bufferSupp1, bufferSupp2);
        free(bufferSupp3);
        if (ret != 0)
        {
            printf("Wrong download accepted hash\n\n");
            return 1;
        } 
        else 
        {
            printf("Download accepted. Downloading, please wait!\n");
            *nonce += 1;
        }
    }
    else
    {
        //We don't know what we received
        printf("Error: We received an incorrect message from the server.\n\n");
        free_2(bufferSupp1, buffer);
        return 1;
    }



        
    /* ---- NOW WE CAN BEGIN DOWNLOAD THE CHUNKS ---- */
    f1 = fopen(filename, "w"); // Inside download ????
    for (i = 0; i < nchunk; i++)
    {
        //THE FORMAT OF THE CHUNK MESSAGE IS LEN_ENC, {CHUNK}K1, H({CHUNK}K1, IV, NONCE), IV
        buffer = (unsigned char*)malloc(BUF_LEN);
        if (!buffer) exit_with_failure("Malloc buffer failed", 1);

        msg_len = LEN_SIZE+ENCR_CHUNK_LEN+HASH_LEN+IV_LEN+(3*BLANK_SPACE);
   
        ret = recv(sock, buffer, msg_len, 0);
        if (ret == -1) exit_with_failure("Receive failed", 0);
        //*(buffer+BUF_LEN-1) = '\0';
        //printf("Received the server's response. It's %s\n", (char*)buffer);

        // WE TAKE THE ENCR LEN, THE ENCRYPTED PART AND THE IV 
        bufferSupp1 = (unsigned char*) malloc(LEN_SIZE);
        if (!bufferSupp1) exit_with_failure("Malloc bufferSupp1 failed", 1);
        memcpy(bufferSupp1, buffer, LEN_SIZE); // Here we have len_enc
        encr_len = atoi((char*)bufferSupp1);

        bufferSupp2 = (unsigned char*) malloc(encr_len);
        if (!bufferSupp2) exit_with_failure("Malloc bufferSupp2 failed", 1);
        memcpy(bufferSupp2, &*(buffer+LEN_SIZE+BLANK_SPACE), encr_len);

        iv = (unsigned char*) malloc(sizeof(unsigned char)*(IV_LEN+1));
        if (!iv) exit_with_failure("Malloc iv failed", 1);
        memcpy(iv, &*(buffer+LEN_SIZE+BLANK_SPACE+encr_len+BLANK_SPACE+HASH_LEN+BLANK_SPACE), IV_LEN); // iv
        //*(iv+IV_LEN) = '\0';

        // WE SHOULD COMPARE THE TWO DIGEST TO AUTHENTICATE THE MESSAGE
        bufferSupp3 = (unsigned char*)malloc(HASH_LEN*sizeof(unsigned char*));
        if (!bufferSupp3) exit_with_failure("Malloc bufferSupp3 failed", 1);
        memcpy(bufferSupp3, &*(buffer+LEN_SIZE+BLANK_SPACE+encr_len+BLANK_SPACE), HASH_LEN); //Here we have the hash to compare
        
        temp = (char*)malloc(sizeof(char)*LEN_SIZE);
        if (!temp) exit_with_failure("Malloc of temp failed", 1);
        
        sprintf(temp, "%u", *nonce);
        msg_to_hash_len = build_msg_3(&msg_to_hash, bufferSupp2, encr_len,\
                                                    iv, IV_LEN,\
                                                    temp, LEN_SIZE);

        if (msg_to_hash_len == -1) exit_with_failure("Something bad happened building the hash...", 0);

        digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len);

        ret = CRYPTO_memcmp(digest, bufferSupp3, HASH_LEN);
        free_5(buffer, bufferSupp3, temp, msg_to_hash, digest);
        if (ret != 0)
        {
            printf("Wrong download chunk hash\n\n");
            free_3(bufferSupp1, bufferSupp2, iv);
            return 1;
        }

        *nonce += 1;

        decrypt_AES_128_CBC(&plaintext, &plain_len, bufferSupp2, encr_len, iv, session_key1);
        //printf("The chunk we received is %s\n\n", (char*)plaintext);


        // WRITE TO FILE
        fwrite(plaintext, sizeof(unsigned char), plain_len, f1);
        
        free_4(bufferSupp1, bufferSupp2, iv, plaintext);
        //printf("We received correctly the chunk number %i\n", i);

        buffer = (unsigned char*)malloc(BUF_LEN);
        if (!buffer) exit_with_failure("Malloc buffer failed", 1 );
        memcpy(buffer, "Ciao", 5);
        ret = send(sock, buffer, BUF_LEN, 0);
        free(buffer);
        if (ret == -1)
        {
            printf("Receive operation gone bad\n");
            return -1;
        }
        //printf("Confirmation sent!\n");
    }
    fclose(f1);

    /* ---- SEND DOWNLOAD FINISHED MESSAGE ---- */
    printf("Download is finished.\n");
    operation_succeed(sock, DOWNLOAD_FINISHED, session_key2, nonce);
        
    return 1;
}

int uploadClient(int sock, char* filename, unsigned char* session_key1, unsigned char* session_key2, unsigned int* nonce)
{
    unsigned char* iv;

    unsigned char* msg_to_encr;
    unsigned char* encr_msg;
    unsigned int msg_to_encr_len;
    int encr_len;
    
    unsigned char* msg_to_hash;
    unsigned char* digest;
    unsigned int digest_len;
    int msg_to_hash_len;
    
    FILE* f1;
    struct stat st;

    int ret, i, max, j, ch;
    long nchunk, rest;
    int msg_len;
    char* temp;
    char* temp2;
    unsigned char* buffer;
    unsigned char* bufferSupp1;
    unsigned char* bufferSupp2;

    if (strcmp(filename, "")==0)
    {
        printf("The filename is missing...\n\n");
        return 1;
    }

    // Initialization of IV
    iv = (unsigned char*) malloc(sizeof(unsigned char)*IV_LEN);
    if (!iv) exit_with_failure("Malloc iv failed", 1);
    ret = RAND_poll(); // Seed OpenSSL PRNG
    if (ret != 1) exit_with_failure("RAND_poll failed\n", 0);
    ret = RAND_bytes((unsigned char*)&iv[0], IV_LEN);
    if (ret != 1) exit_with_failure("RAND_bytes failed\n", 0);

    //Calculate number of chunks of the file! Figure out if file is present! 
    f1 = fopen(filename, "r");
    if (!(f1))
    {
        printf("File %s doesn't exist...\n  ", filename);
        free(iv);
        return 1;
    }
    stat(filename, &st);
    //printf("The size of the file is %ld\n", st.st_size);
    nchunk = (st.st_size/CHUNK_SIZE)+1;
    rest = st.st_size - (nchunk-1)*CHUNK_SIZE; // This is the number of bits of the final chunk

    // If FIle larger than 4GB refuse upload 
    if(st.st_size > 4294967296) //MAGGIORE DI 4 GB
    {
        printf("Upload rejected: File is more than 4 Gigabyte and therefore to large. If you want to upload larger files please purchase a premium plan."); 
        free(iv);
        return 1; 
    }

    //M1: Send message to request the upload. Message format: 
    //UPLOAD_REQUEST encr_len, encr{filename}, Hash(UPLOAD_REQUEST, filename, nchunk, nonce), IV, NCHUNK 
   
    msg_to_encr_len = strlen(filename)+1;
    msg_to_encr = (unsigned char*) malloc(msg_to_encr_len*sizeof(unsigned char));
    if (!msg_to_encr) exit_with_failure("Malloc msg_to_encr failed", 1);

    memcpy(msg_to_encr, filename, msg_to_encr_len); //Now on msg_to_encr there is the string to encrypt
    encrypt_AES_128_CBC(&encr_msg, &encr_len, msg_to_encr, msg_to_encr_len, iv, session_key1);

        // Create the hash
    temp = (char*) malloc(sizeof(char)*LEN_SIZE);
    if (!temp) exit_with_failure("Malloc temp failed", 1);
    temp2 = (char*) malloc(sizeof(char)*LEN_SIZE);
    if (!temp2) exit_with_failure("Malloc temp2 failed", 1);
    bufferSupp1 = (unsigned char*)malloc(LEN_SIZE);
    if (!bufferSupp1) exit_with_failure("Malloc buffSupp1 failed", 1);



    sprintf(temp, "%u", *nonce); // Now in temp there is the string version of the nonce
    sprintf((char*)bufferSupp1, "%li", nchunk); //
    //printf("%s", bufferSupp1); 


    msg_to_hash_len = build_msg_5(&msg_to_hash, UPLOAD_REQUEST, strlen(UPLOAD_REQUEST),\
                                                encr_msg, encr_len,\
                                                iv, IV_LEN,\
                                                temp, LEN_SIZE,\
                                                bufferSupp1, LEN_SIZE);
    if (msg_to_hash_len == -1) exit_with_failure("Error during the building of the message", 1);

    digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len);    


    sprintf(temp2, "%d", encr_len); //DONT KNOW IF IT WORKS IN ANY CASE
    msg_len = build_msg_6(&buffer, UPLOAD_REQUEST, strlen(UPLOAD_REQUEST),\
                                   temp2, LEN_SIZE,\
                                   encr_msg, encr_len,\
                                   digest, HASH_LEN,\
                                   iv, IV_LEN,\
                                   bufferSupp1, LEN_SIZE);
    if (msg_len == -1) exit_with_failure("Error during the building of the message", 1);
    // The message in the buffer now is: DOWNLOAD_REQUEST, len_encr, encr, hash, iv. We can send it now

    //printf("I'm sending to the server the download request.\n");
    ret = send(sock, buffer, BUF_LEN, 0); 
    if (ret == -1) exit_with_failure("Send failed", 1);
    
    *nonce += 1; // message sent, nonce increased for the answer or for other messages

    free_6(temp, buffer, msg_to_hash, digest, msg_to_encr, encr_msg);
    free_3(iv, temp2, bufferSupp1);

    //END OF FIRST MESSAGE 

    //NOW WE RECEIVE REPLY FROM SERVER 
    //EITHER UPPLOAD_ACCEPTED OR UPLOAD_DENIED 

    buffer = (unsigned char*) malloc(sizeof(unsigned char)*BUF_LEN);
    if (!buffer) exit_with_failure("Malloc buffer failed", 1);

    ret = recv(sock, buffer, BUF_LEN,0);
    if (ret == -1) exit_with_failure("Receive failed", 0);
    //printf("Received the server's response.\n");
    //printf("We received %s\n", (char*)buffer); HEAP OVERFLOW WITHOUT \0

    bufferSupp1 = (unsigned char*) malloc((strlen(UPLOAD_DENIED)+1)*sizeof(unsigned char));
    if (!bufferSupp1) exit_with_failure("Malloc bufferSupp1 failed", 1);
    memcpy(bufferSupp1, buffer, strlen(UPLOAD_DENIED)); // denied or accepted same length
    memcpy(&*(bufferSupp1+strlen(UPLOAD_DENIED)), "\0", 1);

    printf("Uploading file %s. Please wait! If this is large file it can take a while.\n", filename);

    // Parse the message based on the server response
    if (strcmp((char*)bufferSupp1, UPLOAD_DENIED) == 0)
    {
        ret = check_reqden_msg(UPLOAD_DENIED, buffer, *nonce, session_key1, session_key2);
        if (ret == -1) printf("Something bad happened checking upload denied message...\n");
        else 
        {
            printf("Upload denied from the server...\n");
            *nonce += 1;
        }

        free_2(bufferSupp1, buffer);
        return 1;    
    } 
    else if (strcmp((char*)bufferSupp1, UPLOAD_ACCEPTED) == 0) 
    {   
        //HERE WE CHECK THE MAC
        iv = (unsigned char*) malloc(sizeof(unsigned char)*IV_LEN);
        if (!iv) exit_with_failure("Malloc iv failed", 1);
        temp = (char*)malloc(LEN_SIZE);
        if (!temp) exit_with_failure("Malloc temp failed", 1);
        bufferSupp2 = (unsigned char*)malloc(sizeof(unsigned char)*HASH_LEN);
        if(!bufferSupp2) exit_with_failure("Malloc bufferSupp2 failed", 1);

        memcpy(bufferSupp2, &*(buffer+strlen(UPLOAD_ACCEPTED)+BLANK_SPACE), HASH_LEN);
        sprintf((char*)temp, "%u", *nonce); //nonce is put on temp as a string

        msg_to_hash_len = build_msg_2(&msg_to_hash, UPLOAD_ACCEPTED, strlen(UPLOAD_ACCEPTED), \
                                                    temp, LEN_SIZE);
        if (msg_to_hash_len == -1) exit_with_failure("Something bad happened building the hash...", 0);

        digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len);

        ret = CRYPTO_memcmp(digest, bufferSupp2, HASH_LEN);
        free_6(bufferSupp2, buffer, bufferSupp1, iv, temp, digest);
        free(msg_to_hash);
        if (ret != 0)
        {
            printf("Wrong Upload chunk hash\n");
            return 1;
        }
        *nonce += 1;

        for (i = 0; i < nchunk; i++) 
        {
            msg_to_encr_len = CHUNK_SIZE;
            msg_to_encr = (unsigned char*)malloc(msg_to_encr_len);
            if (!msg_to_encr) exit_with_failure("Malloc msg_to_encr failed", 1);

            if (i == nchunk-1) max = rest;
            else max = CHUNK_SIZE; 

            for (j = 0; j < max; j++)
            {
                if ((ch = getc(f1)) == EOF)
                {
                   *(msg_to_encr+j) = '\0';
                    printf("File over!");
                    break;
                }
                *(msg_to_encr+j) = ch;
            }


            //ENCRYPT THE MESSAGE SENT
            iv = (unsigned char*) malloc(sizeof(unsigned char)*(IV_LEN));
            if (!iv) exit_with_failure("Malloc iv failed", 1);
            ret = RAND_bytes((unsigned char*)&iv[0], IV_LEN);
            if (ret != 1) exit_with_failure("RAND_bytes failed\n", 0);

            if (i == nchunk-1) encrypt_AES_128_CBC(&encr_msg, &encr_len, msg_to_encr, rest, iv, session_key1);
            else encrypt_AES_128_CBC(&encr_msg, &encr_len, msg_to_encr, msg_to_encr_len, iv, session_key1);

            //CREATE THE HASH
            bufferSupp1 = (unsigned char*)malloc(LEN_SIZE); //nonce string;
            if (!bufferSupp1) exit_with_failure("Malloc bufferSupp1 failed", 1);

            sprintf((char*)bufferSupp1, "%u", *nonce);
            msg_to_hash_len = build_msg_3(&buffer, encr_msg, encr_len,\
                                                   iv, IV_LEN,\
                                                   bufferSupp1, LEN_SIZE);
            if (msg_to_hash_len == -1) exit_with_failure("Something bad happened building the hash...", 0);
            
            digest = hmac_sha256(session_key2, 16, buffer, msg_to_hash_len, &digest_len);
            free(buffer);

            // CREATE THE MESSAGE
            temp = (char*)malloc(LEN_SIZE*sizeof(char));
            if (!temp) exit_with_failure("Malloc temp failed", 1);

            sprintf(temp, "%i", encr_len);
            msg_len = build_msg_4(&buffer, temp, LEN_SIZE,\
                                           encr_msg, encr_len,\
                                           digest, HASH_LEN,\
                                           iv, IV_LEN);
            if (msg_len == -1) exit_with_failure("Something bad happened building the message...", 0);

            //printf("The message len is %i\n", msg_len);
            //printf("I'm sending %s", (char*)buffer);

            ret = send(sock, buffer, msg_len, 0);
            if (ret == -1)
            {
                printf("Send operation gone bad\n");
                free_6(buffer, temp, digest, iv, encr_msg, msg_to_encr);
                free(bufferSupp1);
                return -1;
            }
            *nonce += 1;

            //printf("We are sending the chunk number %i\n", i);

            free_6(iv, encr_msg, msg_to_encr, buffer, bufferSupp1, digest);
            free(temp);

            buffer = (unsigned char*)malloc(BUF_LEN);
            if (!buffer) exit_with_failure("Malloc buffer failed", 1 );
            ret = recv (sock, buffer, BUF_LEN, 0);
            if (ret == -1)
            {
                printf("Send operation gone bad\n");
                return -1;
            }
            //printf("Confirmed! %s\n", (char*)buffer);
            free(buffer);
        }   
        fclose(f1);

        /* ---- WE SENT ALL THE CHUNKS NOW WE WAIT FOR THE CLIENT OUTCOME ---- */
        buffer = (unsigned char*)malloc(BUF_LEN*(sizeof(unsigned char)));
        if (!buffer) exit_with_failure("Malloc buffer failure", 1);
        ret = recv(sock, buffer, BUF_LEN, 0);
        if (ret == -1)
        {
            printf("Send operation gone bad!\n\n");
            free(buffer);
            return -1;
        }

        // DECRYPT THE BUFFER
        ret = check_reqacc_msg(UPLOAD_FINISHED, buffer, *nonce, session_key2);
        if (ret == -1)
        {
            printf("Check upload_finished gone bad.\n\n");
            free(buffer);
            return 1;
        }

        free(buffer);
        printf("Upload successful!\n");
        *nonce += 1;

        return 1;
    }
    else
    {
        printf("We don't know what the server responded...\n");
        return 1;
    }
    return 1;    
}

int shareClient(int sock, char* filename, char* peername, unsigned int* nonce, unsigned char* session_key1, unsigned char* session_key2)
{
    int ret;

    int msg_to_encr_len;
    int encr_len;
    unsigned char* msg_to_encr;
    unsigned char* encr_msg;

    int msg_to_hash_len;
    unsigned int digest_len;
    unsigned char* msg_to_hash;
    unsigned char* digest;

    int msg_len;

    char* temp;
    char* temp2;
    unsigned char* iv;
    unsigned char* buffer;
    unsigned char* bufferSupp1;


    // Generate the IV
    iv = (unsigned char*) malloc(sizeof(unsigned char)*IV_LEN);
    if (!iv) exit_with_failure("Malloc iv failed", 1);
    ret = RAND_poll(); // Seed OpenSSL PRNG
    if (ret != 1) exit_with_failure("RAND_poll failed\n", 0);
    ret = RAND_bytes((unsigned char*)&iv[0], IV_LEN);
    if (ret != 1) exit_with_failure("RAND_bytes failed\n", 0);


    /* ---- Build the message for the server ---- */
    // (SHARE_REQ encr_len encr_msg(username, filename, peer_name) hash(req encr iv nonce_cs) iv)
    msg_to_encr_len = strlen(filename)+strlen(peername)+2;
    msg_to_encr = (unsigned char*) malloc(msg_to_encr_len*sizeof(unsigned char));
    if (!msg_to_encr) exit_with_failure("Malloc msg_to_encr failed", 1);

    msg_to_encr_len = build_msg_2(&msg_to_encr, filename, strlen(filename),\
                                                peername, strlen(peername)+1);
    encrypt_AES_128_CBC(&encr_msg, &encr_len, msg_to_encr, msg_to_encr_len, iv, session_key1);

    // Create the hash
    temp = (char*) malloc(sizeof(char)*LEN_SIZE);
    if (!temp) exit_with_failure("Malloc temp failed", 1);
    temp2 = (char*) malloc(sizeof(char)*LEN_SIZE);
    if (!temp2) exit_with_failure("Malloc temp2 failed", 1);
    
    sprintf(temp, "%u", *nonce); // Now in temp there is the string version of the nonce
    msg_to_hash_len = build_msg_4(&msg_to_hash, SHARE_REQUEST, strlen(SHARE_REQUEST),\
                                                encr_msg, encr_len,\
                                                iv, IV_LEN,\
                                                temp, LEN_SIZE);
    if (msg_to_hash_len == -1) exit_with_failure("Error during the building of the message", 1);

    digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len);    

    // Now that we have both the encryption and the digest of the hash we can initialize the buffer and send the message
    sprintf(temp2, "%d", encr_len);
    msg_len = build_msg_5(&buffer, SHARE_REQUEST, strlen(DOWNLOAD_REQUEST),\
                                   temp2, LEN_SIZE,\
                                   encr_msg, encr_len,\
                                   digest, HASH_LEN,\
                                   iv, IV_LEN);
    if (msg_len == -1) exit_with_failure("Error during the building of the message", 1);

    printf("Sending the share request to the server.\n");
    ret = send(sock, buffer, BUF_LEN, 0); 
    if (ret == -1) exit_with_failure("Send failed", 1);
    
    *nonce += 1; // message sent, nonce increased for the answer or for other messages

    free_6(temp, buffer, msg_to_hash, digest, msg_to_encr, encr_msg);
    free_2(temp2, iv);


    /* ---- Parse server response (operation denied or accepted) ---- */
    buffer = (unsigned char*) malloc(sizeof(unsigned char)*BUF_LEN);
    if (!buffer) exit_with_failure("Malloc buffer failed", 1);

    ret = recv(sock, buffer, BUF_LEN,0);
    if (ret == -1) 
    {
        free(buffer);
        printf("Receive failed.\n");
        return -1;
    }
    //printf("Received the server's response.\n");
    

    bufferSupp1 = (unsigned char*) malloc((strlen(SHARE_DENIED)+1)*sizeof(unsigned char));
    if (!bufferSupp1) exit_with_failure("Malloc bufferSupp1 failed", 1);
    memcpy(bufferSupp1, buffer, strlen(SHARE_DENIED)); // denied or accepted same length
    memcpy(bufferSupp1+strlen(SHARE_DENIED), "\0", 1);

    if (strcmp((char*) bufferSupp1, SHARE_DENIED) == 0)
    {
        ret = check_reqden_msg(SHARE_DENIED, buffer, *nonce, session_key1, session_key2);
        if (ret == -1) printf("Something bad happened checking the share_denied...");

        *nonce += 1;
    }
    else if (strcmp((char*) bufferSupp1, SHARE_ACCEPTED) == 0)
    {
        ret = check_reqacc_msg(SHARE_ACCEPTED, buffer, *nonce, session_key2);
        if (ret == -1) printf("Something bad happened checking the share_accepted...");
        else printf("The share request has been accepted by %s!\n", peername);

        *nonce += 1;
    }
    else
    {
        printf("We don't know what the server said...\n\n");
        ret = 1;
    }

    free_2(buffer, bufferSupp1);

    return ret;
}

int shareReceivedClient(int sd, char* rec_mex, unsigned int* nonce_sc, unsigned char* session_key1, unsigned char* session_key2, char* username)
{
    int ret;
    char s;
    char line[2];
    unsigned int len_fn;
    unsigned int len_pn;

    int encr_len;
    unsigned int plain_len;
    unsigned char* plaintext;

    int msg_to_hash_len;
    unsigned int digest_len;
    unsigned char* msg_to_hash;
    unsigned char* encr_msg;
    unsigned char* digest;

    char* temp;
    unsigned char* iv;
    unsigned char* bufferSupp1;
    unsigned char* bufferSupp2;
    unsigned char* bufferSupp3;
    char* dimension;


    /* ---- Parse server message ---- */
    printf("Sharing request received.\n");
    bufferSupp1 = (unsigned char*) malloc((strlen(SHARE_PERMISSION)+1)*sizeof(unsigned char));
    if (!bufferSupp1) exit_with_failure("Malloc bufferSupp1 failed", 1);
    memcpy(bufferSupp1, rec_mex, strlen(SHARE_PERMISSION));
    *(bufferSupp1+strlen(SHARE_PERMISSION)) = '\0';

    //printf("The nonce_sc is %d\n", *nonce_sc);

    if (strcmp((char*) bufferSupp1, SHARE_PERMISSION) == 0)
    {
        free(bufferSupp1);
        bufferSupp1 = (unsigned char*)malloc(sizeof(unsigned char)*LEN_SIZE);
        if (!bufferSupp1) exit_with_failure("Malloc bufferSupp1 failed", 1);
        memcpy(bufferSupp1, &*(rec_mex+strlen(SHARE_PERMISSION)+BLANK_SPACE), LEN_SIZE);
        encr_len = atoi((char*)bufferSupp1);
        if (encr_len < 0 || encr_len > (4*16)) //16 is the dimension of a AES block, 4 the max number of blocks in this case
        {
            free(bufferSupp1);
            printf("Encryption length too high.\n");
            return 1;
        }

        // HERE WE TAKE THE ENCRYPTED MESSAGE
        encr_msg = (unsigned char*)malloc(sizeof(unsigned char)*encr_len);
        if (!encr_msg) exit_with_failure("Malloc encr_msg failed", 1);
        memcpy(encr_msg, &*(rec_mex+strlen(SHARE_PERMISSION)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE), encr_len);

        //HERE WE TAKE THE MAC
        bufferSupp2 = (unsigned char*)malloc(sizeof(unsigned char)*HASH_LEN);
        if (!bufferSupp2) exit_with_failure("Malloc bufferSupp2 failed", 1);
        memcpy(bufferSupp2, &*(rec_mex+strlen(SHARE_PERMISSION)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE+encr_len+BLANK_SPACE), HASH_LEN);

        //HERE WE TAKE THE IV
        iv = (unsigned char*)malloc(sizeof(unsigned char)*IV_LEN);
        if (!iv) exit_with_failure("Malloc iv failed", 1);
        memcpy(iv, &*(rec_mex+strlen(SHARE_PERMISSION)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE+encr_len+BLANK_SPACE+HASH_LEN+BLANK_SPACE), IV_LEN);

        // HERE WE SAVE THE NONCE INTO A STRING
        temp = (char*) malloc(sizeof(char)*LEN_SIZE);
        if (!temp) exit_with_failure("Malloc temp failed", 1);
        sprintf(temp, "%u", *nonce_sc);

        //Now we prepare the message to hash to compare it with the one we received
        msg_to_hash_len = build_msg_4(&msg_to_hash, SHARE_PERMISSION, strlen(SHARE_PERMISSION), \
                                                    encr_msg, encr_len, \
                                                    iv, IV_LEN, \
                                                    temp, LEN_SIZE);
        if (msg_to_hash_len == -1) exit_with_failure("Something bad happened building the hash...", 0);

        digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len); 

        ret = CRYPTO_memcmp(digest, bufferSupp2, HASH_LEN);

        free_5(bufferSupp1, bufferSupp2, temp, msg_to_hash, digest);

        if (ret != 0)
        {
            printf("Wrong share_permission hash\n\n");
            free_2(encr_msg, iv);
            return 1;
        } 
        else 
        {
            *nonce_sc += 1;
            ret = save_nonce_sc(username, *nonce_sc);
            if (ret == -1)
            {
                printf("Error saving the nonce_sc... Necessary to close the connection\n\n");
                return -1;
            }
        }
       

        // DECRYPT THE MESSAGE
        decrypt_AES_128_CBC(&plaintext, &plain_len, encr_msg, encr_len, iv, session_key1);
        free_2(encr_msg, iv);

        len_fn = str_ssplit(plaintext, DELIM);
        bufferSupp1 = (unsigned char*) malloc((len_fn+1)*sizeof(unsigned char));
        if (!bufferSupp1) exit_with_failure("Malloc bufferSupp1 failed", 1);
        memcpy(bufferSupp1, plaintext, len_fn);
        *(bufferSupp1+len_fn) = '\0';

        len_pn = plain_len - (LEN_SIZE+1) - len_fn - BLANK_SPACE;
        bufferSupp2 = (unsigned char*) malloc((len_pn+1)*sizeof(unsigned char));
        if (!bufferSupp2) exit_with_failure("Malloc bufferSupp2 failed", 1);
        memcpy(bufferSupp2, &*(plaintext+len_fn+BLANK_SPACE), len_pn);
        *(bufferSupp2+len_pn) = '\0';

        bufferSupp3 = (unsigned char*) malloc((LEN_SIZE+1)*sizeof(unsigned char));
        if (!bufferSupp3) exit_with_failure("Malloc bufferSupp2 failed", 1);
        memcpy(bufferSupp3, &*(plaintext+len_fn+BLANK_SPACE+len_pn), LEN_SIZE);
        *(bufferSupp3+LEN_SIZE) = '\0';
        //printf("The dimension we received is: %s\n", bufferSupp3);


        // sanitize them????

        // CHOOSE WHAT TO DO
        from_B_to_H(&dimension, (char*)bufferSupp3);
        printf("A user has requested to share the file %s. What do you choose (y/n)?",
                bufferSupp1);

        free_5(bufferSupp1, bufferSupp2, plaintext, bufferSupp3, dimension);

        if (fgets(line, 2, stdin)) 
        {
            if (1 == sscanf(line, "%c", &s)) {
                // SEND CONFIRMATION OR NOT TO THE SERVER
                if (s == 'y' || s == 'Y')
                {
                    operation_succeed(sd, SHARE_ACCEPTED, session_key2, nonce_sc);
                    ret = save_nonce_sc(username, *nonce_sc);
                    if (ret == -1)
                    {
                        printf("Error saving the nonce_sc... Necessary to close the connection\n\n");
                        return -1;
                    }
                    printf("File received and copied to your storage.\n\n");
                    ret = 1;
                }
                else if (s == 'n' || s == 'N')
                {
                    operation_denied(sd, "The user hasn't accepted to share the file", SHARE_DENIED,\
                        session_key1, session_key2, nonce_sc);
                    ret = 1;
                }
                else
                {
                    printf("We don't know what the user said...\n\n");
                    ret = 1;
                }
            }
        }
    }

    else
    {
        printf("We don't know what the server said...\n\n");
        free(bufferSupp1);
        ret = 1;
    }

    return ret;
}


void reset_nonce_sc(char* username)
{
    char buffer[MAX_LEN_USERNAME+11];
    FILE* f1;

    //if (chdir("../clientsFolder")==-1)
    //{
    //    printf("Error moving to ClientsFolder... Exiting");
    //    exit(1);
    //}

    memset(buffer, 0, MAX_LEN_USERNAME+11);
    sprintf(buffer, "%s_nonce.txt", username);
    f1 = fopen(buffer, "w");
    if (!f1)
    {
        printf("Error during the opening of the nonce file\n");
        exit(1);
    }
    memset(buffer, 0, MAX_LEN_USERNAME+11);
    sprintf(buffer, "0");
    if (!fwrite(buffer, sizeof(char), 2, f1))
    {
        printf("Error during write operation..\n");
        fclose(f1);
        exit(1);
    }
    fclose(f1);
    if (chdir("../download")==-1)
    {
        printf("Error moving to download folder... Need to close the connection\n\n");
        exit(1);
    }
}

int take_nonce_sc(char* username)
{
    unsigned int nonce_sc;
    char buffer[MAX_LEN_USERNAME+11];
    FILE* f1;

    //if (chdir("../clientsFolder")==-1)
    //{
    //    printf("Error moving to ClientsFolder... Exiting");
    //    exit(0);
    //}
    memset(buffer, 0, MAX_LEN_USERNAME+11);
    sprintf(buffer, "%s_nonce.txt", username);
    f1 = fopen(buffer, "r");
    if (!f1)
    {
        printf("Error during the opening of the file of the nonce... This error doesn't allow share operation. Contact us\n");
        exit(1);
    }
    memset(buffer, 0, MAX_LEN_USERNAME+11);
    if(!fread(buffer, sizeof(char), LEN_SIZE+1, f1))
    {
        printf("The file opened is empty... The share operation is not allowed. Contact us\n");
        fclose(f1);
        exit(1);
    }
    fclose(f1);
    if (chdir("../download")==-1)
    {
        printf("Error moving to download folder... Need to close the connection\n\n");
        exit(1);
    }
    sscanf(buffer, "%u", &nonce_sc); //Here we save the nonce used for the communication that begin from the server
    return nonce_sc;
}

int save_nonce_sc(char* username, unsigned int nonce_sc)
{
    char buffer[MAX_LEN_USERNAME+11];
    FILE* f1;

    //if (chdir("../clientsFolder")==-1)
    //{
    //    printf("Error moving to ClientsFolder... Exiting");
    //    return -1;
    //}
    memset(buffer, 0, MAX_LEN_USERNAME+11);
    sprintf(buffer, "%s_nonce.txt", username);
    f1 = fopen(buffer, "w");
    if (!f1)
    {
        printf("Error during the opening of the nonce file\n");
        return -1;
    }
    memset(buffer, 0, MAX_LEN_USERNAME+11);
    sprintf(buffer, "%d", nonce_sc);
    if (!fwrite(buffer, sizeof(char), LEN_SIZE+1, f1))
    {
        printf("Error during write operation..\n");
        fclose(f1);
        return -1;
    }
    fclose(f1);
    if (chdir("../download")==-1)
    {
        printf("Error moving to download folder... Need to close the connection\n\n");
        return -1;
    }
    return 1;
}

int delete_nonce_sc(char* username)
{
    char buffer[MAX_LEN_USERNAME+11];
    FILE* f1;

    //if (chdir("../clientsFolder")==-1)
    //{
    //    printf("Error moving to ClientsFolder... Exiting");
    //    return -1;
    //}
    memset(buffer, 0, MAX_LEN_USERNAME+11);
    sprintf(buffer, "%s_nonce.txt", username);
    f1 = fopen(buffer, "w");
    if (!f1)
    {
        printf("Error during the opening of the nonce file\n");
        return -1;
    }
    remove(buffer);
    fclose(f1);
    if (chdir("../download")==-1)
    {
        printf("Error moving to download folder... Need to close the connection\n\n");
        return -1;
    }
    return 1;
}