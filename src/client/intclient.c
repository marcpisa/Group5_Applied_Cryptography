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

int loginClient(int *sock, unsigned char** session_key1, unsigned char** session_key2, char* username, struct sockaddr_in srv_addr, X509_STORE* ca_store) 
{
    /*********************
     * VARIABLES
     ********************/
    char* path_pubkey;
    char* path_rsa_key;
    int msg_len;
    size_t offset;
    size_t K_len;

    // Digital signature
    unsigned char* exp_digsig;
    unsigned char* signature;
    int expected_len;
    unsigned int signature_len;

    // Diffie-Hellman
    EVP_PKEY* my_prvkey = NULL;
    EVP_PKEY* dh_pubkey = NULL;
    EVP_PKEY* peer_pubkey;
    unsigned char* K;
    unsigned char* pubkey_byte = NULL;
    int pubkey_len = 0;
    
    // Certificate
    X509* serv_cert = NULL;
    EVP_PKEY* pub_rsa_key_serv;
    int cert_len;

    int ret;
    char* temp;
    unsigned char* buffer;
    unsigned char* cert_buffer;
    unsigned char* bufferSupp1;
    unsigned char* bufferSupp2;
    /*********************
     * END VARIABLES
     ********************/

    // Creation of socket
    *sock = createSocket();
    if (connect(*sock, (struct sockaddr*)&srv_addr, sizeof(srv_addr)) < 0) exit_with_failure("Connect failed", 1);

    // Compose the path for the current user
    path_pubkey = (char*) malloc(sizeof(char)*(15+strlen(username)+14+1));
    memcpy(path_pubkey, "../../database/", 15);
    memcpy(&*(path_pubkey+15), username, strlen(username));
    memcpy(&*(path_pubkey+15+strlen(username)), "/dh_pubkey.pem\0", 14+1);
    
    path_rsa_key = (char*) malloc(sizeof(char)*(15+strlen(username)+8+1));
    memcpy(path_rsa_key, "../../database/", 15);
    memcpy(&*(path_rsa_key+15), username, strlen(username));
    memcpy(&*(path_rsa_key+15+strlen(username)), "/rsa.pem\0", 8+1);

    // Generate DH asymmetric key(s)
    pubkey_byte = gen_dh_keys(path_pubkey, &my_prvkey, &dh_pubkey, &pubkey_len);
    EVP_PKEY_free(dh_pubkey);    



    /* ---- 1st message: login request message + username + DH pubkey ---- */
    msg_len = build_msg_3(&buffer, LOGIN_REQUEST, strlen(LOGIN_REQUEST),\
                                   username, strlen(username),\
                                   pubkey_byte, pubkey_len);
    if (msg_len == -1) exit_with_failure("Something bad happened building first login message...", 0);

    printf("I'm sending to the server the first message.\n");
    ret = send(*sock, buffer, BUF_LEN, 0);
    
    free(buffer);
    
    if (ret == -1) 
    {  
        free_3(path_pubkey, path_rsa_key, pubkey_byte);
        EVP_PKEY_free(my_prvkey);
        printf("Send failed.\n");
        return -1;
    }    




    /* ---- Obtain and parse response server (DH pubkey, signature, len. cert. and cert.) ----*/
    buffer = (unsigned char*) malloc(sizeof(unsigned char)*BUF_LEN);
    if (!buffer) exit_with_failure("Malloc buffer failed", 1);
    ret = recv(*sock, buffer, BUF_LEN, 0);
    if (ret == -1) 
    {
        free_4(path_pubkey, path_rsa_key, buffer, pubkey_byte);
        EVP_PKEY_free(my_prvkey);
        printf("Receive failed.\n");
        return -1;
    }
    printf("Received the server's response.\n");

    temp = (char*) malloc(sizeof(char)*LEN_SIZE);
    if (!temp) exit_with_failure("Malloc temp failed", 1);
    bufferSupp1 = (unsigned char*) malloc(sizeof(unsigned char)*pubkey_len);
    if (!bufferSupp1) exit_with_failure("Malloc bufferSupp1 failed", 1);
    bufferSupp2 = (unsigned char*) malloc(sizeof(unsigned char)*SIGN_LEN);
    if (!bufferSupp2) exit_with_failure("Malloc bufferSupp2 failed", 1);

    // Parse the server response
    memcpy(bufferSupp1, buffer, pubkey_len); // g^b
    offset = pubkey_len+BLANK_SPACE;

    memcpy(bufferSupp2, &*(buffer+offset), SIGN_LEN); // dig.sig.
    offset += SIGN_LEN+BLANK_SPACE;

    memcpy(temp, &*(buffer+offset), LEN_SIZE); // len cert
    offset += LEN_SIZE+BLANK_SPACE;
    cert_len = atoi(temp);
    if (cert_len <= 0 || cert_len > MAX_CERT_LEN) 
    {
        free_4(path_pubkey, path_rsa_key, buffer, pubkey_byte);
        EVP_PKEY_free(my_prvkey);
        free_3(temp, bufferSupp1, bufferSupp2);
        printf("Incorrect certificate length.\n");
        return -1;
    }

    // The certificate is greater than 1024
    cert_buffer = (unsigned char*) malloc((cert_len+1)*sizeof(unsigned char));
    if (!cert_buffer) exit_with_failure("cert_buffer malloc failed", 1);
    memcpy(cert_buffer, &*(buffer+offset), cert_len); // cert

    // Obtain the public key, derive the established key
    peer_pubkey = pubkey_to_PKEY(bufferSupp1, pubkey_len);
    K = key_derivation(my_prvkey, peer_pubkey, &K_len);

    // Obtain the two session keys from the established key
    issue_session_keys(K, K_len, session_key1, session_key2);
   
    // Obtain the RSA public key and verify the certificate of the server
    serv_cert = cert_to_X509(cert_buffer, cert_len);
    if (!serv_cert) exit_with_failure("cert_to_X509 failed", 1);
    pub_rsa_key_serv = get_ver_server_pubkey(serv_cert, ca_store);
    
    // Generate the digital signature expected and verify it
    expected_len = build_msg_2(&exp_digsig, pubkey_byte, pubkey_len, bufferSupp1, pubkey_len);
    if (expected_len == -1) exit_with_failure("Something bad happened building the expected dig. sign.", 0);
    ret = verify_signature(exp_digsig, expected_len, bufferSupp2, SIGN_LEN, pub_rsa_key_serv);
      
    free_6(temp, buffer, bufferSupp1, bufferSupp2, pubkey_byte, cert_buffer);
    X509_free(serv_cert);
    EVP_PKEY_free(pub_rsa_key_serv);
    EVP_PKEY_free(my_prvkey);
    EVP_PKEY_free(peer_pubkey);
    
    if (ret != 1) 
    {
        free_4(path_pubkey, path_rsa_key, K, exp_digsig);
        printf("Signature verification failed.\n");
        return -1;    
    }
    



    /* ---- Generate last message for the server (digital signature) ---- */
    msg_len = SIGN_LEN;
    buffer = (unsigned char*) malloc(sizeof(unsigned char)*msg_len);
    if (!buffer) exit_with_failure("Malloc buffer failed", 1);

    // Generate digital signature
    signature = sign_msg(path_rsa_key, exp_digsig, expected_len, &signature_len, 0);

    // Compose the message
    memcpy(buffer, signature, SIGN_LEN); // dig. sig.

    printf("I'm sending to the server the last message.\n");
    ret = send(*sock, buffer, msg_len, 0); 

    free_6(path_pubkey, path_rsa_key, K, exp_digsig, signature, buffer);

    if (ret == -1)
    {
        printf("Send failed.\n");
        return -1;
    } 
 
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
    unsigned char* iv;    


    // Generate the IV
    iv = (unsigned char*) malloc(sizeof(unsigned char)*IV_LEN);
    if (!iv) exit_with_failure("Malloc iv failed", 1);
    ret = RAND_poll(); // Seed OpenSSL PRNG
    if (ret != 1) exit_with_failure("RAND_poll failed\n", 0);
    ret = RAND_bytes((unsigned char*)&iv[0], IV_LEN);
    if (ret != 1) exit_with_failure("RAND_bytes failed\n", 0);




    /* ---- Create the first message (request + hash + iv) ---- */
    // Generating the hash of the request and the nonce
    temp = (char*) malloc(sizeof(char)*LEN_SIZE);
    if (!temp) exit_with_failure("Malloc temp failed", 1);

    sprintf(temp, "%d", *nonce);
    msg_to_hash_len = build_msg_3(&msg_to_hash, LOGOUT_REQUEST, strlen(LOGOUT_REQUEST),\
                                                iv, IV_LEN,\
                                                temp, LEN_SIZE);
    if(msg_to_hash_len == -1) exit_with_failure("Something bad happened building the hash...", 0);

    digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len);    
    
    // Compose the message
    msg_len = build_msg_3(&buffer, LOGOUT_REQUEST, strlen(LOGOUT_REQUEST),\
                                   digest, HASH_LEN,\
                                   iv, IV_LEN);
    if(msg_len== -1) exit_with_failure("Something bad happened building the message...", 0);

    printf("I'm sending to the server the logout message.\n");
    ret = send(sock, buffer, BUF_LEN, 0); 
    
    free_5(temp, buffer, msg_to_hash, digest, iv);
    
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
    char *token;
    char** new_file_list;
    unsigned char* buffer;
    unsigned char* bufferSupp1;
    unsigned char* bufferSupp2;
    unsigned char* bufferSupp3;
    char** file_list;


    // Generate the IV
    iv = (unsigned char*) malloc(sizeof(unsigned char)*IV_LEN);
    if (!iv) exit_with_failure("Malloc iv failed", 1);
    ret = RAND_poll(); // Seed OpenSSL PRNG
    if (ret != 1) exit_with_failure("RAND_poll failed\n", 0);
    ret = RAND_bytes((unsigned char*)&iv[0], IV_LEN);
    if (ret != 1) exit_with_failure("RAND_bytes failed\n", 0);




    /* ---- Create the first message (req., hash(req, iv, nonce), iv) ---- */
    // Create the hash
    temp = (char*) malloc(sizeof(char)*LEN_SIZE);
    if (!temp) exit_with_failure("Malloc temp failed", 1);

    sprintf(temp, "%d", *nonce);
    msg_to_hash_len = build_msg_3(&msg_to_hash, LIST_REQUEST, strlen(LIST_REQUEST),\
                                                iv, IV_LEN,\
                                                temp, LEN_SIZE);
    if (msg_to_hash_len == -1) exit_with_failure("Error during the building of the message", 1);
    
    digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len);   

    // Compose the message
    msg_len = build_msg_3(&buffer, LIST_REQUEST, strlen(LIST_REQUEST),
                                   digest, HASH_LEN,
                                   iv, IV_LEN);
    if (msg_len == -1) exit_with_failure("Error during the building of the message", 1);

    printf("I'm sending to the server the list message.\n");
    ret = send(sock, buffer, BUF_LEN, 0); 

    free_5(temp, buffer, msg_to_hash, digest, iv);

    if (ret == -1)
    {
        printf("Send failed.\n");
        return -1;
    } 
    else *nonce = *nonce + 1;




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
        printf("Received chunk of filenames.\n");

        // Check if something failed server-side
        bufferSupp1 = (unsigned char*) malloc((strlen(LIST_DENIED)+1)*sizeof(unsigned char));
        if (!bufferSupp1) exit_with_failure("Malloc bufferSupp1 failed", 1); 

        memcpy(bufferSupp1, buffer, strlen(LIST_DENIED));
        memcpy(&*(bufferSupp1+strlen(LIST_DENIED)), "\0", 1);

        if (strcmp((char*) bufferSupp1, LIST_DENIED) == 0)
        {
            ret = check_reqden_msg(LIST_DENIED, buffer, *nonce, session_key1, session_key2);
            if (ret == -1) printf("Error checking list denied message.\n");
            else printf("List denied.\n"); 
            
            free_2(bufferSupp1, buffer);
            return -1;
        }

        free(bufferSupp1);


        // No operation denied, let's obtain the list
        temp = (char*) malloc(LEN_SIZE*sizeof(char));
        if (!temp) exit_with_failure("Malloc temp failed", 1);
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

        memcpy(temp, &*(buffer+old_offset), LEN_SIZE); // encr. len.
        encr_len = atoi(temp);
        old_offset += LEN_SIZE+BLANK_SPACE;

        memcpy(bufferSupp1, &*(buffer+old_offset), encr_len); // encr. list
        old_offset += encr_len+BLANK_SPACE;

        memcpy(bufferSupp2, &*(buffer+old_offset), HASH_LEN); // hash
        old_offset += HASH_LEN+BLANK_SPACE;

        memcpy(iv, &*(buffer+old_offset), IV_LEN); // iv

        bufferSupp3 = (unsigned char*)malloc(sizeof(unsigned char)*LEN_SIZE);
        if (!bufferSupp3) exit_with_failure("Malloc bufferSupp3 failed", 1);
        sprintf((char*)bufferSupp3, "%d", *nonce);
        
        // Check hash
        msg_to_hash_len = build_msg_4(&msg_to_hash, temp, LEN_SIZE,\
                                                    bufferSupp1, encr_len,\
                                                    iv, IV_LEN,\
                                                    bufferSupp3, LEN_SIZE);
        if (msg_to_hash_len == -1) exit_with_failure("Something bad happened building the hash...", 0);
        free(bufferSupp3);

        digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len); 

        ret = CRYPTO_memcmp(digest, bufferSupp2, HASH_LEN);
        if (ret == -1)
        {
            operation_denied(sock, "Wrong hash", LIST_DENIED, session_key1, session_key2, nonce);

            free_6(buffer, temp, bufferSupp1, bufferSupp2, iv, msg_to_hash);
            free(digest);
            return -1;
        }
        else if (num_file < 0 || num_file >= CHUNK_SIZE)
        {
            operation_denied(sock, "Incorrect num_file", LIST_DENIED, session_key1, session_key2, nonce);

            free_6(buffer, temp, bufferSupp1, bufferSupp2, iv, msg_to_hash);
            free(digest);
            return -1;
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
                printf("The client receives the complete file's list (%d filenames):\n", tot_num_file-2);
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
                printf("\n");
                free(file_list);
            }
            
        }

        // Send success message
        operation_succeed(sock, LIST_ACCEPTED, session_key2, nonce);

        free_6(temp, iv, buffer, bufferSupp1, bufferSupp2, msg_to_hash);
        free_2(digest, plaintext);
    }

    return 1;
}

int renameClient(int sock, char* filename, char* new_filename, unsigned char* session_key1, unsigned char* session_key2, unsigned int* nonce)
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

    int ret;
    int msg_len;
    char* temp;
    unsigned char* buffer;
    unsigned char* bufferSupp1;

    // Generate the IV
    iv = (unsigned char*) malloc(sizeof(unsigned char)*IV_LEN);
    if (!iv) exit_with_failure("Malloc iv failed", 1);
    ret = RAND_poll(); // Seed OpenSSL PRNG
    if (ret != 1) exit_with_failure("RAND_poll failed\n", 0);
    ret = RAND_bytes((unsigned char*)&iv[0], IV_LEN);
    if (ret != 1) exit_with_failure("RAND_bytes failed\n", 0);


    /* ---- Create the first message (request, len encr., encr(name + new_name), hash(request, encr, iv, nonce), iv) ---- */
    *nonce = *nonce+1;

    // Encrypt the two names
    msg_to_encr_len = build_msg_2(&msg_to_encr, filename, strlen(filename),\
                                                new_filename, strlen(new_filename));
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
    sprintf(temp, "%d", encr_len); // Here we put the encryption length in string format
    msg_len = build_msg_5(&buffer, RENAME_REQUEST, strlen(RENAME_REQUEST),\
                                   temp, LEN_SIZE,\
                                   encr_msg, encr_len,\
                                   digest, HASH_LEN,\
                                   iv, IV_LEN);
    if (msg_len == -1) exit_with_failure("Error during the building of a message", 1);


    printf("I'm sending to the server the rename message.\n");
    ret = send(sock, buffer, msg_len, 0); 
    
    free_6(temp, buffer, msg_to_hash, digest, msg_to_encr, encr_msg);
    free(iv);
    
    if (ret == -1) {
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
    printf("Received the server's response.\n");
    *nonce = *nonce+1;

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
    }
    else
    {
        printf("We don't know what the server said...\n\n");
        ret = -1;
    }

    free(buffer);
    free(bufferSupp1);

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
    
    int ret;
    int len_fn;
    int msg_len; 
    char* temp; 
    unsigned char* buffer;   
    unsigned char* bufferSupp1;
    

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

    sprintf(temp, "%d", *nonce);
    msg_to_hash_len = build_msg_4(&msg_to_hash, DELETE_REQUEST, strlen(DELETE_REQUEST),\
                                                encr_msg, encr_len,\
                                                iv, IV_LEN,\
                                                nonce, LEN_SIZE);
    if (msg_to_hash_len == -1) exit_with_failure("Something bad happened building the hash...", 0);

    digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len);    

    // Compose the message
    sprintf(temp, "%d", encr_len);
    msg_len = build_msg_5(&buffer, DELETE_REQUEST, strlen(DELETE_REQUEST),\
                                   temp, LEN_SIZE,\
                                   encr_msg, encr_len,\
                                   digest, HASH_LEN,\
                                   iv, IV_LEN);

    printf("I'm sending to the server the delete request.\n");
    ret = send(sock, buffer, BUF_LEN, 0); 
    
    free_6(temp, buffer, msg_to_hash, digest, encr_msg, iv);

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
    printf("Received the server's response.\n");

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
    }
    else
    {
        printf("We don't know what the server said...\n\n");
        ret = -1;
    }

    free_2(buffer, bufferSupp1);
    *nonce = *nonce + 1;

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

    int ret, i, j;
    int rest, nchunk;
    int msg_len;
    char* temp;
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

    /* first message M1: download_request, nonce, len encr., encr(filename), hash(download_request, encr, iv, nonce), iv) ---- */
    
    // Encrypt the two names
    msg_to_encr_len = strlen(filename);
    msg_to_encr = (unsigned char*) malloc(msg_to_encr_len*sizeof(unsigned char));
    if (!msg_to_encr) exit_with_failure("Malloc msg_to_encr failed", 1);

    memcpy(msg_to_encr, filename, strlen(filename)); //Now on msg_to_encr there is the string to encrypt

    encrypt_AES_128_CBC(&encr_msg, &encr_len, msg_to_encr, msg_to_encr_len, iv, session_key1);

    // Create the hash
    msg_to_hash_len = strlen(DOWNLOAD_REQUEST) + BLANK_SPACE + encr_len + BLANK_SPACE + IV_LEN + BLANK_SPACE + LEN_SIZE; // LEN SIZE WHY?
    temp = (char*) malloc(sizeof(char)*LEN_SIZE);
    if (!temp) exit_with_failure("Malloc temp failed", 1);

    sprintf(temp, "%d", *nonce); // Now in temp there is the string version of the nonce
    
    ret = build_msg_4(&msg_to_hash, DOWNLOAD_REQUEST, strlen(DOWNLOAD_REQUEST),\
                                    encr_msg, encr_len,\
                                    iv, IV_LEN,\
                                    temp, LEN_SIZE);
    if (ret == -1) exit_with_failure("Error during the building of the message", 1);

    digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len);    
    if (digest_len != (unsigned int) HASH_LEN) exit_with_failure("Wrong digest len", 0);

    // Now that we have both the encryption and the digest of the hash we can initialize the buffer and send the message
    msg_len = strlen(RENAME_REQUEST)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE+encr_len+BLANK_SPACE+HASH_LEN+BLANK_SPACE+IV_LEN;

    sprintf(temp, "%d", encr_len); //DONT KNOW IF IT WORKS IN ANY CASE

    ret = build_msg_5(&buffer, DOWNLOAD_REQUEST, strlen(DOWNLOAD_REQUEST),\
                               temp, LEN_SIZE,\
                               encr_msg, encr_len,\
                               digest, HASH_LEN,\
                               iv, IV_LEN);
    if (ret == -1) exit_with_failure("Error during the building of the message", 1);
    // The message in the buffer now is: DOWNLOAD_REQUEST, len_encr, encr, hash, iv. We can send it now

    printf("I'm sending to the server the download request.\n");
    ret = send(sock, buffer, msg_len, 0); 
    if (ret == -1) exit_with_failure("Send failed", 1);
    *nonce = *nonce+1; // message sent, nonce increased for the answer or for other messages

    free(temp);
    free(buffer);
    free(msg_to_hash);
    free(digest);
    free(msg_to_encr);
    free(encr_msg);
    free(iv);

    //END OF THE COMMUNICATION OF THE FIRST MESSAGE, NOW WE SHOULD RECEIVE A RESPONSE FROM THE SERVER
    msg_len = strlen(DOWNLOAD_DENIED)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE+REST_SIZE+BLANK_SPACE+HASH_LEN+BLANK_SPACE+IV_LEN;
    buffer = (unsigned char*) malloc(sizeof(unsigned char)*BUF_LEN);
    if (!buffer) exit_with_failure("Malloc buffer failed", 1);

    ret = recv(sock, buffer, BUF_LEN,0);
    if (ret == -1) exit_with_failure("Receive failed", 0);
    printf("Received the server's response.\n");
    printf("We received %s\n", (char*)buffer);

    bufferSupp1 = (unsigned char*) malloc((strlen(DOWNLOAD_DENIED)+1)*sizeof(unsigned char));
    if (!bufferSupp1) exit_with_failure("Malloc bufferSupp1 failed", 1);
    memcpy(bufferSupp1, buffer, strlen(DOWNLOAD_DENIED)); // denied or accepted same length
    memcpy(&*(bufferSupp1+strlen(DOWNLOAD_DENIED)), "\0", 1);


    // Parse the message based on the server response
    if (strcmp((char*)bufferSupp1, DOWNLOAD_DENIED) == 0)
    {
        // WAITING FOR TEO STUFFS
        free(bufferSupp1);
        free(buffer);
    }
    else if (strcmp((char*)bufferSupp1, DOWNLOAD_ACCEPTED) == 0)
    {        
        //HERE WE SHOULD CHECK THE HASH: the format of the message received should be: DOWNLOAD_ACCEPTED, nchunk, rest, hash
        // Parse the message
        bufferSupp2 = (unsigned char*) malloc(sizeof(unsigned char)*HASH_LEN);
        if (!bufferSupp2) exit_with_failure("Malloc bufferSupp2 failed", 1);
        memcpy(bufferSupp2, &*(buffer+strlen(DOWNLOAD_ACCEPTED)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE+REST_SIZE+BLANK_SPACE), HASH_LEN); // hash
        
        //SETTING OF THE NCHUNK AND THE REST VARIABLE RECEIVED BY THE SERVER
        free(bufferSupp1);
        bufferSupp1 = (unsigned char*)malloc(sizeof(unsigned char)*LEN_SIZE); // Here we save the nchunk value of the message
        if (!bufferSupp1) exit_with_failure("Malloc bufferSupp1 for nchunk failed", 1);
        temp = (char*)malloc(sizeof(char)*REST_SIZE); // Here we save the number of bytes of the last chunk
        if (!temp) exit_with_failure("Malloc bufferSupp1 for nchunk failed", 1);
        memcpy(bufferSupp1, &*(buffer+strlen(DOWNLOAD_ACCEPTED)+BLANK_SPACE), LEN_SIZE); //We put the nchunk value on bufferSupp1
        memcpy(temp, &*(buffer+strlen(DOWNLOAD_ACCEPTED)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE), REST_SIZE);
        nchunk = atoi((char*)bufferSupp1);
        rest = atoi(temp);
        free(temp);
        if (nchunk == 0)
        {
            printf("The number of chunk is 0, this means that the file is empty. Download refused!\n\n");
            return 1;
        }
        
        // Check hash on DOWNLOAD_ACCEPTED, NONCE, NCHUNK, REST
        printf("I'm going to check the mac value!\n");
        msg_to_hash_len = strlen(DOWNLOAD_ACCEPTED)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE+LEN_SIZE+REST_SIZE;

        temp = (char*) malloc(sizeof(char)*LEN_SIZE); //Here we save the nonce
        if (!temp) exit_with_failure("Malloc temp failed", 1);
        bufferSupp3 = (unsigned char*)malloc(sizeof(unsigned char)*REST_SIZE); // Here we save the rest value of the message
        if (!bufferSupp3) exit_with_failure("Malloc bufferSupp3 for nchunk failed", 1);

        sprintf(temp, "%d", *nonce); //nonce strring format
        memcpy(bufferSupp3, &*(bufferSupp2+strlen(DOWNLOAD_ACCEPTED)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE), REST_SIZE); //rest string format

        ret = build_msg_4(&msg_to_hash, DOWNLOAD_ACCEPTED, strlen(DOWNLOAD_ACCEPTED),\
                                        temp, LEN_SIZE, \
                                        bufferSupp1, LEN_SIZE,\
                                        bufferSupp3, REST_SIZE);
        if (ret == -1) exit_with_failure("Error during the building of the message...", 1);

        digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len);

        ret = CRYPTO_memcmp(digest, bufferSupp2, HASH_LEN);
        free_6(digest, temp, buffer, msg_to_hash, bufferSupp1, bufferSupp2);
        free(bufferSupp3);
        if (ret == -1)
        {
            printf("Wrong download accepted hash\n\n");
            ret = -1;
        }
        printf("The download request has been accepted!\n\n");

        //NOW WE CAN BEGIN DOWNLOAD THE CHUNKS
        f1 = fopen(filename, "w");
        for (i = 0; i < nchunk; i++)
        {
            //THE FORMAT OF THE CHUNK MESSAGE IS LEN_ENC, {CHUNK}K1, H(FILENAME, CHUNK, NONCE), iv
            msg_len = LEN_SIZE+BLANK_SPACE+BUF_LEN+BLANK_SPACE+HASH_LEN+BLANK_SPACE+IV_LEN;
            buffer = (unsigned char*) malloc(sizeof(unsigned char)*msg_len);
            if (!buffer) exit_with_failure("Malloc buffer failed", 1);

            ret = recv(sock, buffer, msg_len,0);
            if (ret == -1) exit_with_failure("Receive failed", 0);
            printf("Received the server's response.\n");

            iv = (unsigned char*) malloc(sizeof(unsigned char)*IV_LEN);
            if (!iv) exit_with_failure("Malloc iv failed", 1);
            memcpy(iv, &*(buffer+LEN_SIZE+BLANK_SPACE+BUF_LEN+BLANK_SPACE+HASH_LEN+BLANK_SPACE), IV_LEN); // iv

            //Now we take the encr_len and the encrypted part to decrypt it later
            bufferSupp1 = (unsigned char*) malloc(LEN_SIZE);
            if (!bufferSupp1) exit_with_failure("Malloc bufferSupp1 failed", 1);
            memcpy(bufferSupp1, buffer, LEN_SIZE); // Here we have len_enc
            encr_len = atoi((char*)bufferSupp1);
            bufferSupp2 = (unsigned char*)malloc(encr_len);
            if (!bufferSupp2) exit_with_failure("Malloc bufferSupp2 failed", 1);
            memcpy(bufferSupp2, &*(buffer+LEN_SIZE+BLANK_SPACE), encr_len);
            
            decrypt_AES_128_CBC(&plaintext, &plain_len, bufferSupp2, encr_len, iv, session_key1);

            free(bufferSupp1);

            //NOW WE SHOULD COMPARE THE TWO DIGEST TO AUTHENTICATE THE MESSAGE
            temp = (char*)malloc(sizeof(char)*LEN_SIZE);
            if (!temp) exit_with_failure("Error during the malloc of temp", 1);
            sprintf(temp, "%ls", nonce); //nonce string format
            bufferSupp3 = (unsigned char*)malloc(HASH_LEN*sizeof(unsigned char*));
            if (!bufferSupp3) exit_with_failure("Malloc bufferSupp3 failed", 1);
            memcpy(bufferSupp3, &*(buffer+LEN_SIZE+BLANK_SPACE+encr_len+BLANK_SPACE), HASH_LEN); //Here we have the hash to compare
            msg_to_hash_len = plain_len + BLANK_SPACE + LEN_SIZE + BLANK_SPACE + IV_LEN;

            ret = build_msg_3(&msg_to_hash, bufferSupp2, encr_len,\
                                            temp, LEN_SIZE,\
                                            iv, IV_LEN);
            if (ret == -1) exit_with_failure("Error during the building of the message", 1);

            digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len);

            ret = CRYPTO_memcmp(digest, bufferSupp3, HASH_LEN);
            if (ret == -1)
            {
                printf("Wrong download chunk hash\n\n");
                free_5(digest, temp, msg_to_hash, bufferSupp2, bufferSupp3);
                free_3(buffer, iv, plaintext);
                return -1;
            }

            free_5(digest, temp, msg_to_hash, bufferSupp2, bufferSupp3);
            free_2(buffer, iv);

            if (i == nchunk-1) for (j = 0; j < rest; j++) fprintf(f1, "%c", *(plaintext+j));
	        else for (j = 0; j < CHUNK_SIZE; j++) fprintf(f1, "%c", *(plaintext+j));
            free(plaintext);
            printf("We received correctly the chunk number %i\n", i);
        }
        fclose(f1);
        //Now we should send a message of download completed

        // Initialization of IV
        iv = (unsigned char*) malloc(sizeof(unsigned char)*IV_LEN);
        if (!iv) exit_with_failure("Malloc iv failed", 1);
        ret = RAND_poll(); // Seed OpenSSL PRNG
        if (ret != 1) exit_with_failure("RAND_poll failed\n", 0);
        ret = RAND_bytes((unsigned char*)&iv[0], IV_LEN);
        if (ret != 1) exit_with_failure("RAND_bytes failed\n", 0);

        // Create the hash
        msg_to_hash_len = strlen(DOWNLOAD_FINISHED)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE+IV_LEN;
        temp = (char*) malloc(sizeof(char)*LEN_SIZE);
        if (!temp) exit_with_failure("Malloc temp failed", 1);
        sprintf(temp, "%d", *nonce); // Now in temp there is the string version of the nonce

        ret = build_msg_3(&msg_to_hash, DOWNLOAD_FINISHED, strlen(DOWNLOAD_FINISHED),\
                                        temp, LEN_SIZE,\
                                        iv, IV_LEN);
        if (ret == -1) exit_with_failure("Error during the building of the message", 1);
        
        digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len);    
        if (digest_len != (unsigned int) HASH_LEN) exit_with_failure("Wrong digest len", 0);

        // Now that we have both the encryption and the digest of the hash we can initialize the buffer and send the message
        msg_len = strlen(DOWNLOAD_FINISHED)+BLANK_SPACE+HASH_LEN+BLANK_SPACE+IV_LEN;

        ret = build_msg_3(&buffer, DOWNLOAD_FINISHED, strlen(DOWNLOAD_FINISHED),\
                                   digest, HASH_LEN,\
                                   iv, IV_LEN);
        if (ret == -1) exit_with_failure("Error during the buildinf of the message", 1);
        // The message in the buffer now is: DOWNLOAD_FINISHED, hash, iv. We can send it now

        printf("I'm sending to the server the download request.\n");
        ret = send(sock, buffer, BUF_LEN, 0); 
        if (ret == -1) exit_with_failure("Send failed", 1);
        *nonce = *nonce+1; // message sent, nonce increased for the answer or for other messages

        free(temp);
        free(buffer);
        free(msg_to_hash);
        free(digest);
        free(msg_to_encr);
        free(encr_msg);
        free(iv);
        return 1;
    }
    else
    {
        //We don't know what we received
        printf("We received an uncorrect message from the server...\n\n");
        return -1;
    }
    return 1;
}



int uploadClient(int sock, char* username, char* filename)
{
    // We received a message with this format: download_request username filenameù
    char buffer[BUF_LEN];
    char bufferSupp1[BUF_LEN];
    char bufferSupp2[BUF_LEN];
    char bufferSupp3[BUF_LEN];
    char payload[CHUNK_SIZE+1];
    struct stat st;
    int i, j, nchunk, ret, start_payload, rest;
    FILE* fd;

    // SANIFICATION FILENAME
    if (chdir(MAIN_FOLDER_CLIENT) == -1)
    {
        printf("Main folder of the client unaccessible...\n\n");
        return -1;
    }
    if ((fd = fopen(filename, "r")) == NULL)
    {
        //printf("The inserted filename is %s", filename);
        printf("The file doesn't exist\n\n");
        return -1;
    }
    else
    {
        stat(filename, &st);
        nchunk = (st.st_size/CHUNK_SIZE)+1;
        rest = st.st_size - (nchunk-1)*CHUNK_SIZE; 

        memset(buffer, 0, strlen(buffer));
        memset(bufferSupp1, 0, strlen(bufferSupp1));
        memset(bufferSupp2, 0, strlen(bufferSupp2));
        //sprintf(buffer, "%s %s %s %i %d", UPLOAD_REQUEST, username, filename, nchunk, rest);

        // ENCRYPT THE BUFFER
        printf("I'm sending %s\n\n", buffer);
        ret = send(sock, buffer, strlen(buffer), 0);
        if (ret == -1)
        {
            printf("Send operation gone bad!\n\n");
            exit(1);
        }

        memset(buffer, 0, strlen(buffer));
        memset(bufferSupp1, 0, strlen(bufferSupp1));
        memset(bufferSupp2, 0, strlen(bufferSupp2));
        memset(bufferSupp3, 0, strlen(bufferSupp3));
        ret = recv(sock, buffer, BUF_LEN, 0);
        if (ret == -1)
        {
            printf("Receive operation gone bad!\n\n");
            exit(1);
        }
        printf("I received %s from the server\n\n", buffer);

        // DECRYPT THE BUFFER

        sscanf(buffer, "%s %s %s", bufferSupp1, bufferSupp2, bufferSupp3);
        if (strcmp(bufferSupp1, UPLOAD_ACCEPTED) != 0)
        {
            printf("Upload operation denied by the server!\n\n");
            return -1;
        }
    }
    fd = fopen(filename, "r");
    printf("I'm starting the upload operation...\n\n");
    // We should add another check about the fact that the file exists or not
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
        sprintf(bufferSupp1, "%s %s ", UPLOAD_CHUNK, filename); //Format of the message sent is: type_mex filename payload
        start_payload = MEX_TYPE_LEN + strlen(filename) + 2;
	if (i == nchunk-1) for (j = 0; j < rest; j++) bufferSupp1[start_payload+j] = payload[j];
	else for (j = 0; j < CHUNK_SIZE; j++) bufferSupp1[start_payload+j] = payload[j];
        
        printf("We are sending %s\n\n", bufferSupp1);

        //ENCRYPT THE MESSAGE SENT

        ret = send(sock, bufferSupp1, BUF_LEN, 0);
        if (ret == -1)
        {
            printf("Send operation gone bad\n");
            // Change this later to manage properly the session
            exit(1);
        }
    }
    memset(buffer, 0, strlen(buffer));
    ret = recv(sock, buffer, BUF_LEN, 0);
    if (ret == -1)
    {
        printf("Send operation gone bad!\n\n");
        exit(1);
    }
    printf("I'm receiving %s\n\n", buffer);

    // DECRYPT THE BUFFER

    sscanf(buffer, "%s %s %s", bufferSupp1, bufferSupp2, bufferSupp3);

    if (!(strcmp(bufferSupp1, UPLOAD_FINISHED)==0) || !(strcmp(bufferSupp2, username)==0) || !(strcmp(bufferSupp3, filename)==0))
    {
        printf("Error in the last message sent: message of end upload\n\n");
        return -1;
    }
    printf("We have completed successfully the upload operation!\n\n");

    return 1;
}




int shareClient(int sock, char* username, char* filename, char* peername)
{
    char buffer[BUF_LEN];
    char bufferSupp1[BUF_LEN];
    char bufferSupp2[BUF_LEN];
    char bufferSupp3[BUF_LEN];
    int ret;

    memset(buffer, 0, strlen(buffer));
    memset(bufferSupp1, 0, strlen(bufferSupp1));
    memset(bufferSupp2, 0, strlen(bufferSupp2));
    memset(bufferSupp3, 0, strlen(bufferSupp3));

    sprintf(buffer, "%s %s %s %s", SHARE_REQUEST, username, peername, filename);

    printf("I'm sending %s to the server\n\n", buffer);

    // ENCRYPT THE BUFFER

    ret = send(sock, buffer, strlen(buffer), 0);
    if (ret == -1)
    {
        printf("Error during send operation!\n\n");
        return -1;
    }

    memset(buffer, 0, strlen(buffer));
    memset(bufferSupp1, 0, strlen(bufferSupp1));
    memset(bufferSupp2, 0, strlen(bufferSupp2));
    memset(bufferSupp3, 0, strlen(bufferSupp3));
    ret = recv(sock, buffer, BUF_LEN,0);
    if (ret == -1)
    {
        printf("Error during receive operation!\n\n");
        return -1;
    }

    // DECRYPT THE BUFFER

    sscanf(buffer, "%s %s %s", bufferSupp1, bufferSupp2, bufferSupp3);
    if (strcmp(bufferSupp1, SHARE_ACCEPTED) == 0)
    {
        printf("Share operation accepted by the server!\n\n");
        return 1;
    }
    else printf("Share operation denied by the server!\n\n");
    return -1;
}


int shareReceivedClient(int sd, char* rec_mex)
{
    int ret;
    char* p;
    char buffer[BUF_LEN];
    char bufferSupp1[BUF_LEN];
    char bufferSupp2[BUF_LEN];
    char bufferSupp3[BUF_LEN];
    char filename[MAX_LEN_FILENAME];
    char sharername[MAX_LEN_USERNAME];

    //DECRYPT REC_MEX, SANITIZE THE INPUT

    sscanf(rec_mex, "%s %s %s", bufferSupp1, sharername, filename);
    if (strcmp(bufferSupp1, SHARE_PERMISSION) != 0)
    {
        //printf("The mex type is incorrect!\n\n");
        return -1;
    }
    printf("We received a share request: the filename is %s from peer %s.\n Do you accept the share operation? [Y/N]\n\n", filename, sharername);
    //sscanf(buffer, "%s", stdin); // REMEMBER TO CHANGE PROPERLY THIS COMMAND
    while((strcmp(buffer, "Y")!=0) && (strcmp(buffer, "N")!=0))
    {
        if (fgets(buffer, BUF_LEN, stdin) == NULL)
        {
            printf("Some problem during the get function...\n\n");
            return -1;
        }
        p = strchr(buffer, '\n');
        if(p) {*p = '\0';}

        printf("Given in input %s", buffer);
        printf("\n"); 
        if(strcmp(buffer, "Y") == 0)
        {
            memset(buffer, 0, strlen(buffer));
            memset(bufferSupp1, 0, strlen(bufferSupp1));
            memset(bufferSupp2, 0, strlen(bufferSupp2));
            memset(bufferSupp2, 0, strlen(bufferSupp3));
            sprintf(buffer, "%s %s %s", SHARE_ACCEPTED, sharername, filename);
            ret = send(sd, buffer, strlen(buffer), 0);
            if (ret == -1)
            {
                printf("Send operation gone bad.\n\n");
                return -1;
            }
            return 1;
        }
        else if (strcmp(buffer, "N") == 0)
        {
            //test comment remove later not important just to test if git works for francesco
            memset(buffer, 0, strlen(buffer));
            memset(bufferSupp1, 0, strlen(bufferSupp1));
            memset(bufferSupp2, 0, strlen(bufferSupp2));
            memset(bufferSupp2, 0, strlen(bufferSupp3));
            sprintf(buffer, "%s %s %s", SHARE_DENIED, sharername, filename);
            ret = send(sd, buffer, strlen(buffer), 0);
            if (ret == -1)
            {
                printf("Send operation gone bad.\n\n");
                return -1;
            }
            return 1;
        }
        else printf("Given a bad input. Retry!\n\n");
        fflush(stdin);
    }

    return -1;
}