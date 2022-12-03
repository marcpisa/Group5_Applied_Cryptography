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

int loginServer(int sd, char* rec_mex)
{
    unsigned int nonce_cs = 0;
    
    unsigned char* buffer;
    unsigned char* msg_to_sign;

    char* path_pubkey = "../dh_server_pubkey.pem";
    char* path_cert_rsa = "cert.pem";
    char* path_rsa_key = "rsa_prvkey.pem";
    char* path_documents = "documents/";
    char* path_temp;
    
    int ret;
    int msg_len;
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
    EVP_PKEY* my_prvkey = NULL;
    EVP_PKEY* peer_pubkey;
    
    unsigned char* pubkey_byte = NULL;
    unsigned char* K;
    
    int pubkey_len = 0;
    
    unsigned int len_username;

    char funcBuff[BUF_LEN];
    char funcSupp1[BUF_LEN];

    unsigned char* session_key1;
    unsigned char* session_key2;

    FILE* fd_1;
    int port_client;
    int msg_to_hash_len;
    unsigned char* msg_to_hash;
    unsigned char* digest;
    unsigned int plain_len;

    char nonce_buff[BUF_LEN+1];
    char username[MAX_LEN_USERNAME+1];
    char path_cert_client_rsa[5+MAX_LEN_USERNAME+4+1];
    unsigned char pk_buff[DH_PUBKEY_SIZE];
    unsigned char sgn_buff[SIGN_LEN];
    char n_buff[LEN_SIZE];
    char t_buff[TYPE_LEN];
    unsigned char h_buff[HASH_LEN];
    unsigned char iv_buff[IV_LEN];
    char p_buff[PORT_SIZE];
    unsigned char* p;
    char* t ;
    unsigned char* payload;
    int p_len;
    unsigned char* plaintext;

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
    pubkey_byte = gen_dh_keys(path_pubkey, &my_prvkey, &pubkey_len);
    if (pubkey_len != DH_PUBKEY_SIZE) exit_with_failure("Wrong pubkey len", 0);



    /* ---- Parse the first message (login request message + username + DH pubkey) ---- */
    t = rec_mex;
    t += strlen(LOGIN_REQUEST)+BLANK_SPACE;

    // Parse and sanitize username
    if((len_username = str_ssplit((unsigned char*) t, DELIM)) > MAX_LEN_USERNAME)
    {
        printf("Username too long.\n");
        return -1;
    }
    memset(username, 0, len_username);
    memcpy(username, t, len_username); // username
    memcpy(username+len_username, "\0", 1);
    t += len_username+BLANK_SPACE;

    if (!username_sanitization(username))
    {
        printf("Username sanitization fails.\n");
        return -1;
    } 

    // Move to the database/username folder of the server
    ret = chdir(MAIN_FOLDER_SERVER);
    if (ret == -1)
    {
        printf("No such directory MAIN_FOLDER_SERVER.\n");
        return -1;
    }
    ret = chdir(username);
    if (ret == -1) 
    {
        printf("User folder doesn't exists...\n");
        return -1;
    }


    // Parse pubkey, obtain the established key and the session keys
    memset(pk_buff, 0, DH_PUBKEY_SIZE);
    memcpy(pk_buff, t, pubkey_len); // dh pubkey

    peer_pubkey = pubkey_to_PKEY(pk_buff, pubkey_len);
    K = key_derivation(my_prvkey, peer_pubkey, &K_len);
    issue_session_keys(K, K_len, &session_key1, &session_key2);
    

    // Retrieve the client pubkey (from the client cert., already owned by the server)
    memset(path_cert_client_rsa, 0, 5+MAX_LEN_USERNAME+4+1);
    memcpy(path_cert_client_rsa, "\0", 1);
    strcat(path_cert_client_rsa, "cert_");
    strncat(path_cert_client_rsa, username, len_username);
    strcat(path_cert_client_rsa, ".pem");
    pub_rsa_client = get_client_pubkey(path_cert_client_rsa);
    
    //printf("#1 Login request message is correct.\n");
    
    EVP_PKEY_free(my_prvkey);
    EVP_PKEY_free(peer_pubkey);




    /* --- Send response (DH pubkey, signature, len. cert. and cert.) --- */
    // Prepare the digital signature (g^a || g^b)
    msg_to_sign_len = (pubkey_len*2)+BLANK_SPACE;
    msg_to_sign = (unsigned char*) malloc(msg_to_sign_len*sizeof(unsigned char));
    if (!msg_to_sign) exit_with_failure("Malloc msg_to_sign failed", 0);

    p = msg_to_sign;
    memcpy(p, pk_buff, pubkey_len);
    p += pubkey_len;
    memcpy(p, " ", BLANK_SPACE);
    p += BLANK_SPACE;
    memcpy(p, pubkey_byte, pubkey_len);

    ret = chdir("../../src");
    if (ret == -1) exit_with_failure("No such directory.\n", 0);
    signature = sign_msg(path_rsa_key, msg_to_sign, msg_to_sign_len, &signature_len, 1);

    // Serialize the certificate
    cert_byte = read_cert(path_cert_rsa, &cert_len);

    // Come back to the user directory
    ret = chdir("../database/");
    if (ret == -1) exit_with_failure("No such directory.\n", 0);
    ret = chdir(username);
    if (ret == -1) exit_with_failure("No such directory.\n", 0);

    // Compose the message
    memset(n_buff, 0, LEN_SIZE);
    sprintf(n_buff, "%d", cert_len);
    
    msg_len = pubkey_len+SIGN_LEN+LEN_SIZE+cert_len+(BLANK_SPACE*3);
    buffer = (unsigned char*) malloc(msg_len*sizeof(unsigned char));
    if (!buffer) exit_with_failure("Malloc buffer failed", 0);

    p = buffer;
    memcpy(p, pubkey_byte, pubkey_len);
    p += pubkey_len;
    memcpy(p, " ", BLANK_SPACE);
    p += BLANK_SPACE;
    memcpy(p, signature, SIGN_LEN);
    p += SIGN_LEN;
    memcpy(p, " ", BLANK_SPACE);
    p += BLANK_SPACE;
    memcpy(p, n_buff, LEN_SIZE);
    p += LEN_SIZE;
    memcpy(p, " ", BLANK_SPACE);
    p += BLANK_SPACE;
    memcpy(p, cert_byte, cert_len);
    p += cert_len;

    ret = send(sd, buffer, msg_len, 0); 

    free_n(4, buffer, pubkey_byte, cert_byte, signature);
    if (ret == -1)
    {
        free_n(4, K, msg_to_sign, session_key1, session_key2);
        EVP_PKEY_free(pub_rsa_client);
        printf("Send failed.\n");
        return -1;
    } 
    //else printf("#2 Message sent to client.\n");




    /* Parse the client message and verify the fields */
    buffer = (unsigned char*) malloc(sizeof(unsigned char)*BUF_LEN);
    if (!buffer) exit_with_failure("Malloc buffer failed", 1);
 
    ret = recv(sd, buffer, BUF_LEN, 0);
    if (ret == -1) 
    {
        free_n(5, buffer, K, msg_to_sign, session_key1, session_key2);
        EVP_PKEY_free(pub_rsa_client);
        printf("Receive failed.\n");
        return -1;
    } 
    //else printf("#3 Response received.\n");
 
    // Parse signature
    memset(sgn_buff, 0, SIGN_LEN);
    memcpy(sgn_buff, buffer, SIGN_LEN);
    //memcpy(&*(bufferSupp1+SIGN_LEN), "\0", 1);

    // Verify signature
    ret = verify_signature(msg_to_sign, msg_to_sign_len, sgn_buff, SIGN_LEN, pub_rsa_client);
    
    free_n(3, buffer, msg_to_sign, K);
    EVP_PKEY_free(pub_rsa_client);
    if (ret != 1) 
    {
        free_n(2, session_key1, session_key2);
        printf("Signature verification failed.\n");
        return -1;
    }


       

    /* ---- Receive the client's port ---- */
    buffer = (unsigned char*) malloc(BUF_LEN*sizeof(unsigned char));
    if (!buffer) 
    {
       printf("Malloc buffer failed.\n");
       return -1; 
    } 

    ret = recv(sd, buffer, BUF_LEN, 0);
    if (ret == -1)
    {
        free_n(3, buffer, session_key1, session_key2);
        printf("Receive failed...\n");
        return -1;
    }
    //else printf("#4 Port received by the client.\n");


    // Parse the message
    memset(t_buff, 0, TYPE_LEN);
    memset(h_buff, 0, HASH_LEN);
    memset(iv_buff, 0, IV_LEN);
    p_len = 0;
    ret = parse_msg(buffer, ret, t_buff, &p_len, &payload, h_buff, iv_buff);
    
    free(buffer);
    if (ret == -1)
    {
        free_n(2, session_key1, session_key2);
        printf("Problem parsing the message...\n");
        return -1;
    }


    // Check the hash
    msg_to_hash_len = concat_5(&msg_to_hash, payload, p_len, iv_buff, IV_LEN, NULL, 1, NULL, 1, NULL, 1);
    if (msg_to_hash_len == -1)
    {
        free_n(3, payload, session_key1, session_key2);
        printf("Problem building hash...\n");
        return -1;
    }

    digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, NULL); 
    ret = CRYPTO_memcmp(digest, h_buff, HASH_LEN);
    
    free_n(2, digest, msg_to_hash);
    if (ret != 0)
    {
        free_n(3, payload, session_key1, session_key2);
        printf("Checking hash failed.\n");
        return -1;
    }


    // Decrypt the message and save the port
    decrypt_AES_128_CBC(&plaintext, &plain_len, payload, p_len, iv_buff, session_key1); 
    port_client = atoi((char*) plaintext);
    free_n(2, plaintext, payload);


    // Serialize session_key1, session_key2 and port
    ret = chdir("..");
    if (ret == -1) 
    {
        free_n(2, session_key1, session_key2);
        printf("Problem changing directory...\n");
        return -1;
    }
    ret = chdir("info");
    if (ret == -1) 
    {
        free_n(2, session_key1, session_key2);
        printf("Problem moving directory into info...\n");
        return -1;
    }

    path_temp = (char*) malloc((len_username+4+1)*sizeof(char));
    if (!path_temp)
    {
        printf("Malloc path_temp failed.\n");
        return -1;
    }
    memcpy(path_temp, "\0", 1);
    strncat(path_temp, username, len_username);
    strcat(path_temp, ".txt\0");

    fd_1 = fopen(path_temp, "w");
    if (!fd_1)
    {
        printf("Can't open path_temp...\n");
        free_n(3, path_temp, session_key1, session_key2);
        return -1;
    }

    // Write port, session_key1 and session_key2 to file
    memset(p_buff, 0, PORT_SIZE);
    sprintf(p_buff, "%d", port_client);
    ret = fwrite(p_buff, sizeof(char), PORT_SIZE, fd_1);
    if (ret == -1) 
    {
        printf("Fwrite failed.\n");
        free_n(3, path_temp, session_key1, session_key2);
        return -1;
    }
    ret = fwrite(session_key1, sizeof(unsigned char), 16, fd_1);
    if (ret == -1) 
    {
        printf("Fwrite failed.\n");
        free_n(3, path_temp, session_key1, session_key2);
        return -1;
    }
    ret = fwrite(session_key2, sizeof(unsigned char), 16, fd_1);
    if (ret == -1) 
    {
        printf("Fwrite failed.\n");
        free_n(3, path_temp, session_key1, session_key2);
        return -1; 
    }
    memset(nonce_buff, 0, LEN_SIZE);
    sprintf(nonce_buff, "0");
    ret = fwrite(nonce_buff, sizeof(char), LEN_SIZE, fd_1);
    if (ret == -1)
    {
        printf("Fwrite failed.\n");
        free_n(3, path_temp, session_key1, session_key2);
    }

    free(path_temp);
    fclose(fd_1);

    // Going back to the main directory
    ret = chdir("..");
    if (ret == -1) 
    {
        free_n(2, session_key1, session_key2);
        printf("Problem moving back to parent directory...\n");
        return -1; 
    }
    ret = chdir(username);
    if (ret == -1) 
    {
        free_n(2, session_key1, session_key2);
        printf("Problem moving into username directory...\n");
        return -1; 
    }


    // FUNCTIONAL PART
    // Now that we have the cryptographic elements to have a secure communication with the client we are able to receive function messages
    // Here we are at database/username/
    printf("Login Request Managed. Client connected!\n");
    

    //printf("Now the buffer contains %s\n\n", funcBuff);
    while (1)
    {
        memset(funcBuff, 0, BUF_LEN);
        ret = recv(sd, funcBuff, BUF_LEN, 0);
        if (ret < 0)
        {
            perror("Error during recv operation: ");
            break;
        }
        // We check the first keyword to understand what the Client wants us to do
        memset(funcSupp1, 0, BUF_LEN);
        memcpy(funcSupp1, funcBuff, str_ssplit((unsigned char*) funcBuff, DELIM));


        // ************ LOGIN REQUEST MANAGER ***********
        if (strcmp(funcSupp1, LOGIN_REQUEST) == 0)
        {
            printf("\nLogin request received, but client already logged in. Something bad happened...\n\n");
        }


        //************ LOGOUT REQUEST MANAGER ************
        else if (strcmp(funcSupp1, LOGOUT_REQUEST) == 0)
        {
            printf("\nA logout request has come up...\n");
            // LOGOUT MANAGER: SERVER SIDE
                            
            ret = logoutServer(funcBuff, &nonce_cs, session_key2);
            if (ret == -1) printf("Something bad happened during the management of the client logout request...\n\n");
            else
            {
                printf("End of logout request management!\n");
                ret = remove_info_file(username);
                if (ret == -1) printf("Problems removing the info file of the user\n\n");
                break;
            }
        }


        // ************* LIST REQUEST MANAGER ***************
        else if (strcmp(funcSupp1, LIST_REQUEST) == 0)
        {
            printf("\nA list request has come up.\n");
            // LIST MANAGER: SERVER SIDE
        
            ret = listServer(sd, funcBuff, path_documents, &nonce_cs, session_key1, session_key2);
            if (ret == -1)
            {
                printf("Something bad happened during the management of the client list request...\n\n");
                ret = remove_info_file(username);
                if (ret == -1) printf("Problems removing the info file of the user\n\n");
                break;
            }
            else printf("End of list request management!\n");
        }


        //*************** RENAME REQUEST MANAGER *****************
        else if (strcmp(funcSupp1, RENAME_REQUEST) == 0)
        {
            printf("\nA rename request has come up.\n");
            // RENAME MANAGER: SERVER SIDE
                            
            ret = renameServer(sd, funcBuff, &nonce_cs, session_key1, session_key2);
            if (ret == -1)
            {
                printf("Something bad happened during the management of the client rename request...\n\n");
                ret = remove_info_file(username);
                if (ret == -1) printf("Problems removing the info file of the user\n\n");
                break;
            }
            else printf("End of rename request management!\n");
        }


        // **************** DELETE REQUEST MANAGER ******************
        else if (strcmp(funcSupp1, DELETE_REQUEST) == 0)
        {
            printf("\nA delete request has come up.\n");
            // DELETE MANAGER: SERVER SIDE
                            
            ret = deleteServer(sd, funcBuff, &nonce_cs, session_key1, session_key2);
            if (ret == -1)
            {
                printf("Something bad happened during the management of the client delete request...\n\n");
                ret = remove_info_file(username);
                if (ret == -1) printf("Problems removing the info file of the user\n\n");
                break;
            } else printf("End of delete request management!\n");
        }

        
        // *************** DOWNLOAD REQUEST MANAGER ****************
        else if (strcmp(funcSupp1, DOWNLOAD_REQUEST) == 0)
        {
            printf("\nA download request has come up.\n");

            // DOWNLOAD MANAGER: SERVER SIDE
                            
            ret = downloadServer(sd, funcBuff, &nonce_cs, session_key1, session_key2);
            if (ret == -1)
            {
                printf("Something bad happened during the management of the client download request...\n\n");
                ret = remove_info_file(username);
                if (ret == -1) printf("Problems removing the info file of the user\n\n");
                break;
            } 
            else printf("End of download request management!\n");
        }


        // *************** UPLOAD REQUEST MANAGER ***************
        else if (strcmp(funcSupp1, UPLOAD_REQUEST) == 0)
        {
            printf("\nAn upload request has come up.\n");
            // UPLOAD MANAGER: SERVER SIDE
                            
            ret = uploadServer(sd, funcBuff, &nonce_cs, session_key1, session_key2);
            if (ret == -1)
            {
                printf("Something bad happened during the management of the client upload request...\n\n");
                ret = remove_info_file(username);
                if (ret == -1) printf("Problems removing the info file of the user\n\n");
                break;
            }
            else printf("End of upload request management!\n\n");
        }


        // **************** SHARE REQUEST MANAGER ****************
        else if (strcmp(funcSupp1, SHARE_REQUEST) == 0)
        {
            printf("\nA share request has come up.\n");
            // SHARE MANAGER: SERVER SIDE

            ret = shareServer(sd, funcBuff, username, &nonce_cs, session_key1, session_key2);            
            if (ret == -1)
            {
                printf("Something bad happened during the management of the client share request...\n\n");
                ret = remove_info_file(username);
                if (ret == -1) printf("Problems removing the info file of the user\n\n");
                break;
            }
            else printf("End of share request management!\n"); 
        }

        else printf("Unknown type of request by the Client...\n");  
    }

    // Clear session keys from the file
    // ......

    free_n(2, session_key1, session_key2);
    close(sd);
    
    return 1;
}

int logoutServer(char* rec_mex, unsigned int* nonce, unsigned char* session_key2)
{
    unsigned int digest_len;
    int ret;
    int msg_to_hash_len;

    size_t offset;

    unsigned char* temp;
    unsigned char* bufferSupp2;
    unsigned char* bufferSupp3;
    unsigned char* msg_to_hash;
    unsigned char* digest; 


    /* ---- Parse the first client message (request + hash + iv) ---- */
    temp = (unsigned char*) malloc(sizeof(char)*LEN_SIZE);
    if (!temp) exit_with_failure("Malloc temp failed", 1);   
    bufferSupp2 = (unsigned char*) malloc(sizeof(unsigned char)*HASH_LEN);   
    if (!bufferSupp2) exit_with_failure("Malloc bufferSupp2 failed", 1);
    bufferSupp3 = (unsigned char*) malloc(sizeof(unsigned char)*IV_LEN);   
    if (!bufferSupp3) exit_with_failure("Malloc bufferSupp3 failed", 1);

    offset = strlen(LOGOUT_REQUEST)+BLANK_SPACE;

    memcpy(bufferSupp2, &*((unsigned char*) rec_mex+offset), HASH_LEN); // hash
    offset += HASH_LEN+BLANK_SPACE;
    
    memcpy(bufferSupp3, &*((unsigned char*) rec_mex+offset), IV_LEN); // iv


    // Check hash correctness
    sprintf((char*)temp, "%u", *nonce);
    msg_to_hash_len = build_msg_3(&msg_to_hash, LOGOUT_REQUEST, strlen(LOGOUT_REQUEST), \
                                                bufferSupp3, IV_LEN, \
                                                temp, LEN_SIZE);
    if (msg_to_hash_len == -1) exit_with_failure("Something bad happened building the hash message...", 0);

    digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len);   
    ret = CRYPTO_memcmp(digest, bufferSupp2, HASH_LEN);
    if (ret != 0) 
    {
        printf("Wrong logout request hash.\n");
        return 1;
    }

    free_5(bufferSupp2, bufferSupp3, temp, digest, msg_to_hash);
    return 1;
}

int listServer(int sd, char* rec_mex, char* path_documents, unsigned int* nonce, unsigned char* session_key1, unsigned char* session_key2)
{
    DIR* d;
    struct dirent *files;

    unsigned char* iv;
    int num_file;
    int tot_num_file;
    int len_filename;

    unsigned char* ciphertext;
    int cipher_len;
    
    unsigned char* msg_to_hash;
    unsigned char* digest;
    unsigned int digest_len;
    int msg_to_hash_len;
    
    size_t offset;
    size_t old_offset;

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


    /* ---- Parse the list request (req., hash(req, iv, nonce), iv) ---- */
    bufferSupp1 = (unsigned char*) malloc(HASH_LEN*sizeof(unsigned char));
    if (!bufferSupp1) exit_with_failure("Malloc bufferSupp1 failed", 1);

    // Parsing
    old_offset = strlen(LIST_REQUEST)+BLANK_SPACE;
    memcpy(bufferSupp1, &*(rec_mex+old_offset), HASH_LEN); // hash
    old_offset += HASH_LEN+BLANK_SPACE;
    memcpy(iv, &*(rec_mex+old_offset), IV_LEN); // iv

    // Compare the hash
    temp = (char*) malloc(sizeof(char)*LEN_SIZE);
    if (!temp) exit_with_failure("Malloc temp failed", 1);

    sprintf((char*)temp, "%u", *nonce);
    msg_to_hash_len = build_msg_3(&msg_to_hash, LIST_REQUEST, strlen(LIST_REQUEST),\
                                                iv, IV_LEN,\
                                                temp, LEN_SIZE);
    if (msg_to_hash_len == -1) exit_with_failure("Error during the building of the message", 1);
    
    digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len);

    ret = CRYPTO_memcmp(digest, bufferSupp1, HASH_LEN);
    
    free_5(iv, bufferSupp1, msg_to_hash, digest, temp);
    
    if (ret != 0) // If the hash comparison failed
    {
        printf("Wrong list request hash.\n");
        return 1;
    }

    //printf("List request message parsed successfully\n");
    *nonce += 1;




    /* ---- Prepare the list of filenames (num_file, len. encr., encr. list, hash(num_file, encr. list, iv, nonce), iv) ---- */
    offset = 0;
    len_filename = 0;
    num_file = 0;
    tot_num_file = 0;

    while (num_file != -1) {
        // Build the filenames' list
        bufferSupp1 = (unsigned char*) malloc((CHUNK_SIZE+1)*sizeof(unsigned char));
        if (!bufferSupp1) exit_with_failure("Malloc bufferSupp1 failed", 1);

        num_file = 0;
        d = opendir(path_documents);   
        if(d)
        {
            // If this is the second list of filenames, reset the pointer to the prev. position
            for (int i = 0; i < tot_num_file; i++) files = readdir(d);

            while((files = readdir(d)) != NULL)
            {
                len_filename = strlen(files->d_name);
                // The filename fits the list length
                if ((offset+len_filename+BLANK_SPACE) <= CHUNK_SIZE)
                { 
                    memcpy(&*(bufferSupp1+offset), files->d_name, len_filename);
                    offset += len_filename;
                    memcpy(&*(bufferSupp1+offset), " ", BLANK_SPACE);
                    offset += BLANK_SPACE;
                    num_file += 1;
                }
            }

            if (offset == 0)
            {
                memcpy(bufferSupp1, "empty", strlen("empty"));
                offset += strlen("empty");
            }
            memcpy(&*(bufferSupp1+offset), "\0", 1);
            offset += 1;
            tot_num_file += num_file;
        }
        else exit_with_failure("Impossible to open path_documents", 1);     
        closedir(d);

        // Encrypt the list
        iv = (unsigned char*) malloc(sizeof(unsigned char)*IV_LEN);
        if (!iv) exit_with_failure("Malloc iv failed", 1);
        ret = RAND_bytes(iv, IV_LEN);
        if (ret != 1) exit_with_failure("RAND_bytes failed\n", 0);
        encrypt_AES_128_CBC(&ciphertext, &cipher_len, bufferSupp1, offset, iv, session_key1);

        free(bufferSupp1);
        offset = 0;

        // Prepare the hash
        bufferSupp1 = (unsigned char*) malloc(sizeof(unsigned char)*LEN_SIZE);
        if (!bufferSupp1) exit_with_failure("Malloc bufferSupp1 failed", 1);
        temp = (char*) malloc(sizeof(char)*LEN_SIZE);
        if (!temp) exit_with_failure("Malloc temp failed", 1);
        
        sprintf(temp, "%d", num_file);
        sprintf((char*)bufferSupp1, "%u", *nonce);
        msg_to_hash_len = build_msg_4(&msg_to_hash, temp, LEN_SIZE,\
                                                    ciphertext, cipher_len,\
                                                    iv, IV_LEN,\
                                                    bufferSupp1, LEN_SIZE);
        
        if (msg_to_hash_len == -1) exit_with_failure("Error during the building of the message", 1);

        digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len);  

        // Build the message
        sprintf(temp, "%d", num_file);
        sprintf((char*)bufferSupp1, "%d", cipher_len);
        msg_len = build_msg_5(&buffer, temp, LEN_SIZE,\
                                       bufferSupp1, LEN_SIZE,\
                                       ciphertext, cipher_len,\
                                       digest, HASH_LEN,\
                                       iv, IV_LEN);
        if (msg_len == -1) exit_with_failure("Error during the building of the message", 1);

        if (num_file != 0) printf("I'm sending to the client a chunk of the filenames list\n"); 
        ret = send(sd, buffer, BUF_LEN, 0); 
        
        free_5(temp, bufferSupp1, buffer, ciphertext, digest);
        free_2(msg_to_hash, iv);
        
        if (ret == -1) 
        {
            printf("Send failed.\n");
            return -1;
        }
        
        *nonce += 1;

        


        /* ---- Check if the client succeed or failed ---- */
        buffer = (unsigned char*) malloc(sizeof(unsigned char)*BUF_LEN);
        if (!buffer) exit_with_failure("Malloc buffer failed", 1);

        ret = recv(sd, buffer, BUF_LEN,0);
        if (ret == -1)
        {
            free(buffer);
            printf("Receive failed.\n");
            return -1;
        }

        bufferSupp1 = (unsigned char*) malloc((strlen(LIST_DENIED)+1)*sizeof(unsigned char));
        if (!bufferSupp1) exit_with_failure("Malloc bufferSupp1 failed", 1);
        memcpy(bufferSupp1, buffer, strlen(LIST_DENIED)); // denied or accepted same length
        memcpy(&*(bufferSupp1+strlen(LIST_DENIED)), "\0", 1);

        if (strcmp((char*) bufferSupp1, LIST_DENIED) == 0)
        {
            ret = check_reqden_msg(LIST_DENIED, buffer, *nonce, session_key1, session_key2);
            free_2(bufferSupp1, buffer);
            
            if (ret == -1) 
            {
                printf("The check of the hash is gone bad...\n");
                return 1;
            }
            else 
            {
                printf("Received list denied message.\n");
                *nonce += 1;
                return 1;
            }
        }
        else if (strcmp((char*) bufferSupp1, LIST_ACCEPTED) == 0)
        {
            ret = check_reqacc_msg(LIST_ACCEPTED, buffer, *nonce, session_key2);
            free_2(buffer, bufferSupp1);

            if (ret == -1)
            {
                printf("The check of the hash is gone bad\n");
                return 1;
            } 
            if (num_file == 0) num_file = -1;
            *nonce += 1;
        }
        else
        {
            printf("We don't know what the client said...\n\n");
            free_2(bufferSupp1, buffer);
            return 1;
        }
    }

    return 1;
}

int renameServer(int sd, char* rec_mex, unsigned int* nonce, unsigned char* session_key1, unsigned char* session_key2)
{
    int ret;
    size_t old_offset;
    size_t offset;
    unsigned char* iv;

    unsigned int encr_len;
    unsigned int plain_len;
    unsigned char* plaintext;

    int msg_to_hash_len;
    unsigned int digest_len;
    unsigned char* msg_to_hash;
    unsigned char* digest;

    char* temp;
    char* temp2;
    unsigned char* bufferSupp1;
    unsigned char* bufferSupp2;

    char* filename;
    int len_fn;
    char* new_filename;
    int len_newfn;

    // Seed for the IV
    iv = (unsigned char*) malloc(sizeof(unsigned char)*IV_LEN);
    if (!iv) exit_with_failure("Malloc iv failed", 1);
    ret = RAND_poll(); // Seed OpenSSL PRNG
    if (ret != 1) exit_with_failure("RAND_poll failed\n", 0);




    /* ---- Parse first message (request, len encr., encr(name + new_name), hash(request, encr, iv, nonce), iv) ---- */
    bufferSupp2 = (unsigned char*) malloc(HASH_LEN*sizeof(unsigned char));
    if (!bufferSupp2) exit_with_failure("Malloc bufferSupp2 failed", 1);
    temp = (char*) malloc(LEN_SIZE*sizeof(char));
    if (!temp) exit_with_failure("Malloc temp failed", 1);
    temp2 = (char*) malloc(LEN_SIZE*sizeof(char));
    if (!temp2) exit_with_failure("Malloc temp2 failed", 1);
    
    offset = strlen(RENAME_REQUEST)+BLANK_SPACE;
    memcpy(temp, &*(rec_mex+offset), LEN_SIZE); // len. encr.
    offset += LEN_SIZE+BLANK_SPACE;
    encr_len = atoi((char*)temp);

    bufferSupp1 = (unsigned char*) malloc(encr_len*sizeof(unsigned char));
    if (!bufferSupp1) exit_with_failure("Malloc bufferSupp1 failed", 1);

    memcpy(bufferSupp1, &*(rec_mex+offset), encr_len); // encr
    offset += encr_len+BLANK_SPACE;

    memcpy(bufferSupp2, &*(rec_mex+offset), HASH_LEN); // hash
    offset += HASH_LEN+BLANK_SPACE;
    
    memcpy(iv, &*(rec_mex+offset), IV_LEN); // iv
    
    // Check hash
    sprintf(temp2, "%u", *nonce);
    msg_to_hash_len= build_msg_4(&msg_to_hash, RENAME_REQUEST, strlen(RENAME_REQUEST),\
                                    bufferSupp1, encr_len,\
                                    iv, IV_LEN,\
                                    temp2, LEN_SIZE);
    if (msg_to_hash_len == -1) exit_with_failure("Error during the building of the message", 1);

    // If hash correct, decrypt
    digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len);

    ret = CRYPTO_memcmp(digest, bufferSupp2, HASH_LEN);
    if (ret != 0) 
    {
        printf("Wrong rename request hash.\n");
        free_6(bufferSupp1, bufferSupp2, temp, iv, msg_to_hash, digest);
        free(temp2);
        return 1;
    }

    *nonce += 1;

    decrypt_AES_128_CBC(&plaintext, &plain_len, bufferSupp1, encr_len, iv, session_key1);

    free_6(bufferSupp1, bufferSupp2, temp, iv, msg_to_hash, digest);
    free(temp2);

    // Obtain the filenames from the plaintext and sanitize them
    // Filename
    offset = str_ssplit(plaintext, DELIM);
    len_fn = (int)offset;
    if (len_fn > MAX_LEN_FILENAME) 
    {
        printf("Dimension of the filename too long...\n\n");
        operation_denied(sd, "Filename too long", RENAME_DENIED, session_key1, session_key2, nonce);
        free(plaintext);
        return 1;
    }

    filename = (char*) malloc(len_fn*sizeof(char)+1);
    if (!filename) exit_with_failure("Malloc filename failed", 0);
    memcpy(filename, plaintext, len_fn);
    *(filename+len_fn) = '\0';
    //printf("The filename we should change is %s\n", filename);

    // New_filename
    old_offset = offset + BLANK_SPACE;
    offset = str_ssplit(&*(plaintext+old_offset), DELIM);
    len_newfn = (int)offset;
    if (len_newfn > MAX_LEN_FILENAME)
    {
        printf("Dimension of the new filename too long...\n");
        operation_denied(sd, "New_filename too long", RENAME_DENIED, session_key1, session_key2, nonce);
        free_2(plaintext, filename);
        return 1;
    } 
    
    new_filename = (char*) malloc(len_newfn*sizeof(char)+1);
    if (!new_filename) exit_with_failure("Malloc new_filename failed", 0);
    memcpy(new_filename, &*(plaintext+old_offset), len_newfn);
    *(new_filename+len_newfn) = '\0';
    if (strcmp(new_filename, "")==0)
    {
        printf("The new filename sent by the client is missing. Request denied...\n");
        operation_denied(sd, "New filename is missing", RENAME_DENIED, session_key1, session_key2, nonce);
        free_3(plaintext, filename, new_filename);
        return 1;
    }
    printf("File %s changed to new filename %s\n", filename, new_filename);
                   
    ret = filename_sanitization (filename);
    ret += filename_sanitization (new_filename);
    if (ret <= 1) 
    {
        printf("The sanitization of the filename is gone bad\n");
        operation_denied(sd, "Filename sanitization failed", RENAME_DENIED, session_key1, session_key2, nonce);
        free_3(plaintext, filename, new_filename);
        return 1;
    }

    // Execute the rename if possible, otherwise send failed message to client
    ret = chdir("documents");
    if (ret == -1)
    {
        printf("Error during the cd of the directory documents... It's necessary to close the connection\n\n");
        return -1;
    }
    ret = rename(filename, new_filename);
    chdir("..");
    if (ret == -1) {
        printf("Problem moving to parent directory... It's necessary to close the connection\n");
        free_3(plaintext, filename, new_filename);
        return -1;
    }
    
    free_3(plaintext, filename, new_filename);


    // Send success message to the client
    operation_succeed(sd, RENAME_ACCEPTED, session_key2, nonce);
    
    return 1;
}

int deleteServer(int sd, char* rec_mex, unsigned int* nonce, unsigned char* session_key1, unsigned char* session_key2)
{
    int ret;
    size_t offset;
    unsigned char* iv;

    unsigned int encr_len;
    unsigned int plain_len;
    unsigned char* plaintext;

    int msg_to_hash_len;
    unsigned int digest_len;
    unsigned char* msg_to_hash;
    unsigned char* digest;

    char* temp;
    char* temp2;
    unsigned char* bufferSupp1;
    unsigned char* bufferSupp2;

    char* filename; 
    int len_fn; 

    iv = (unsigned char*) malloc(sizeof(unsigned char)*IV_LEN);
    if (!iv) exit_with_failure("Malloc iv failed", 1);
    ret = RAND_poll(); // Seed OpenSSL PRNG
    if (ret != 1) exit_with_failure("RAND_poll failed\n", 0);

    /* ---- Parse first message (request, len encr., encr(name), hash(request, encr, iv, nonce), iv) ---- */
    bufferSupp2 = (unsigned char*) malloc(HASH_LEN*sizeof(unsigned char));
    if (!bufferSupp2) exit_with_failure("Malloc bufferSupp2 failed", 1);
    temp = (char*) malloc(LEN_SIZE*sizeof(char));
    if (!temp) exit_with_failure("Malloc temp failed", 1);
    temp2 = (char*) malloc(LEN_SIZE*sizeof(char));
    if (!temp2) exit_with_failure("Malloc temp2 failed", 1);

    offset = strlen(DELETE_REQUEST)+BLANK_SPACE;
    memcpy(temp, &*(rec_mex+offset), LEN_SIZE); // len. encr.
    offset += LEN_SIZE+BLANK_SPACE;
    encr_len = atoi((char*)temp);

    bufferSupp1 = (unsigned char*) malloc(encr_len*sizeof(unsigned char));
    if (!bufferSupp1) exit_with_failure("Malloc bufferSupp1 failed", 1);

    memcpy(bufferSupp1, &*(rec_mex+offset), encr_len); // encr
    offset += encr_len+BLANK_SPACE;

    memcpy(bufferSupp2, &*(rec_mex+offset), HASH_LEN); // hash
    offset += HASH_LEN+BLANK_SPACE;
    
    memcpy(iv, &*(rec_mex+offset), IV_LEN); // iv

    sprintf(temp2, "%u", *nonce);
    msg_to_hash_len = build_msg_4(&msg_to_hash, DELETE_REQUEST, strlen(DELETE_REQUEST),\
                                                bufferSupp1, encr_len,\
                                                iv, IV_LEN,\
                                                temp2, LEN_SIZE);
    if (ret == -1) exit_with_failure("Error during the building of the message", 1);

    digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len);

    ret = CRYPTO_memcmp(digest, bufferSupp2, HASH_LEN);

    free_5(bufferSupp2, temp, msg_to_hash, digest, temp2);

    if (ret != 0) 
    {
        printf("Wrong delete request hash.\n");
        free_2(bufferSupp1, iv);
        return 1;
    }
    *nonce += 1;

    // Decrypt the filename
    decrypt_AES_128_CBC(&plaintext, &plain_len, bufferSupp1, encr_len, iv, session_key1);

    free_2(bufferSupp1, iv);

    len_fn = plain_len;
    if (len_fn > MAX_LEN_FILENAME) 
    {
        printf("The filename is too long...\n");
        operation_denied(sd, "Filename too long", DELETE_DENIED, session_key1, session_key2, nonce);
        free(plaintext);
        return 1;
    }

    filename = (char*) malloc((len_fn+1)*sizeof(char));
    if (!filename) exit_with_failure("Malloc filename failed", 0);
    memcpy(filename, plaintext, len_fn+1); 
    if (strcmp(filename, "")==0) 
    {
        printf("The filename is missing...\n");
        operation_denied(sd, "Filename is missing", DELETE_DENIED, session_key1, session_key2, nonce);
        free_2(plaintext, filename);
        return 1;
    }

    // Sanitize the filename
    ret = filename_sanitization(filename);
    if (ret != 1) 
    {
        printf("The sanitization of the filename is gone bad... Bad characters inside of it...\n");
        operation_denied(sd, "Filename sanitization failed", DELETE_DENIED, session_key1, session_key2, nonce);
        free_2(plaintext, filename);
        return 1;
    }


    // Remove the file
    ret = chdir("documents/");
    if (ret == -1) exit_with_failure("Can't change directory to path_documents", 1);
    ret = remove(filename);
    if (ret == -1)
    {
        printf("The delete operation went bad...\n");
        operation_denied(sd, "Something bad happened during the delete operation", DELETE_DENIED, session_key1, session_key2, nonce);
        free_2(plaintext, filename);
        return 1;
    }
    else printf("Delete operation accomplished. File %s deleted.\n", filename);
    ret = chdir("../");
    if (ret == -1) 
    {
        operation_denied(sd, "Something bad happened during the delete operation... It's necessary to close the connection", DELETE_DENIED, session_key1, session_key2, nonce);
        free_2(plaintext, filename);
        return -1;
    }
    
    if (ret == -1) exit_with_failure("Can't change directory", 1);
    free_2(plaintext, filename);

    // Send success message
    operation_succeed(sd, DELETE_ACCEPTED, session_key2, nonce);

    return 1;
}

int downloadServer(int sock, char* rec_mex, unsigned int* nonce, unsigned char* session_key1, unsigned char* session_key2)
{
    int ret;
    unsigned char* iv;

    int encr_len;
    unsigned int plain_len;
    unsigned char* plaintext;
    unsigned char* encr_msg;

    int msg_to_hash_len;
    unsigned int digest_len;
    unsigned int msg_to_encr_len;
    unsigned char* msg_to_encr;
    unsigned char* msg_to_hash;
    unsigned char* digest;

    int msg_len;
    char* temp;
    unsigned char* buffer;
    unsigned char* bufferSupp1;
    unsigned char* bufferSupp2;

    char filename[MAX_LEN_FILENAME];
    struct stat st;
    int i, j, ch, max;
    int nchunk, rest;
    FILE* fd;




    /* ---- Parsing the message ----*/
    //THE FORMAT OF THE MESSAGE WE RECEIVED SHOULD BE M1: download_request, len encr., encr(filename), hash(download_request, encr, iv, nonce), iv)
    bufferSupp1 = (unsigned char*)malloc(sizeof(unsigned char)*LEN_SIZE);
    if (!bufferSupp1) exit_with_failure("Malloc bufferSupp1 failed", 1);
    memcpy(bufferSupp1, &*(rec_mex+strlen(DOWNLOAD_REQUEST)+BLANK_SPACE), LEN_SIZE);
    encr_len = atoi((char*)bufferSupp1);

    // HERE WE TAKE THE ENCRYPTED MESSAGE
    encr_msg = (unsigned char*)malloc(sizeof(unsigned char)*encr_len);
    if (!encr_msg) exit_with_failure("Malloc encr_msg failed", 1);
    memcpy(encr_msg, &*(rec_mex+strlen(DOWNLOAD_REQUEST)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE), encr_len);

    //HERE WE TAKE THE MAC
    bufferSupp2 = (unsigned char*)malloc(sizeof(unsigned char)*HASH_LEN);
    if (!bufferSupp2) exit_with_failure("Malloc bufferSupp2 failed", 1);
    memcpy(bufferSupp2, &*(rec_mex+strlen(DOWNLOAD_REQUEST)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE+encr_len+BLANK_SPACE), HASH_LEN);

    //HERE WE TAKE THE IV
    iv = (unsigned char*)malloc(sizeof(unsigned char)*IV_LEN);
    if (!iv) exit_with_failure("Malloc iv failed", 1);
    memcpy(iv, &*(rec_mex+strlen(DOWNLOAD_REQUEST)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE+encr_len+BLANK_SPACE+HASH_LEN+BLANK_SPACE), IV_LEN);

    // HERE WE SAVE THE NONCE INTO A STRING
    temp = (char*) malloc(sizeof(char)*LEN_SIZE);
    if (!temp) exit_with_failure("Malloc temp failed", 1);
    sprintf(temp, "%u", *nonce);
    
    //Now we prepare the message to hash to compare it with the one we received
    msg_to_hash_len = build_msg_4(&msg_to_hash, DOWNLOAD_REQUEST, strlen(DOWNLOAD_REQUEST), \
                                                encr_msg, encr_len, \
                                                iv, IV_LEN, \
                                                temp, LEN_SIZE);
    if (msg_to_hash_len == -1) exit_with_failure("Something bad happened building the hash...", 0);

    digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len); 

    ret = CRYPTO_memcmp(digest, bufferSupp2, HASH_LEN);
    
    free_5(bufferSupp1, bufferSupp2, temp, msg_to_hash, digest);

    if (ret != 0)
    {
        printf("Wrong download failed hash\n\n");
        free_2(encr_msg, iv);
        return 1;
    } 
    else 
    {
        printf("The MAC is been correctly compared!\n");
        *nonce += 1;
    }
    

    //NOW WE CAN DECRYPT AND TAKE THE VALUE OF THE FILENAME DECRYPTED
    decrypt_AES_128_CBC(&plaintext, &plain_len, encr_msg, encr_len, iv, session_key1);
    if (plain_len > MAX_LEN_FILENAME)
    {
        free_3(encr_msg, iv, plaintext);
        operation_denied(sock, "The length of the filename is too long", DOWNLOAD_DENIED, session_key1, session_key2, nonce);
        printf("The length of the filename is too big, download management terminated...\n\n");
        return 1;
    }
    
    memset(filename, 0, MAX_LEN_FILENAME);
    memcpy(filename, plaintext, plain_len); 
    if (strcmp(filename, "")==0)
    {
        free_3(encr_msg, iv, plaintext);
        printf("The filename is missing\n");
        operation_denied(sock, "The filename is missing", DOWNLOAD_DENIED, session_key1, session_key2, nonce);
        return 1;
    }
    ret = filename_sanitization (filename);
    if (ret == 0) 
    {
        printf("The sanitization of the filename is gone bad\n");
        operation_denied(sock, "Filename sanitization failed", DOWNLOAD_DENIED, session_key1, session_key2, nonce);
        free_3(encr_msg, iv, plaintext);
        return 1;
    }

    free_3(encr_msg, iv, plaintext);


    ret = chdir("documents");
    if (ret == -1) exit_with_failure("Can't open directory documents...", 1);
    fd = fopen(filename, "r");
    if (!(fd))
    {
        printf("File %s doesn't exist...\n  ", filename);
        chdir("..");
        operation_denied(sock, "The file doesn't exists", DOWNLOAD_DENIED, session_key1, session_key2, nonce);
        return 1;
    }
    stat(filename, &st);
    chdir("..");
    printf("The filename is %s\n", filename);
    //printf("The size of the file is %ld\n", st.st_size);
    nchunk = (st.st_size/CHUNK_SIZE)+1;
    rest = st.st_size - (nchunk-1)*CHUNK_SIZE; // This is the number of bits of the final chunk

    //printf("The number of chunk is %i\n", nchunk);
    //printf("The number of rest is %i\n", rest);




    /* ---- Send download_accepted to the client ---- */ 
    //THE FORMAT OF THE MESSAGE WE SHOULD SEND IS DOWNLOAD_ACCEPTED NCHUNK REST HASH IV
    //FIRST OF ALL WE SHOULD CALCULATE THE DIGEST OF THE HASH FOR THE MAC: DOWNLOAD_ACCEPTED NCHUNK REST IV NONCE
    iv = (unsigned char*) malloc(sizeof(unsigned char)*IV_LEN);
    if (!iv) exit_with_failure("Malloc iv failed", 1);
    ret = RAND_poll(); // Seed OpenSSL PRNG
    if (ret != 1) exit_with_failure("RAND_poll failed\n", 0);
    ret = RAND_bytes((unsigned char*)&iv[0], IV_LEN);
    if (ret != 1) exit_with_failure("RAND_bytes failed\n", 0);

    bufferSupp1 = (unsigned char*)malloc(LEN_SIZE);
    if (!bufferSupp1) exit_with_failure("Malloc buffSupp1 failed", 1);
    bufferSupp2 = (unsigned char*)malloc(REST_SIZE);
    if (!bufferSupp2) exit_with_failure("Malloc bufferSupp2 failed", 1);
    temp = (char*)malloc(LEN_SIZE);
    if (!temp) exit_with_failure("Malloc temp failed", 1);

    sprintf(temp, "%u", *nonce); //nonce is put on temp as a string
    sprintf((char*)bufferSupp1, "%i", nchunk); //nchunk is put on bufferSupp1 as a string
    sprintf((char*)bufferSupp2, "%i", rest); //rest is put on bufferSUpp2 as a string
    msg_to_hash_len = build_msg_5(&msg_to_hash, DOWNLOAD_ACCEPTED, strlen(DOWNLOAD_ACCEPTED), \
                                                bufferSupp1, LEN_SIZE,\
                                                bufferSupp2, REST_SIZE,\
                                                iv, IV_LEN,\
                                                temp, LEN_SIZE);
    if (msg_to_hash_len == -1) exit_with_failure("Something bad happened building the hash...", 0);

    digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len);

    msg_len = build_msg_5(&buffer, DOWNLOAD_ACCEPTED, strlen(DOWNLOAD_ACCEPTED), \
                                   bufferSupp1, LEN_SIZE, \
                                   bufferSupp2, REST_SIZE, \
                                   digest, HASH_LEN,\
                                   iv, IV_LEN);
    if (msg_len == -1) exit_with_failure("Something bad happened building the message...", 0);
    
    ret = send(sock, buffer, BUF_LEN, 0);
    if (ret == -1)
    {
        printf("Send operation gone bad.\n");
        free_6(buffer, bufferSupp1, bufferSupp2, msg_to_hash, temp, digest);
        free(iv);
        return -1;
    }
    *nonce += 1;

    free_6(buffer, bufferSupp1, bufferSupp2, msg_to_hash, temp, digest);
    free(iv);
    

    printf("Sending chunks.\n");

    /* ---- Send chunks ---- */
    //NOW WE START TO SEND THE CHUNKS
    for (i = 0; i < nchunk; i++)
    {
        msg_to_encr_len = CHUNK_SIZE;
        msg_to_encr = (unsigned char*)malloc(msg_to_encr_len);
        if (!msg_to_encr) exit_with_failure("Malloc msg_to_encr failed", 1);
        
        if (i == nchunk-1) max = rest;
        else max = CHUNK_SIZE; 

        for (j = 0; j < max; j++)
        {
            if ((ch = getc(fd)) == EOF)
            {
               *(msg_to_encr+j) = '\0';
                printf("File over!");
                break;
            }

            *(msg_to_encr+j) = ch;
        }


        //ENCRYPT THE MESSAGE SENT
        iv = (unsigned char*) malloc(sizeof(unsigned char)*(IV_LEN+1));
        if (!iv) exit_with_failure("Malloc iv failed", 1);
        ret = RAND_bytes((unsigned char*)&iv[0], IV_LEN);
        if (ret != 1) exit_with_failure("RAND_bytes failed\n", 0);
        //*(iv+IV_LEN) = '\0';        
        //printf("I'm sending the chunk %s\n\n", (char*)msg_to_encr);

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

        free_6(buffer, temp, iv, digest, encr_msg, msg_to_encr);
        free(bufferSupp1);

        if (ret == -1)
        {
            printf("Send operation gone bad\n");
            return -1;
        }
        *nonce += 1;
           
        //printf("We are sending the chunk number %i\n", i);



        buffer = (unsigned char*)malloc(BUF_LEN);
        if (!buffer) exit_with_failure("Malloc buffer failed", 1 );
        ret = recv (sock, buffer, BUF_LEN, 0);
        if (ret == -1)
        {
            printf("Receive operation gone bad\n");
            return -1;
        }
        //printf("Confirmed! %s\n", (char*)buffer);
        free(buffer);
    }
    fclose(fd);




    /* ---- WE SENT ALL THE CHUNKS NOW WE WAIT FOR THE CLIENT OUTCOME ---- */
    buffer = (unsigned char*)malloc(BUF_LEN*(sizeof(unsigned char)));
    if (!buffer) exit_with_failure("Malloc buffer failure", 1);
    ret = recv(sock, buffer, BUF_LEN, 0);
    if (ret == -1)
    {
        printf("Receive operation gone bad!\n\n");
        free(buffer);
        return -1;
    }

    // DECRYPT THE BUFFER
    ret = check_reqacc_msg(DOWNLOAD_FINISHED, buffer, *nonce, session_key2);
    if (ret == -1)
    {
        printf("Check download_finished gone bad.\n\n");
        free(buffer);
        return 1;
    }

    free(buffer);
    printf("Download operation completed!\n");
    *nonce += 1;

    return 1;
}

int uploadServer(int sock, char* rec_mex, unsigned int* nonce, unsigned char* session_key1, unsigned char* session_key2)
{

    int ret;
    unsigned char* iv;

    int encr_len;
    unsigned int plain_len;
    unsigned char* plaintext;
    unsigned char* encr_msg;

    int msg_to_hash_len;
    unsigned int digest_len;
    unsigned char* msg_to_hash;
    unsigned char* digest;

    int msg_len;
    char* temp;
    unsigned char* buffer;
    unsigned char* bufferSupp1;
    unsigned char* bufferSupp2;
    unsigned char* bufferSupp3;

    char filename[MAX_LEN_FILENAME];
    int i;
    int nchunk;
    FILE* fd;



    /* ---- Parsing the message ----*/
    //THE FORMAT OF THE MESSAGE WE RECEIVED SHOULD BE M1: UPLOAD_REQUEST encr_len, encr{filename}, Hash(UPLOAD_REQUEST, filename, nchunk, nonce), IV, nchunk 
    bufferSupp1 = (unsigned char*)malloc(sizeof(unsigned char)*LEN_SIZE);
    if (!bufferSupp1) exit_with_failure("Malloc bufferSupp1 failed", 1);
    memcpy(bufferSupp1, &*(rec_mex+strlen(UPLOAD_REQUEST)+BLANK_SPACE), LEN_SIZE);
    encr_len = atoi((char*)bufferSupp1);

    // HERE WE TAKE THE ENCRYPTED MESSAGE
    encr_msg = (unsigned char*)malloc(sizeof(unsigned char)*encr_len);
    if (!encr_msg) exit_with_failure("Malloc encr_msg failed", 1);
    memcpy(encr_msg, &*(rec_mex+strlen(UPLOAD_REQUEST)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE), encr_len);

    //HERE WE TAKE THE MAC
    bufferSupp2 = (unsigned char*)malloc(sizeof(unsigned char)*HASH_LEN);
    if (!bufferSupp2) exit_with_failure("Malloc bufferSupp2 failed", 1);
    memcpy(bufferSupp2, &*(rec_mex+strlen(UPLOAD_REQUEST)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE+encr_len+BLANK_SPACE), HASH_LEN);

    //HERE WE TAKE THE IV
    iv = (unsigned char*)malloc(sizeof(unsigned char)*IV_LEN);
    if (!iv) exit_with_failure("Malloc iv failed", 1);
    memcpy(iv, &*(rec_mex+strlen(UPLOAD_REQUEST)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE+encr_len+BLANK_SPACE+HASH_LEN+BLANK_SPACE), IV_LEN);

    //Here we take the number of chunks 
    bufferSupp3 = (unsigned char*)malloc(sizeof(unsigned char)*LEN_SIZE);
    if (!bufferSupp3) exit_with_failure("Malloc iv failed", 1);
    memcpy(bufferSupp3, &*(rec_mex+strlen(UPLOAD_REQUEST)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE+encr_len+BLANK_SPACE+HASH_LEN+BLANK_SPACE+IV_LEN+BLANK_SPACE), LEN_SIZE);
    nchunk = atoi((char*)bufferSupp3);
    //printf("%s", nchunk); 

    // HERE WE SAVE THE NONCE INTO A STRING
    buffer = (unsigned char*)malloc(sizeof(unsigned char)*LEN_SIZE);
    if (!buffer) exit_with_failure("Malloc buffer failed", 1);
    sprintf((char*)buffer, "%u", *nonce);


    //Now we prepare the message to hash to compare it with the one we received
    msg_to_hash_len = build_msg_5(&msg_to_hash, UPLOAD_REQUEST, strlen(UPLOAD_REQUEST), \
                                                encr_msg, encr_len, \
                                                iv, IV_LEN, \
                                                buffer, LEN_SIZE,\
                                                bufferSupp3, LEN_SIZE);
    if (msg_to_hash_len == -1) exit_with_failure("Something bad happened building the hash...", 0);

    digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len); 

    ret = CRYPTO_memcmp(digest, bufferSupp2, HASH_LEN);
    if (ret != 0)
    {
        printf("Wrong rename failed hash\n\n");
        free_6(buffer, bufferSupp1, bufferSupp2, iv, encr_msg, msg_to_hash);
        free(digest);
        return 1;
    } 
    else printf("The MAC has been correctly compared!\n");
    *nonce += 1;


    //NOW WE CAN DECRYPT AND TAKE THE VALUE OF THE FILENAME DECRYPTED
    decrypt_AES_128_CBC(&plaintext, &plain_len, encr_msg, encr_len, iv, session_key1);
    if (plain_len > MAX_LEN_FILENAME)
    {
        free_6(bufferSupp1, bufferSupp2, encr_msg, iv, plaintext, buffer);
        free_2(msg_to_hash, digest);
        printf("The length of the filename is too big, download management terminated...\n\n");
        return 1;
    }
    
    memset(filename, 0, MAX_LEN_FILENAME);
    memcpy(filename, plaintext, plain_len); 

    free_6(bufferSupp1, bufferSupp2, msg_to_hash, encr_msg, plaintext, iv);
    free_3(buffer, digest, bufferSupp3);

    ret = filename_sanitization (filename);
    if (ret == 0) 
    {
        printf("The sanitization of the filename is gone bad\n");
        operation_denied(sock, "Filename sanitization failed", UPLOAD_DENIED, session_key1, session_key2, nonce);
        return 1;
    }

    //CHECK OF FILE NAME ALREADY EXISTS 
    ret = chdir("documents");
    if (ret == -1) exit_with_failure("Can't open directory documents...", 1);
    fd = fopen(filename, "r");
    chdir("..");
    if (fd)
    {
        printf("File %s already exists...\n  ", filename);
        fclose(fd);
        operation_denied(sock, "The file already exists", UPLOAD_DENIED, session_key1, session_key2, nonce);
        return 1;
    }

    //CHECK IF FILE NOT TOO LARGE 

    //NOW we send UPLOAD_ACCEPTED TO CLIENT 
    
    /* ---- Send Upload_accepted to the client ---- */ 
    //THE FORMAT OF THE MESSAGE WE SHOULD SEND IS UPLOAD_ACCEPTED  HASH IV
    //FIRST OF ALL WE SHOULD CALCULATE THE DIGEST OF THE HASH FOR THE MAC: UPLOAD_ACCEPTED IV NONCE
    iv = (unsigned char*) malloc(sizeof(unsigned char)*IV_LEN);
    if (!iv) exit_with_failure("Malloc iv failed", 1);
    ret = RAND_poll(); // Seed OpenSSL PRNG
    if (ret != 1) exit_with_failure("RAND_poll failed\n", 0);
    ret = RAND_bytes((unsigned char*)&iv[0], IV_LEN);
    if (ret != 1) exit_with_failure("RAND_bytes failed\n", 0);

    bufferSupp1 = (unsigned char*)malloc(LEN_SIZE);
    if (!bufferSupp1) exit_with_failure("Malloc buffSupp1 failed", 1);

    bufferSupp2 = (unsigned char*)malloc(REST_SIZE);
    if (!bufferSupp2) exit_with_failure("Malloc bufferSupp2 failed", 1);

    temp = (char*)malloc(LEN_SIZE);
    if (!temp) exit_with_failure("Malloc temp failed", 1);

    sprintf((char*)temp, "%u", *nonce); //nonce is put on temp as a string
    msg_to_hash_len = build_msg_3(&msg_to_hash, UPLOAD_ACCEPTED, strlen(UPLOAD_ACCEPTED), \
                                                iv, IV_LEN,\
                                                temp, LEN_SIZE);
    if (msg_to_hash_len == -1) exit_with_failure("Something bad happened building the hash...", 0);

    digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len);

    msg_len = build_msg_3(&buffer, UPLOAD_ACCEPTED, strlen(UPLOAD_ACCEPTED), \
                                   digest, HASH_LEN,\
                                   iv, IV_LEN);
    if (msg_len == -1) exit_with_failure("Something bad happened building the message...", 0);
    
    ret = send(sock, buffer, BUF_LEN, 0);
    printf("Sending UPLOAD_ACCEPTED\n"); 
    if (ret == -1)
    {
        printf("Send operation gone bad.\n");
        free_6(buffer, bufferSupp1, bufferSupp2, msg_to_hash, temp, digest);
        free(iv);
        return -1;
    }
    *nonce += 1;

    free_6(buffer, bufferSupp1, bufferSupp2, msg_to_hash, temp, digest);
    free(iv);
    

    /* ---- NOW WE CAN BEGIN DOWNLOAD THE CHUNKS ---- */
    ret = chdir("documents");
    if (ret == -1) exit_with_failure("Can't open directory documents...", 1);
    fd = fopen(filename, "w");
    chdir("..");
    if (!fd)
    {
        printf("Error during the opening of the file %s...\n  ", filename);
        return -1;
    }
    for (i = 0; i < nchunk; i++)
    {
        //THE FORMAT OF THE CHUNK MESSAGE IS LEN_ENC, {CHUNK}K1, H({CHUNK}K2, IV, NONCE), IV
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

        bufferSupp2 = (unsigned char*)malloc(encr_len);
        if (!bufferSupp2) exit_with_failure("Malloc bufferSupp2 failed", 1);
        memcpy(bufferSupp2, &*(buffer+LEN_SIZE+BLANK_SPACE), encr_len);

        iv = (unsigned char*) malloc(sizeof(unsigned char)*(IV_LEN));
        if (!iv) exit_with_failure("Malloc iv failed", 1);
        memcpy(iv, &*(buffer+LEN_SIZE+BLANK_SPACE+encr_len+BLANK_SPACE+HASH_LEN+BLANK_SPACE), IV_LEN); // iv

        // WE SHOULD COMPARE THE TWO DIGEST TO AUTHENTICATE THE MESSAGE
        bufferSupp3 = (unsigned char*)malloc(HASH_LEN*sizeof(unsigned char*));
        if (!bufferSupp3) exit_with_failure("Malloc bufferSupp3 failed", 1);
        memcpy(bufferSupp3, &*(buffer+LEN_SIZE+BLANK_SPACE+encr_len+BLANK_SPACE), HASH_LEN); //Here we have the hash to compare
        
        temp = (char*)malloc(sizeof(char)*LEN_SIZE);
        if (!temp) exit_with_failure("Malloc of temp failed", 1);
        
        sprintf(temp, "%u", *nonce); //nonce string format
        msg_to_hash_len = build_msg_3(&msg_to_hash, bufferSupp2, encr_len,\
                                                    iv, IV_LEN,\
                                                    temp, LEN_SIZE);
        if (msg_to_hash_len == -1) exit_with_failure("Something bad happened building the hash...", 0);

        digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len);
        
        ret = CRYPTO_memcmp(digest, bufferSupp3, HASH_LEN);
        free_5(buffer, bufferSupp3, temp, msg_to_hash, digest);
        if (ret != 0)
        {
            printf("Wrong upload chunk hash\n\n");
            free_3(bufferSupp1, bufferSupp2, iv);
            return 1;
        }
        *nonce += 1;

        decrypt_AES_128_CBC(&plaintext, &plain_len, bufferSupp2, encr_len, iv, session_key1);

        // WRITE TO FILE
        fwrite(plaintext, sizeof(unsigned char), plain_len, fd);
        
        free_4(bufferSupp1, bufferSupp2, iv, plaintext);
        //printf("We received correctly the chunk number %i\n", i);

        buffer = (unsigned char*)malloc(BUF_LEN);
        if (!buffer) exit_with_failure("Malloc buffer failed", 1 );
        memcpy(buffer, "Ciao", 5);
        ret = send(sock, buffer, BUF_LEN, 0);
        if (ret == -1)
        {
            printf("Receive operation gone bad\n");
            return -1;
        }
        //printf("Confirmation sent!\n");
        free(buffer);
    }
    fclose(fd);
    
    /* ---- SEND UPLOAD FINISHED MESSAGE ---- */
    printf("Send upload finished message.\n");
    operation_succeed(sock, UPLOAD_FINISHED, session_key2, nonce);
        
    return 1;
}

int shareServer(int sd, char* rec_mex, char* username, unsigned int* nonce_cs, unsigned char* session_key1, unsigned char* session_key2)
{
    int ret;
    int sd_peer;
    int msg_len;
    int ch, j;

    unsigned int nonce_sc;

    unsigned int len_fn;
    unsigned int len_pn;

    int encr_len;
    int msg_to_encr_len;
    unsigned int plain_len;
    unsigned char* plaintext;
    unsigned char* encr_msg;
    unsigned char* msg_to_encr;

    int msg_to_hash_len;
    unsigned int digest_len;
    unsigned char* msg_to_hash;
    unsigned char* digest;

    char* temp;
    char* temp2;
    char* path_temp;
    unsigned char* iv;
    unsigned char* buffer;
    unsigned char* bufferSupp1;
    unsigned char* bufferSupp2;
    unsigned char* bufferSupp3;

    unsigned char peer_session_key1[16];
    unsigned char peer_session_key2[16];
    unsigned char nonce_sc_buffer[LEN_SIZE+1];

    FILE* f1;
    FILE* src_fd;
    struct stat st;

    struct sockaddr_in rcv_addr;
    int rcv_port;


    bufferSupp1 = (unsigned char*)malloc(sizeof(unsigned char)*LEN_SIZE);
    if (!bufferSupp1) exit_with_failure("Malloc bufferSupp1 failed", 1);
    memcpy(bufferSupp1, &*(rec_mex+strlen(SHARE_REQUEST)+BLANK_SPACE), LEN_SIZE);
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
    memcpy(encr_msg, &*(rec_mex+strlen(SHARE_REQUEST)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE), encr_len);

    //HERE WE TAKE THE MAC
    bufferSupp2 = (unsigned char*)malloc(sizeof(unsigned char)*HASH_LEN);
    if (!bufferSupp2) exit_with_failure("Malloc bufferSupp2 failed", 1);
    memcpy(bufferSupp2, &*(rec_mex+strlen(SHARE_REQUEST)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE+encr_len+BLANK_SPACE), HASH_LEN);

    //HERE WE TAKE THE IV
    iv = (unsigned char*)malloc(sizeof(unsigned char)*IV_LEN);
    if (!iv) exit_with_failure("Malloc iv failed", 1);
    memcpy(iv, &*(rec_mex+strlen(SHARE_REQUEST)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE+encr_len+BLANK_SPACE+HASH_LEN+BLANK_SPACE), IV_LEN);

    // HERE WE SAVE THE NONCE INTO A STRING
    temp = (char*) malloc(sizeof(char)*LEN_SIZE);
    if (!temp) exit_with_failure("Malloc temp failed", 1);
    sprintf(temp, "%u", *nonce_cs);
    
    //Now we prepare the message to hash to compare it with the one we received
    msg_to_hash_len = build_msg_4(&msg_to_hash, SHARE_REQUEST, strlen(SHARE_REQUEST), \
                                                encr_msg, encr_len, \
                                                iv, IV_LEN, \
                                                temp, LEN_SIZE);
    if (msg_to_hash_len == -1) exit_with_failure("Something bad happened building the hash...", 0);

    digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len); 

    ret = CRYPTO_memcmp(digest, bufferSupp2, HASH_LEN);
    
    free_5(bufferSupp1, bufferSupp2, temp, msg_to_hash, digest);

    if (ret != 0)
    {
        printf("Wrong share failed hash\n\n");
        free_2(encr_msg, iv);
        return 1;
    } 
    else *nonce_cs += 1;

    // DECRYPT THE MESSAGE
    decrypt_AES_128_CBC(&plaintext, &plain_len, encr_msg, encr_len, iv, session_key1);
    free_2(iv, encr_msg);

    len_fn = str_ssplit(plaintext, DELIM);
    bufferSupp1 = (unsigned char*) malloc((len_fn+1)*sizeof(unsigned char));
    if (!bufferSupp1) exit_with_failure("Malloc bufferSupp1 failed", 1);
    memcpy(bufferSupp1, plaintext, len_fn); //Here we have the filename
    *(bufferSupp1+len_fn) = '\0';

    len_pn = plain_len - len_fn - BLANK_SPACE;
    bufferSupp2 = (unsigned char*) malloc((len_pn+1)*sizeof(unsigned char));
    if (!bufferSupp2) exit_with_failure("Malloc bufferSupp2 failed", 1);
    memcpy(bufferSupp2, &*(plaintext+len_fn+BLANK_SPACE), len_pn); //Here we have the peername
    *(bufferSupp2+len_pn) = '\0';

    free(plaintext);

    // now we should sanitize the filename and the peername
    ret = chdir("documents");
    if (ret == -1)
    {
        free_2(bufferSupp1, bufferSupp2);
        printf("I'm having some problem moving into documents...\n");
        // Send denied message to left party
        operation_denied(sd, "Problem accessing directories... Need a new connection", SHARE_DENIED, session_key1, session_key2, nonce_cs);
        return -1;
    }

    // TRY TO OPEN PEERNAME'S FILE TO SHARE
    printf("The file to share is %s and the peer to share with is %s.\n", bufferSupp1, bufferSupp2);
    //printf("The peer to share with is %s\n", bufferSupp2);

    ret = username_sanitization((char*)bufferSupp2);
    if (ret == 0)
    {
        printf("Peername not accepted after username sanitization... Exiting from the request\n");
        chdir("..");
        // Send denied message to left party
        operation_denied(sd, "Peername not accepted after sanitization", SHARE_DENIED, session_key1, session_key2, nonce_cs);
        free_2(bufferSupp1, bufferSupp2);
        return 1;
    }
    ret = filename_sanitization((char*)bufferSupp1);
    if (ret == 0)
    {
        printf("Filename not accepted after filename sanitization... Exiting from the request\n");
        chdir("..");
        // Send denied message to left party
        operation_denied(sd, "Filename not accepted after sanitization", SHARE_DENIED, session_key1, session_key2, nonce_cs);
        free_2(bufferSupp1, bufferSupp2);
        return 1;
    }

    f1 = fopen((char*) bufferSupp1, "r");
    if (!f1)
    {
        printf("The sharer doesn't have any file called %s\n", bufferSupp1);
        chdir("..");
        // Send denied message to left party
        operation_denied(sd, "No such file", SHARE_DENIED, session_key1, session_key2, nonce_cs);
        free_2(bufferSupp1, bufferSupp2);
        return 1;
    }
    fclose(f1);

    stat((char*)bufferSupp1, &st);
    chdir("..");
    //printf("The size of the file is %ld\n", st.st_size);


    // We should ask to the receiver whether it wants to allow the share operation
    // Save on database/info/peername.txt the socket descriptor of the peername
    path_temp = (char*) malloc((len_pn+4)*sizeof(char));
    if (!path_temp) exit_with_failure("Malloc path_temp failed", 1);
    memcpy(path_temp, bufferSupp2, len_pn-1);
    memcpy(path_temp+len_pn-1, ".txt\0", 5);

    temp = (char*) malloc(LEN_SIZE*sizeof(char));
    if (!temp) exit_with_failure("Malloc temp failed", 1);

    ret = chdir("../info");
    if (ret == -1)
    {
        free_4(bufferSupp1, bufferSupp2, temp, path_temp);
        printf("I'm having some problem moving into info directory... Need to close the connection\n");
        return -1;
    }

    // Here we take the port and the session keys
    f1 = fopen(path_temp, "r");
    chdir("../");
    ret = chdir(username);
    if (ret == -1)
    {
        free_4(bufferSupp1, bufferSupp2, temp, path_temp);
        printf("I'm having some problem moving into username directory... Need to close the connection\n");
        return -1;
    }
    if (!f1) 
    {
        printf("A peer called %s doesn't exists... Retry\n\n", bufferSupp2);
        free_4(bufferSupp1, bufferSupp2, temp, path_temp);
        operation_denied(sd, "Peer doesn't exists", SHARE_DENIED, session_key1, session_key2, nonce_cs);
        return 1;
    }

    //Now we take the information about the peer on the file txt 
    for (j = 0; j < PORT_SIZE; j++)
    {
        if ((ch = getc(f1)) == EOF)
        {
            *(temp+j) = '\0';
            printf("File over!");
            break;
        }

        *(temp+j) = ch;
    }
    for (j = 0; j < 16; j++) //session_key1 bytes
    {
        if ((ch = getc(f1)) == EOF)
        {
            *(peer_session_key1+j) = '\0';
            printf("File over!");
            break;
        }

        *(peer_session_key1+j) = ch;
    }
    for (j = 0; j < 16; j++) //session_key2 bytes
    {
        if ((ch = getc(f1)) == EOF)
        {
            *(peer_session_key2+j) = '\0';
            printf("File over!");
            break;
        }

        *(peer_session_key2+j) = ch;
    }
    memset(nonce_sc_buffer, 0, LEN_SIZE+1);
    for (j = 0; j < LEN_SIZE+1; j++) //nonce sc bytes
    {
        if ((ch = getc(f1)) == EOF)
        {
            *(nonce_sc_buffer+j) = '\0';
            printf("File over!");
            break;
        }

        *(nonce_sc_buffer+j) = ch;
    }
    sscanf((char*)nonce_sc_buffer, "%u", &nonce_sc);
    //printf("The nonce now is %u\n", nonce_sc); 
    fclose(f1);

    //We should go on the directory of the peer
    chdir("..");
    chdir((char*) bufferSupp2); //peername
    chdir("documents");

    f1 = fopen((char*)bufferSupp1, "r");
    chdir("../..");
    chdir(username);
    if (f1)
    {
        printf("The peer already has a file called %s.\nShare denied\n", bufferSupp1);
        free_4(temp, path_temp, bufferSupp1, bufferSupp2);
        operation_denied(sd, "Peer already have a file with this name", SHARE_DENIED, session_key1, session_key2, nonce_cs);
        return 1;
    }

    rcv_port = atoi(temp); //This is the port where the peer is listening

    //Configuration of the structure used for the comunication with the second peer
    memset(&rcv_addr, 0, sizeof(rcv_addr));
	rcv_addr.sin_family = AF_INET;
	rcv_addr.sin_port = htons(rcv_port);
	inet_pton(AF_INET, LOCALHOST, &rcv_addr.sin_addr);

    sd_peer = createSocket();
    if (connect(sd_peer, (struct sockaddr*)&rcv_addr, sizeof(rcv_addr)) < 0) 
    {
        printf("Connection Failed\n");
        free_4(temp, path_temp, bufferSupp1, bufferSupp2);
        operation_denied(sd, "The peer is not online", SHARE_DENIED, session_key1, session_key2, nonce_cs);
        return 1;
    }

    free_2(temp, path_temp);



    /* ---- Send share_perm to peer ---- */
    // share_perm encr_len encr(filename peername) hash(share_perm encr iv nonce_sc) iv

    // GENERATE THE IV
    iv = (unsigned char*) malloc(sizeof(unsigned char)*IV_LEN);
    if (!iv) exit_with_failure("Malloc iv failed", 1);
    ret = RAND_poll(); // Seed OpenSSL PRNG
    if (ret != 1) exit_with_failure("RAND_poll failed\n", 0);
    ret = RAND_bytes((unsigned char*)&iv[0], IV_LEN);

    //Here we put the length of the file
    bufferSupp3 = (unsigned char*) malloc((LEN_SIZE+1)*sizeof(unsigned char));
    if (!bufferSupp3) exit_with_failure("Malloc bufferSupp3 failed", 1);
    sprintf((char*)bufferSupp3, "%ld", st.st_size);
    //printf("Now in bufferSupp3 there is: %s\n", bufferSupp3);
    
    // CREATE ENCRYPTED MESSAGE // filename, peername
    msg_to_encr_len = build_msg_3(&msg_to_encr, bufferSupp1, len_fn,\
                                                bufferSupp2, len_pn,\
                                                bufferSupp3, LEN_SIZE+1);
    if (msg_to_encr_len == -1) exit_with_failure("Something bad happened building the message to encrypt...", 0);
    free(bufferSupp3);

    encrypt_AES_128_CBC(&encr_msg, &encr_len, msg_to_encr, msg_to_encr_len, iv, peer_session_key1);

    // CREATE THE HASH
    temp = (char*) malloc(LEN_SIZE*sizeof(char));
    if (!temp) exit_with_failure("Malloc temp failed", 1);
    sprintf(temp, "%u", nonce_sc);
    msg_to_hash_len = build_msg_4(&msg_to_hash, SHARE_PERMISSION, strlen(SHARE_PERMISSION),\
                                                encr_msg, encr_len,\
                                                iv, IV_LEN,\
                                                temp, LEN_SIZE);
    if (msg_to_hash_len == -1) exit_with_failure("Something bad happened building the hash...", 0);

    digest = hmac_sha256(peer_session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len);

    // BUILD THE MESSAGE
    temp2 = (char*) malloc(LEN_SIZE*sizeof(char));
    if (!temp2) exit_with_failure("Malloc temp2 failed", 1);
    sprintf(temp2, "%d", encr_len);
    msg_len = build_msg_5(&buffer, SHARE_PERMISSION, strlen(SHARE_PERMISSION),\
                                   temp2, LEN_SIZE,\
                                   encr_msg, encr_len,\
                                   digest, HASH_LEN,\
                                   iv, IV_LEN);
    if (msg_len == -1) exit_with_failure("Something bad happened building the message...", 0);

    ret = send(sd_peer, buffer, BUF_LEN, 0);
    
    free_6(iv, temp, msg_to_encr, encr_msg, msg_to_hash, digest);
    free_2(temp2, buffer);

    if (ret == -1)
    {
        free_2(bufferSupp1, bufferSupp2);
        operation_denied(sd, "Send peer failed", SHARE_DENIED, session_key1, session_key2, nonce_cs);
        printf("Send peer failed.\n");
        return -1;
    } 
    else 
    {
        printf("Sent share permission to peer.\n");
        nonce_sc = nonce_sc + 1;
    }




    /* ---- Check peer response ---- */
    // denied or accepted nonce_sc

    buffer = (unsigned char*) malloc(sizeof(unsigned char)*BUF_LEN);
    if (!buffer) exit_with_failure("Malloc buffer failed", 1);

    ret = recv(sd_peer, buffer, BUF_LEN,0);
    if (ret == -1)
    {
        free_3(buffer, bufferSupp1, bufferSupp2);
        operation_denied(sd, "Receive peer failed", SHARE_DENIED, session_key1, session_key2, nonce_cs);
        printf("Receive failed.\n");
        return -1;
    }
    printf("Received the peer outcome.\n");

    bufferSupp3 = (unsigned char*) malloc((strlen(SHARE_DENIED)+1)*sizeof(unsigned char));
    if (!bufferSupp3) exit_with_failure("Malloc bufferSupp3 failed", 1);
    memcpy(bufferSupp3, buffer, strlen(SHARE_DENIED)); // denied or accepted same length
    memcpy(&*(bufferSupp3+strlen(SHARE_DENIED)), "\0", 1);


    if (strcmp((char*) bufferSupp3, SHARE_DENIED) == 0)
    {
        ret = check_reqden_msg(SHARE_DENIED, buffer, nonce_sc, peer_session_key1, peer_session_key2);
        if (ret == -1) 
        {
            printf("Error checking share denied message.\n");
            operation_denied(sd, "Error checking share denied message", SHARE_DENIED, session_key1, session_key2, nonce_cs);
            ret = 1;
        }
        else 
        {
            printf("Share has been denied.\n");
            nonce_sc += 1;
            operation_denied(sd, "Share has been denied", SHARE_DENIED, session_key1, session_key2, nonce_cs);
            ret = 1;
        }
        if (!save_info_file(username, bufferSupp2, rcv_port, peer_session_key1, peer_session_key2, nonce_sc)) ret = -1;
        free_4(buffer, bufferSupp1, bufferSupp2, bufferSupp3);
        return ret;
    }
    else if (strcmp((char*) bufferSupp3, SHARE_ACCEPTED) == 0)
    {
        ret = check_reqacc_msg(SHARE_ACCEPTED, buffer, nonce_sc, peer_session_key2);
        if (ret == -1) 
        {
            printf("Error checking share accepted message.\n");
            operation_denied(sd, "Error checking share accepted message", SHARE_DENIED, session_key1, session_key2, nonce_cs);
            return 1;
        }
        printf("The share request has been accepted!\n");
        nonce_sc += 1;
        if (!save_info_file(username, bufferSupp2, rcv_port, peer_session_key1, peer_session_key2, nonce_sc))
        {
            printf("Error saving the info file of %s... We should deny the request\n", bufferSupp2);
            operation_denied(sd, "Error saving info file", SHARE_DENIED, session_key1, session_key2, nonce_cs);
            free_4(buffer, bufferSupp1, bufferSupp2, bufferSupp3);
            return -1;
        }
    }
    else
    {
        printf("We don't know what the peer said...\n\n");
        operation_denied(sd, "We don't know what the peer said", SHARE_DENIED, session_key1, session_key2, nonce_cs);
        free_4(buffer, bufferSupp1, bufferSupp2, bufferSupp3);
        return 1;
    }

    free_2(bufferSupp3, buffer);

    // COPY THE FILE IN THE FOLDER OF THE REICEIVER, we are in database/peername/documents
    printf("The receiver is allowing the share operation...\n");

    path_temp = (char*) malloc((6+(len_pn-1)+1+10+len_fn+1)*sizeof(char));
    memcpy(path_temp, "../../", 6);
    memcpy(&*(path_temp+6), bufferSupp2, len_pn-1); //peername
    memcpy(&*(path_temp+6+(len_pn-1)), "/", 1);
    memcpy(&*(path_temp+6+(len_pn-1)+1), "documents/", 10);
    memcpy(&*(path_temp+6+(len_pn-1)+1+10), bufferSupp1, len_fn); //filename
    memcpy(&*(path_temp+6+(len_pn-1)+1+10+len_fn), "\0", 1);
    //printf("%s\n%s\n", path_temp, bufferSupp1);
    
    chdir("documents");
    src_fd = fopen((char*)bufferSupp1, "r");
    f1 = fopen(path_temp, "w");
    chdir("..");
    if (!src_fd || !f1) 
    {
        free_3(path_temp, bufferSupp1, bufferSupp2);
        printf("Can't open f1 or src_fd...\n");
        operation_denied(sd, "General error: need to recreate the connection", SHARE_DENIED, session_key1, session_key2, nonce_cs);
        return 1;
    }

    buffer = (unsigned char*) malloc(BUF_LEN*sizeof(unsigned char));
    if (!buffer) exit_with_failure("Malloc buffer failed", 1);

    while (1) 
    {
        ret = fread(buffer, sizeof(unsigned char), BUF_LEN, src_fd);
        if (ret == -1) 
        {
            printf("Error reading file.\n");
            free_4(path_temp, buffer, bufferSupp1, bufferSupp2);
            operation_denied(sd, "General error: need to recreate the connection", SHARE_DENIED, session_key1, session_key2, nonce_cs);
            return -1;
        }
    
        if (ret == 0) break;

        ret = fwrite(buffer, sizeof(unsigned char), ret, f1);
        if (ret == -1) 
        {
            printf("Error writing to file.\n");
            free_4(path_temp, buffer, bufferSupp1, bufferSupp2);
            operation_denied(sd, "General error: need to recreate the connection", SHARE_DENIED, session_key1, session_key2, nonce_cs);
            return -1;
        }
    }

    free_4(buffer, bufferSupp1, bufferSupp2, path_temp);
    fclose(src_fd);
    fclose(f1);


    // Send outcome to left party
    operation_succeed(sd, SHARE_ACCEPTED, session_key2, nonce_cs);

    return 1;
}


int save_info_file(char* old_username, unsigned char* username, int port, unsigned char* session_key1, unsigned char* session_key2, unsigned int nonce_sc)
{
    FILE* f1;
    char buffer[BUF_LEN];
    char port_buffer[PORT_SIZE];
    char nonce_sc_buffer[LEN_SIZE+1];

    sprintf(port_buffer, "%d", port);
    sprintf(nonce_sc_buffer, "%u", nonce_sc);
    if (chdir("../info") == -1)
    {
        printf("Error moving to the info directory... Need to close the connection\n");
        return 0;
    }

    sprintf(buffer, "%s.txt", (char*)username);
    memcpy(buffer+strlen((char*)username)+4, "\0", 1);
    f1 = fopen(buffer, "w");
    chdir("..");
    chdir(old_username);
    if (!f1)
    {
        printf("Error during the opening in write mode of a file... Need to close the connection\n");
        return 0;
    }
    
    if (!fwrite(port_buffer, sizeof(char), PORT_SIZE, f1))
    {
        printf("Error during the wirting of the file... Need to close the connection\n");
        fclose(f1);
        return 0;
    }
    if (!fwrite(session_key1, sizeof(unsigned char), 16, f1))
    {
        printf("Error during the wirting of the file... Need to close the connection\n");
        fclose(f1);
        return 0;
    }
    if (!fwrite(session_key2, sizeof(unsigned char), 16, f1))
    {
        printf("Error during the wirting of the file... Need to close the connection\n");
        fclose(f1);
        return 0;
    }
    if (!fwrite(nonce_sc_buffer, sizeof(char), LEN_SIZE+1, f1))
    {
        printf("Error during the wirting of the file... Need to close the connection\n");
        fclose(f1);
        return 0;
    } 
    fclose(f1);
    return 1;
}

int remove_info_file(char* username)
{
    int ret;
    char filename[MAX_LEN_FILENAME+4];

    memset(filename, 0, MAX_LEN_FILENAME+4);
    memcpy(filename, username, strlen(username));
    memcpy(filename+strlen(username), ".txt\0", 5);
    ret = chdir("../info");
    if (ret == -1)
    {
        printf("Error changing directory to info...\n");
        return -1;
    }
    ret = remove(filename);
    if (ret == -1)
    {
        printf("Problem during the remotion of %s\n", filename);
        chdir("..");
        chdir(username);
        return -1;
    }
    chdir("..");
    chdir(username);
    return 1;
}
