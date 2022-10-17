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
    // Diffie-Hellman variables
    EVP_PKEY* my_prvkey = NULL;
    int pubkey_len = 0;
    unsigned char* pubkey_byte = NULL;
    unsigned char* pk_buff;
    
    // Certificate
    unsigned char* cert_byte;
    int cert_len = 0;
    EVP_PKEY* pub_rsa_client;

    // Digital Signature and hash
    unsigned char* signature;

    // General variables
    char username[MAX_LEN_USERNAME+1];
    unsigned char* buffer;
    int ret, msg_len; 
    unsigned int len;
    unsigned char* p;
    
    // Functions' variables
    char funcBuff[BUF_LEN];
    char t_buff[TYPE_LEN+1];
    unsigned int nonce_cs = 0;
    unsigned int nonce_sc = 0;
    unsigned char* session_key1;
    unsigned char* session_key2;

    // Parsing variables
    unsigned char* sgn_buff;
    char* n_buff;
    
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
    pubkey_byte = gen_dh_keys("../dh_server_pubkey.pem", &my_prvkey, &pubkey_len);
    if (pubkey_len != DH_PUBKEY_SIZE) exit_with_failure("Wrong pubkey len", 0);



    /* ---- Parse the first message (login request message + username + DH pubkey) ---- */
    p = (unsigned char*) rec_mex;
    p += strlen(LOGIN_REQUEST)+BLANK_SPACE;

    // Parse and sanitize username
    if((len = str_ssplit(p, DELIM)) > MAX_LEN_USERNAME)
    {
        printf("Username too long.\n");
        return -1;
    }
    memset(username, 0, len);
    memcpy(username, p, len); // username
    memcpy(username+len, "\0", 1);
    p += len+BLANK_SPACE;

    if (!username_sanitization(username))
    {
        printf("Username sanitization fails.\n");
        return -1;
    } 

    // Move to the database/username folder of the server
    ret = chdir_n(2, MAIN_FOLDER_SERVER, username);
    if (ret == -1) return -1;

    // Parse pubkey and obtain the session keys
    pk_buff = (unsigned char*) malloc((DH_PUBKEY_SIZE+1)*sizeof(unsigned char));
    if (!pk_buff) exit_with_failure("Malloc pk_buff failed", 1);
    memcpy(pk_buff, p, pubkey_len); // dh pubkey
    memcpy(pk_buff+pubkey_len, "\0", 1);

    ret = issue_session_keys(my_prvkey, pk_buff, pubkey_len, &session_key1, &session_key2);
    EVP_PKEY_free(my_prvkey);
    if (ret == -1) return -1;

    // Retrieve the client pubkey (from the client cert., already owned by the server)
    pub_rsa_client = get_client_pubkey(username);
    
    printf("#1 Login request message is correct.\n");

    


    /* --- Send response (DH pubkey, signature, len. cert. and cert.) --- */
    // Prepare the digital signature (g^a || g^b)
    msg_len = concat_5(&buffer, pk_buff, pubkey_len,\
                                pubkey_byte, pubkey_len, NULL, 0, NULL, 0, NULL, 0);
    if (msg_len == -1) 
    {
        free(buffer);
        return -1;
    }

    ret = chdir_n(1, "../../src");
    if (ret == -1)
    {
        free(buffer);
        return -1;
    } 

    signature = sign_msg("rsa_prvkey.pem", buffer, msg_len, &len, 1);
    free(buffer);

    // Serialize the certificate
    cert_byte = read_cert("cert.pem", &cert_len);

    // Come back to the user directory
    ret = chdir_n(2, "../database/", username);
    if (ret == -1) return -1;

    // Compose the message
    n_buff = (char*) malloc(LEN_SIZE*sizeof(char));
    if (!n_buff) exit_with_failure("Malloc n_buff failed", 1);
    sprintf(n_buff, "%d", cert_len);
    msg_len = concat_5(&buffer, pubkey_byte, pubkey_len,\
                                signature, SIGN_LEN,\
                                n_buff, LEN_SIZE,\
                                cert_byte, cert_len, NULL, 0); 
    if (msg_len == -1) return -1;

    print_debug(buffer, msg_len);
    ret = send(sd, buffer, msg_len, 0); 
    
    free_n(4, buffer, cert_byte, signature, n_buff);
    if (ret == -1)
    {
        free_n(2, session_key1, session_key2);
        EVP_PKEY_free(pub_rsa_client);
        printf("Send failed.\n");
        return -1;
    } 
    else printf("#2 Message sent to client.\n");




    /* Parse the client message and verify the fields */
    buffer = (unsigned char*) malloc(sizeof(unsigned char)*BUF_LEN);
    if (!buffer) exit_with_failure("Malloc buffer failed", 1);
 
    ret = recv(sd, buffer, BUF_LEN, 0);
    if (ret == -1) 
    {
        free_n(3, buffer, session_key1, session_key2);
        EVP_PKEY_free(pub_rsa_client);
        printf("Receive failed.\n");
        return -1;
    } 
    else printf("#3 Response received.\n");
    print_debug(buffer, ret);
 
    // Parse signature
    sgn_buff = (unsigned char*) malloc((SIGN_LEN+1)*sizeof(unsigned char));
    if (!sgn_buff) exit_with_failure("Malloc sgn_buff failed", 1);
    memcpy(sgn_buff, buffer, SIGN_LEN);
    memcpy(sgn_buff+SIGN_LEN, "\0", 1);
    free(buffer);

    // Verify signature
    msg_len = concat_5(&buffer, pk_buff, pubkey_len,\
                                pubkey_byte, pubkey_len, NULL, 0, NULL, 0, NULL, 0);
    if (msg_len == -1) return -1;
    ret = verify_signature(buffer, msg_len, sgn_buff, SIGN_LEN, pub_rsa_client);
    
    free_n(4, pubkey_byte, buffer, pk_buff, sgn_buff);
    EVP_PKEY_free(pub_rsa_client);
    if (ret != 1) 
    {
        free_n(2, session_key1, session_key2);
        printf("Signature verification failed.\n");
        return -1;
    }


    /* ---- Receive the client's port ---- */
    if ((ret = rcv_port(sd, session_key1, session_key2, username)) == -1) 
    {
        free_n(2, session_key1, session_key2);
        return -1;
    }




    // FUNCTIONAL PART
    // Now that we have the cryptographic elements to have a secure communication with the client we are able to receive function messages
    // Here we are at database/username/
    printf("I managed a login request and all was good!\n\n");
    

    //printf("Now the buffer contains %s\n\n", funcBuff);
    while (1)
    {
        memset(funcBuff, 0, BUF_LEN);
        ret = recv(sd, funcBuff, BUF_LEN, 0);
        if (ret <= 0)
        {
            perror("Error during recv operation: ");
            break;
        }
        len = ret;

        // We check the first keyword to understand what the Client wants us to do
        memset(t_buff, 0, TYPE_LEN);
        memcpy(t_buff+TYPE_LEN, "\0", 1);
        if ((ret=str_ssplit((unsigned char*) funcBuff, DELIM)) > TYPE_LEN)
        {
            printf("Invalid request.\n\n");
            continue;
        }
        else
        {
            memcpy(t_buff, funcBuff, TYPE_LEN);
        }
        


        // ************ LOGIN REQUEST MANAGER ***********
        if (strcmp(t_buff, LOGIN_REQUEST) == 0)
        {
            printf("\nWe received a login request but this client is already logged... Something bad happened...\n\n");
        }


        //************ LOGOUT REQUEST MANAGER ************
        else if (strcmp(t_buff, LOGOUT_REQUEST) == 0)
        {
            printf("\nA logout request has came up...\n\n");
            // LOGOUT MANAGER: SERVER SIDE
                            
            ret = logoutServer(funcBuff, msg_len, &nonce_cs, session_key2);
            if (ret == -1) printf("Something bad happened during the management of the client logout request...\n\n");
            else
            {
                printf("End of logout request management!\n\n");
                break;
            }
        }


        // ************* LIST REQUEST MANAGER ***************
        else if (strcmp(t_buff, LIST_REQUEST) == 0)
        {
            printf("\nA list request has came up...\n\n");
            // LIST MANAGER: SERVER SIDE
        
            ret = listServer(sd, funcBuff, len, &nonce_cs, session_key1, session_key2);
            if (ret == -1)
            {
                printf("Something bad happened during the management of the client list request...\n\n");
                break;
            }
            else printf("End of list request management!\n\n");
        }


        //*************** RENAME REQUEST MANAGER *****************
        else if (strcmp(t_buff, RENAME_REQUEST) == 0)
        {
            printf("\nA rename request has came up...\n\n");
            // RENAME MANAGER: SERVER SIDE
                            
            ret = renameServer(sd, funcBuff, &nonce_cs, session_key1, session_key2);
            if (ret == -1)
            {
                printf("Something bad happened during the management of the client rename request...\n\n");
                break;
            }
            else printf("End of rename request management!\n\n");
        }


        // **************** DELETE REQUEST MANAGER ******************
        else if (strcmp(t_buff, DELETE_REQUEST) == 0)
        {
            printf("\nA delete request has came up...\n\n");
            // DELETE MANAGER: SERVER SIDE
                            
            ret = deleteServer(sd, funcBuff, &nonce_cs, session_key1, session_key2);
            if (ret == -1)
            {
                printf("Something bad happened during the management of the client delete request...\n\n");
                break;
            } else printf("End of delete request management!\n\n");
        }

        
        // *************** DOWNLOAD REQUEST MANAGER ****************
        else if (strcmp(t_buff, DOWNLOAD_REQUEST) == 0)
        {
            printf("\nA download request has came up...\n\n");

            // DOWNLOAD MANAGER: SERVER SIDE
                            
            ret = downloadServer(sd, funcBuff, &nonce_cs, session_key1, session_key2);
            if (ret == -1)
            {
                printf("Something bad happened during the management of the client download request...\n\n");
                break;
            } 
            else printf("End of download request management!\n\n");
        }


        // *************** UPLOAD REQUEST MANAGER ***************
        else if (strcmp(t_buff, UPLOAD_REQUEST) == 0)
        {
            printf("\nAn upload request has came up...\n\n");
            // UPLOAD MANAGER: SERVER SIDE
                            
            ret = uploadServer(sd, funcBuff, &nonce_cs, session_key1, session_key2);
            if (ret == -1)
            {
                printf("Something bad happened during the management of the client upload request...\n\n");
                break;
            }
            else printf("End of upload request management!\n\n");
        }


        // **************** SHARE REQUEST MANAGER ****************
        else if (strcmp(t_buff, SHARE_REQUEST) == 0)
        {
            printf("\nA share request has came up...\n\n");
            // SHARE MANAGER: SERVER SIDE

            ret = shareServer(sd, funcBuff, username, &nonce_cs, &nonce_sc, session_key1, session_key2);            
            if (ret == -1)
            {
                printf("Something bad happened during the management of the client share request...\n\n");
                break;
            }
            else
            {
                printf("End of share request management!\n\n");
                ret = chdir("../../");
                if (ret == -1) {
                    printf("Problem changing directory");
                    break;
                }
                ret = chdir(username);
                if (ret == -1) {
                    printf("Problem changing directory");
                    break;
                }
            } 
        }

        else printf("Unknown type of request by the Client...\n");  
    }

    // Clear session keys from the file
    // ......

    free_n(2, session_key1, session_key2);
    close(sd);
    
    return 1;
}

int logoutServer(char* rec_mex, unsigned int msg_len, unsigned int* nonce, unsigned char* session_key2)
{
    unsigned int digest_len, len;
    int ret, msg_to_hash_len;
    unsigned char* temp, *msg_to_hash, *digest, *hash, *iv;


    /* ---- Parse the first client message (request + hash + iv) ---- */
    temp = (unsigned char*) malloc(sizeof(char)*LEN_SIZE);
    if (!temp) exit_with_failure("Malloc temp failed", 1);   
    hash = (unsigned char*) malloc(sizeof(unsigned char)*HASH_LEN);   
    if (!hash) exit_with_failure("Malloc hash failed", 1);
    iv = (unsigned char*) malloc(sizeof(unsigned char)*IV_LEN);   
    if (!iv) exit_with_failure("Malloc iv failed", 1);

    len = 0;
    ret = parse_msg((unsigned char*)rec_mex, msg_len, NULL, &len, NULL, hash, iv);
    if (ret == -1)
    {
        free_n(3, temp, hash, iv);
        return -1;
    }

    // Check hash correctness
    sprintf((char*)temp, "%u", *nonce);
    msg_to_hash_len = concat_5(&msg_to_hash, LOGOUT_REQUEST, strlen(LOGOUT_REQUEST), \
                                             iv, IV_LEN, \
                                             temp, LEN_SIZE, NULL, 0, NULL, 0);
    if (msg_to_hash_len == -1) 
    {
        free_n(3, temp, hash, iv);
        return -1;
    }

    digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len);   
    ret = CRYPTO_memcmp(digest, hash, HASH_LEN);

    free_n(5, iv, hash, temp, digest, msg_to_hash);
    if (ret != 0) 
    {
        printf("Wrong logout request hash.\n");
        return -1;
    }

    return 1;
}

int listServer(int sd, char* rec_mex, unsigned int len, unsigned int* nonce, unsigned char* session_key1, unsigned char* session_key2)
{
    DIR* d;

    unsigned char* iv;
    unsigned int num_file, tot_num_file;
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
    

    /* ---- Parse the list request (req., hash(req, iv, nonce), iv) ---- */
    // Parse message
    iv = (unsigned char*) malloc(sizeof(unsigned char)*IV_LEN);
    if (!iv) exit_with_failure("Malloc iv failed", 1);
    ret = RAND_poll(); // Seed OpenSSL PRNG
    if (ret != 1) exit_with_failure("RAND_poll failed\n", 0);
    bufferSupp1 = (unsigned char*) malloc(HASH_LEN*sizeof(unsigned char));
    if (!bufferSupp1) exit_with_failure("Malloc bufferSupp1 failed", 1);
    temp = (char*) malloc(sizeof(char)*LEN_SIZE);
    if (!temp) exit_with_failure("Malloc temp failed", 1);

    ret = parse_msg(rec_mex, len, NULL, 0, NULL, bufferSupp1, iv);
    if (ret == -1)
    {
        free_n(3, iv, bufferSupp1, temp);
        return -1;
    }
    
    // Compare the hash
    sprintf((char*)temp, "%u", *nonce);
    msg_len = concat_5(&msg_to_hash, LIST_REQUEST, strlen(LIST_REQUEST),\
                                             iv, IV_LEN,\
                                             temp, LEN_SIZE, NULL, 0, NULL, 0);
    if (msg_len == -1)
    {
        free_n(3, iv, bufferSupp1, temp);
        return -1;
    }
    
    digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_len, &digest_len);
    ret = CRYPTO_memcmp(digest, bufferSupp1, HASH_LEN);
    free_n(5, iv, bufferSupp1, msg_to_hash, digest, temp);
    if (ret != 0) // If the hash comparison failed
    {
        printf("Wrong list request hash.\n");
        return -1;
    }

    printf("List request message parsed successfully\n");
    *nonce += 1;


    /* ---- Prepare the list of filenames (num_file, len. encr., encr. list, hash(num_file, encr. list, iv, nonce), iv) ---- */
    num_file = 0;
    tot_num_file = 0;

    while (ret != -1) {
        // Build the filenames' list
        bufferSupp1 = (unsigned char*) malloc((CHUNK_SIZE+1)*sizeof(unsigned char));
        if (!bufferSupp1) exit_with_failure("Malloc bufferSupp1 failed", 1);

        d = opendir("documents");   
        if(d) num_file = build_file_list(d, &tot_num_file, bufferSupp1);
        else exit_with_failure("Impossible to open path_documents", 1);     
        closedir(d);

        // Encrypt the list
        iv = (unsigned char*) malloc(sizeof(unsigned char)*IV_LEN);
        if (!iv) exit_with_failure("Malloc iv failed", 1);
        ret = RAND_bytes(iv, IV_LEN);
        if (ret != 1) exit_with_failure("RAND_bytes failed\n", 0);
        encrypt_AES_128_CBC(&ciphertext, &cipher_len, bufferSupp1, offset, iv, session_key1);
        free(bufferSupp1);

        // Prepare the hash
        bufferSupp1 = (unsigned char*) malloc(sizeof(unsigned char)*LEN_SIZE);
        if (!bufferSupp1) exit_with_failure("Malloc bufferSupp1 failed", 1);
        temp = (char*) malloc(sizeof(char)*LEN_SIZE);
        if (!temp) exit_with_failure("Malloc temp failed", 1);
        
        sprintf(temp, "%d", num_file);
        sprintf((char*)bufferSupp1, "%u", *nonce);
        msg_len = concat_5(&msg_to_hash, temp, LEN_SIZE,\
                                         ciphertext, cipher_len,\
                                         iv, IV_LEN,\
                                         bufferSupp1, LEN_SIZE, NULL, 0);
        free(bufferSupp1);
        if (msg_len == -1) 
        {
            free_n(3, iv, temp, ciphertext);
            return -1;
        }
        digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_len, &digest_len);
        free(msg_to_hash); 

        // Build the message
        sprintf(temp, "%u", num_file);
        ret = concat_5(&bufferSupp1, temp, LEN_SIZE, ciphertext, cipher_len, NULL, 0, NULL, 0, NULL, 0);
        if (msg_len == -1)
        {
            free_n(3, iv, ciphertext, digest);
            return -1;
        }

        msg_len = build_msg(&buffer, LIST_MESSAGE, cipher_len, bufferSupp1, digest, iv);
        if (msg_len == -1)
        {
            free_n(4, bufferSupp1, iv, ciphertext, digest);
            return -1;
        }

        // Send the message
        printf("I'm sending to the client the filename's list\n"); 
        ret = send(sd, buffer, msg_len, 0); 
        
        free_n(5, iv, bufferSupp1, buffer, ciphertext, digest);
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
        printf("Received the client outcome.\n");

        bufferSupp1 = (unsigned char*) malloc((TYPE_LEN+1)*sizeof(unsigned char));
        if (!bufferSupp1) exit_with_failure("Malloc bufferSupp1 failed", 1);
        memcpy(bufferSupp1, buffer, TYPE_LEN);
        memcpy(bufferSupp1+TYPE_LEN, "\0", 1);

        if (strcmp((char*) bufferSupp1, LIST_DENIED) == 0)
        {
            ret = check_reqden_msg(LIST_DENIED, buffer, *nonce, session_key1, session_key2);
            free_n(2, bufferSupp1, buffer);
            
            if (ret == -1) return -1;
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
            free_n(2, buffer, bufferSupp1);

            if (ret == -1) return -1;
            if (num_file == 0) ret = -1;
            *nonce += 1;
        }
        else
        {
            printf("We don't know what the client said...\n\n");
            free_n(2, bufferSupp1, buffer);
            return -1;
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
        return -1;
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
        operation_denied(sd, "Filename too long", RENAME_DENIED, session_key1, session_key2, nonce);
        free(plaintext);
        return -1;
    }

    filename = (char*) malloc(len_fn*sizeof(char)+1);
    if (!filename) exit_with_failure("Malloc filename failed", 0);
    memcpy(filename, plaintext, len_fn);
    *(filename+len_fn) = '\0';
    printf("The filename we should change is %s\n", filename);

    // New_filename
    old_offset = offset + BLANK_SPACE;
    offset = str_ssplit(&*(plaintext+old_offset), DELIM);
    len_newfn = (int)offset;
    if (len_newfn > MAX_LEN_FILENAME)
    {
        operation_denied(sd, "New_filename too long", RENAME_DENIED, session_key1, session_key2, nonce);
        free_2(plaintext, filename);
        return -1;
    } 
    
    new_filename = (char*) malloc(len_newfn*sizeof(char)+1);
    if (!new_filename) exit_with_failure("Malloc new_filename failed", 0);
    memcpy(new_filename, &*(plaintext+old_offset), len_newfn);
    *(new_filename+len_newfn) = '\0';
    printf("The new filename should be %s\n", new_filename);
                   
    ret = filename_sanitization (filename);
    ret += filename_sanitization (new_filename);
    if (ret <= 1) {
        operation_denied(sd, "Filename sanitization failed", RENAME_DENIED, session_key1, session_key2, nonce);
        free_3(plaintext, filename, new_filename);
        return -1;
    }

    // Execute the rename if possible, otherwise send failed message to client
    chdir("documents");
    ret = rename(filename, new_filename);
    chdir("..");
    if (ret == -1) {
        printf("Problem moving to parent directory.\n");
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
        return -1;
    }
    *nonce += 1;

    // Decrypt the filename
    decrypt_AES_128_CBC(&plaintext, &plain_len, bufferSupp1, encr_len, iv, session_key1);

    free_2(bufferSupp1, iv);

    len_fn = plain_len;
    if (len_fn > MAX_LEN_FILENAME) 
    {
        operation_denied(sd, "Filename too long", DELETE_DENIED, session_key1, session_key2, nonce);
        free(plaintext);
        return -1;
    }

    filename = (char*) malloc((len_fn+1)*sizeof(char));
    if (!filename) exit_with_failure("Malloc filename failed", 0);
    memcpy(filename, plaintext, len_fn+1); 

    // Sanitize the filename
    ret = filename_sanitization(filename);
    if (ret != 1) {
        operation_denied(sd, "Filename sanitization failed", RENAME_DENIED, session_key1, session_key2, nonce);
        free_2(plaintext, filename);
        return -1;
    }

    // Remove the file
    ret = chdir("documents/");
    if (ret == -1) exit_with_failure("Can't change directory to path_documents", 1);
    ret = remove(filename);
    ret = chdir("../");
    if (ret == -1) 
    {
        operation_denied(sd, "Something bad happened during the delete operation", RENAME_DENIED, session_key1, session_key2, nonce);
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
        printf("Wrong rename failed hash\n\n");
        return -1;
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
        printf("The length of the filename is too big, download management terminated...\n\n");
        return -1;
    }
    // HERE WE SHOULD SANITIZE THE FILENAME
    memset(filename, 0, MAX_LEN_FILENAME);
    memcpy(filename, plaintext, plain_len); 

    free_3(encr_msg, iv, plaintext);


    ret = chdir("documents");
    if (ret == -1) exit_with_failure("Can't open directory documents...", 1);
    fd = fopen(filename, "r");
    if (!(fd))
    {
        printf("File %s doesn't exist...\n  ", filename);
        operation_denied(sock, "The file doesn't exists", DOWNLOAD_DENIED, session_key1, session_key2, nonce);
        return 1;
    }
    stat(filename, &st);
    chdir("..");
    printf("The filename is %s\n", filename);
    printf("The size of the file is %ld\n", st.st_size);
    nchunk = (st.st_size/CHUNK_SIZE)+1;
    rest = st.st_size - (nchunk-1)*CHUNK_SIZE; // This is the number of bits of the final chunk

    printf("The number of chunk is %i\n", nchunk);
    printf("The number of rest is %i\n", rest);




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
           
        printf("We are sending the chunk number %i\n", i);



        buffer = (unsigned char*)malloc(BUF_LEN);
        if (!buffer) exit_with_failure("Malloc buffer failed", 1 );
        ret = recv (sock, buffer, BUF_LEN, 0);
        if (ret == -1)
        {
            printf("Receive operation gone bad\n");
            return -1;
        }
        printf("Confirmed! %s\n", (char*)buffer);
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
        return -1;
    }

    free(buffer);
    printf("We have completed successfully the donwload operation!\n\n");
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
        return -1;
    } 
    else printf("The MAC is been correctly compared!\n");
    *nonce += 1;


    //NOW WE CAN DECRYPT AND TAKE THE VALUE OF THE FILENAME DECRYPTED
    decrypt_AES_128_CBC(&plaintext, &plain_len, encr_msg, encr_len, iv, session_key1);
    if (plain_len > MAX_LEN_FILENAME)
    {
        free_6(bufferSupp1, bufferSupp2, encr_msg, iv, plaintext, buffer);
        free_2(msg_to_hash, digest);
        printf("The length of the filename is too big, download management terminated...\n\n");
        return -1;
    }
    // HERE WE SHOULD SANITIZE THE FILENAME
    memset(filename, 0, MAX_LEN_FILENAME);
    memcpy(filename, plaintext, plain_len); 

    free_6(bufferSupp1, bufferSupp2, msg_to_hash, encr_msg, plaintext, iv);
    free_3(buffer, digest, bufferSupp3);

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

    //CHECK IF FILE NOT TO LARGE 


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
        printf("Error during the operning of the file %s...\n  ", filename);
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

        iv = (unsigned char*) malloc(sizeof(unsigned char)*(IV_LEN+1));
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
            printf("Wrong download chunk hash\n\n");
            free_3(bufferSupp1, bufferSupp2, iv);
            return -1;
        }
        *nonce += 1;

        decrypt_AES_128_CBC(&plaintext, &plain_len, bufferSupp2, encr_len, iv, session_key1);

        // WRITE TO FILE
        fwrite(plaintext, sizeof(unsigned char), plain_len, fd);
        
        free_4(bufferSupp1, bufferSupp2, iv, plaintext);
        printf("We received correctly the chunk number %i\n", i);

        buffer = (unsigned char*)malloc(BUF_LEN);
        if (!buffer) exit_with_failure("Malloc buffer failed", 1 );
        memcpy(buffer, "Ciao", 5);
        ret = send(sock, buffer, BUF_LEN, 0);
        if (ret == -1)
        {
            printf("Receive operation gone bad\n");
            return -1;
        }
        printf("Confirmation sent!\n");
        free(buffer);
    }
    fclose(fd);
    
    /* ---- SEND DOWNLOAD FINISHED MESSAGE ---- */
    printf("Send download finished message.\n");
    operation_succeed(sock, DOWNLOAD_FINISHED, session_key2, nonce);
        
    return 1;
}

int shareServer(int sd, char* rec_mex, char* username, unsigned int* nonce_cs, unsigned int* nonce_sc, unsigned char* session_key1, unsigned char* session_key2)
{
    int ret;
    int sd_peer;
    int msg_len;

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

    FILE* f1;
    FILE* src_fd;

    struct sockaddr_in rcv_addr;
    int rcv_port;

    

    /* ---- Parse file received ---- */
    // receive, share_req encr_len encr(filename peername) hash(share_req encr iv nonce_cs) iv
    // SHARE REQUEST ALREADY PARSED
    temp = (char*) malloc(LEN_SIZE*sizeof(char));
    if (!temp) exit_with_failure("Malloc temp failed", 1);
    iv = (unsigned char*) malloc(IV_LEN*sizeof(unsigned char));
    if (!iv) exit_with_failure("Malloc iv failed", 1);
    bufferSupp2 = (unsigned char*) malloc(HASH_LEN*sizeof(unsigned char));
    if (!bufferSupp2) exit_with_failure("Malloc bufferSupp2 failed", 1);

    // PARSE ENCRYPTION LENGTH
    memcpy(temp, &*(rec_mex+strlen(SHARE_REQUEST)+BLANK_SPACE), LEN_SIZE);
    encr_len = atoi(temp);
    if (encr_len < 0 || encr_len > (MAX_LEN_FILENAME+MAX_LEN_USERNAME+BLOCK_SIZE+1))
    {
        free_3(temp, iv, bufferSupp2);
        printf("Encryption length too high.\n");
        return -1;
    }

    // PARSE ENCRYPTED MESSAGE
    bufferSupp1 = (unsigned char*) malloc(encr_len*sizeof(unsigned char));
    if (!bufferSupp1) exit_with_failure("Malloc bufferSupp1 failed", 1);
    memcpy(bufferSupp1, &*(rec_mex+strlen(SHARE_REQUEST)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE),\
        encr_len);

    // PARSE IV
    memcpy(iv, &*(rec_mex+strlen(SHARE_REQUEST)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE+encr_len+\
        BLANK_SPACE+HASH_LEN+BLANK_SPACE), IV_LEN);

    // PARSE HASH AND CHECK IT
    memcpy(bufferSupp2, &*(rec_mex+strlen(SHARE_REQUEST)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE),\
        HASH_LEN);

    sprintf(temp, "%u", *nonce_cs);
    msg_to_hash_len = build_msg_4(&msg_to_hash, SHARE_REQUEST, strlen(SHARE_REQUEST),\
                                               bufferSupp1, encr_len,\
                                               iv, IV_LEN,\
                                               temp, LEN_SIZE);
    if (msg_to_hash_len == -1) exit_with_failure("Something bad happened building the hash...", 0);

    digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len);

    ret = CRYPTO_memcmp(digest, bufferSupp2, HASH_LEN);
        
    free_4(bufferSupp2, temp, msg_to_hash, digest);
        
    if (ret != 0)
    {
        printf("Wrong share_request hash.\n");
        free_2(bufferSupp1, iv);
        return -1;
    } 
    else 
    {
        printf("Hash is correct.\n");
        *nonce_cs = *nonce_cs + 1;
    }

    // DECRYPT THE MESSAGE
    decrypt_AES_128_CBC(&plaintext, &plain_len, bufferSupp1, encr_len, iv, session_key1);
    free_2(iv, bufferSupp1); 

    len_fn = str_ssplit(plaintext, DELIM);
    bufferSupp1 = (unsigned char*) malloc((len_fn+1)*sizeof(unsigned char));
    if (!bufferSupp1) exit_with_failure("Malloc bufferSupp1 failed", 1);
    memcpy(bufferSupp1, plaintext, len_fn);
    *(bufferSupp1+len_fn) = '\0';

    len_pn = plain_len - len_fn - BLANK_SPACE;
    bufferSupp2 = (unsigned char*) malloc((len_pn+1)*sizeof(unsigned char));
    if (!bufferSupp2) exit_with_failure("Malloc bufferSupp2 failed", 1);
    memcpy(bufferSupp2, &*(plaintext+len_fn+BLANK_SPACE), len_pn);
    *(bufferSupp2+len_pn) = '\0';

    free(plaintext);

    // sanitize them ???


    // NOW WE ARE INSIDE database/username, we should try to move inside database/peername/documents
    ret = chdir(".."); // database/
    if (ret == -1)
    {
        free_2(bufferSupp1, bufferSupp2);
        printf("I'm having some problem changing directory...\n");
        return -1;
    }
    ret = chdir((char*) bufferSupp2); // database/peername
    if (ret == -1)
    {
        free_2(bufferSupp1, bufferSupp2);
        printf("I'm having some problem moving into peername...\n");
        return -1;
    }
    ret = chdir("documents"); // database/peername/documents
    if (ret == -1)
    {
        free_2(bufferSupp1, bufferSupp2);
        printf("I'm having some problem moving into documents...\n");
        return -1;
    }
    


    // TRY TO OPEN PEERNAME'S FILE TO SHARE
    f1 = fopen((char*) bufferSupp1, "r");
    if (!f1)
    {
        printf("The sharer doesn't have any file called \"%s\"\n", bufferSupp1);
        // Send denied message to left party
        operation_denied(sd, "No such file", SHARE_DENIED, session_key1, session_key2, nonce_cs);
        free_2(bufferSupp1, bufferSupp2);
        return 1;
    }
    fclose(f1);


    // We should ask to the receiver whether it wants to allow the share operation
    // Save on database/info/peername.txt the socket descriptor of the peername
    path_temp = (char*) malloc((len_pn+4)*sizeof(char));
    if (!path_temp) exit_with_failure("Malloc path_temp failed", 1);
    memcpy(path_temp, bufferSupp2, len_pn-1);
    memcpy(path_temp+len_pn-1, ".txt\0", 5);

    temp = (char*) malloc(LEN_SIZE*sizeof(char));
    if (!temp) exit_with_failure("Malloc temp failed", 1);

    ret = chdir("../../info");
    if (ret == -1)
    {
        free_4(bufferSupp1, bufferSupp2, temp, path_temp);
        printf("I'm having some problem moving into info directory...\n");
        return -1;
    }

    // Here we take the port and the session keys
    f1 = fopen(path_temp, "r");
    if (!f1) 
    {
        free_4(bufferSupp1, bufferSupp2, temp, path_temp);
        printf("I'm having some problem opening path_temp...\n");
        return -1;
    }
    ret = fread(temp, sizeof(char), PORT_SIZE, f1);
    if (ret == -1)
    {
        printf("Problem during the reading of the file to share...\n");
        free_4(bufferSupp1, bufferSupp2, temp, path_temp);
        operation_denied(sd, "General error", SHARE_DENIED, session_key1, session_key2, nonce_cs);
        return -1;
    }
    ret = fread(peer_session_key1, sizeof(unsigned char), 16, f1);
    if (ret == -1)
    {
        printf("Problem during the reading of the file to share...\n");
        free_4(bufferSupp1, bufferSupp2, temp, path_temp);
        operation_denied(sd, "General error", SHARE_DENIED, session_key1, session_key2, nonce_cs);
        return -1;
    }
    ret = fread(peer_session_key2, sizeof(unsigned char), 16, f1);
    if (ret == -1)
    {
        printf("Problem during the reading of the file to share...\n");
        free_4(bufferSupp1, bufferSupp2, temp, path_temp);
        operation_denied(sd, "General error", SHARE_DENIED, session_key1, session_key2, nonce_cs);
        return -1;
    }

    fclose(f1);

    chdir("..");
    chdir((char*) bufferSupp2);
    chdir("documents");

    rcv_port = atoi(temp);

    memset(&rcv_addr, 0, sizeof(rcv_addr));
	rcv_addr.sin_family = AF_INET;
	rcv_addr.sin_port = htons(rcv_port);
	inet_pton(AF_INET, LOCALHOST, &rcv_addr.sin_addr);

    sd_peer = createSocket();
    if (connect(sd_peer, (struct sockaddr*)&rcv_addr, sizeof(rcv_addr)) < 0) 
    {
        printf("Connection Failed\n");
        operation_denied(sd, "General error", SHARE_DENIED, session_key1, session_key2, nonce_cs);
        return -1;
    }

    free_2(temp, path_temp);



    /* ---- Send share_perm to peer ---- */
    // share_perm encr_len encr(filename peername) hash(share_perm encr iv nonce_sc) iv
    temp = (char*) malloc(LEN_SIZE*sizeof(char));
    if (!temp) exit_with_failure("Malloc temp failed", 1);
    temp2 = (char*) malloc(LEN_SIZE*sizeof(char));
    if (!temp2) exit_with_failure("Malloc temp2 failed", 1);


    // GENERATE THE IV
    iv = (unsigned char*) malloc(sizeof(unsigned char)*IV_LEN);
    if (!iv) exit_with_failure("Malloc iv failed", 1);
    ret = RAND_poll(); // Seed OpenSSL PRNG
    if (ret != 1) exit_with_failure("RAND_poll failed\n", 0);
    ret = RAND_bytes((unsigned char*)&iv[0], IV_LEN);

    // CREATE ENCRYPTED MESSAGE
    msg_to_encr_len = build_msg_2(&msg_to_encr, bufferSupp1, len_fn,\
                                                bufferSupp2, len_pn+1);
    if (msg_to_encr_len == -1) exit_with_failure("Something bad happened building the message to encrypt...", 0);

    encrypt_AES_128_CBC(&encr_msg, &encr_len, msg_to_encr, msg_to_encr_len, iv, peer_session_key1);

    // CREATE THE HASH
    sprintf(temp, "%u", *nonce_sc);
    msg_to_hash_len = build_msg_4(&msg_to_hash, SHARE_PERMISSION, strlen(SHARE_PERMISSION),\
                                                encr_msg, encr_len,\
                                                iv, IV_LEN,\
                                                temp, LEN_SIZE);
    if (msg_to_hash_len == -1) exit_with_failure("Something bad happened building the hash...", 0);

    digest = hmac_sha256(peer_session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len);

    // BUILD THE MESSAGE
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
        *nonce_sc = *nonce_sc + 1;
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
        ret = check_reqden_msg(SHARE_DENIED, buffer, *nonce_sc, peer_session_key1, peer_session_key2);
        if (ret == -1) 
        {
            printf("Error checking share denied message.\n");
            operation_denied(sd, "Error checking share denied message", SHARE_DENIED, session_key1, session_key2, nonce_cs);
            ret = -1;
        }
        else 
        {
            printf("Share has been denied.\n");
            *nonce_sc += 1;
            operation_denied(sd, "Share has been denied", SHARE_DENIED, session_key1, session_key2, nonce_cs);
            ret = 1;
        }
        
        free_4(buffer, bufferSupp1, bufferSupp2, bufferSupp3);
        return ret;
    }
    else if (strcmp((char*) bufferSupp3, SHARE_ACCEPTED) == 0)
    {
        ret = check_reqacc_msg(SHARE_ACCEPTED, buffer, *nonce_sc, peer_session_key2);
        if (ret == -1) 
        {
            printf("Error checking share accepted message.\n");
            operation_denied(sd, "Error checking share accepted message", SHARE_DENIED, session_key1, session_key2, nonce_cs);
            return -1;
        }
        *nonce_sc += 1;
    }
    else
    {
        printf("We don't know what the peer said...\n\n");
        operation_denied(sd, "We don't know what the peer said", SHARE_DENIED, session_key1, session_key2, nonce_cs);
        free_4(buffer, bufferSupp1, bufferSupp2, bufferSupp3);
        return -1;
    }

    free_2(bufferSupp3, buffer);

    // COPY THE FILE IN THE FOLDER OF THE REICEIVER, we are in database/peername/documents
    printf("The receiver is allowing the share operation...\n");

    path_temp = (char*) malloc((6+(len_pn-1)+1+10+len_fn+1)*sizeof(char));
    memcpy(path_temp, "../../", 6);
    memcpy(&*(path_temp+6), username, strlen(username));
    memcpy(&*(path_temp+6+strlen(username)), "/", 1);
    memcpy(&*(path_temp+6+strlen(username)+1), "documents/", 10);
    memcpy(&*(path_temp+6+strlen(username)+1+10), bufferSupp1, len_fn);
    memcpy(&*(path_temp+6+strlen(username)+1+10+len_fn), "\0", 1);
    printf("%s\n%s\n", path_temp, bufferSupp1);

    src_fd = fopen((char*) bufferSupp1, "r");
    f1 = fopen(path_temp, "w");
    if (!src_fd || !f1) 
    {
        free_3(path_temp, bufferSupp1, bufferSupp2);
        printf("Can't open f1 or src_fd...\n");
        operation_denied(sd, "General error", SHARE_DENIED, session_key1, session_key2, nonce_cs);
        return -1;
    } 

    buffer = (unsigned char*) malloc(BUF_LEN*sizeof(unsigned char));
    if (!buffer) exit_with_failure("Malloc buffer failed", 1);

    while (1) {
        ret = fread(buffer, sizeof(unsigned char), BUF_LEN, src_fd);
        if (ret == -1) {
            printf("Error reading file.\n");
            free_4(path_temp, buffer, bufferSupp1, bufferSupp2);
            operation_denied(sd, "General error", SHARE_DENIED, session_key1, session_key2, nonce_cs);
            return -1;
        }
    
        if (ret == 0) break;

        ret = fwrite(buffer, sizeof(unsigned char), ret, f1);
        if (ret == -1) {
            printf("Error writing to file.\n");
            free_4(path_temp, buffer, bufferSupp1, bufferSupp2);
            operation_denied(sd, "General error", SHARE_DENIED, session_key1, session_key2, nonce_cs);
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
