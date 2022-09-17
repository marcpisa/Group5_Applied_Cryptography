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

int loginServer(int sd, char* rec_mex, char** username, user_stat** user_list, unsigned char* session_key1, unsigned char* session_key2)
{
    int nonce_cs = 0; // CHECK WRAPPING UP, SHOULD BE UNSIGNED?? ENOGUH FOR 4GB?
    
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

    char funcBuff[BUF_LEN];
    char funcSupp1[BUF_LEN];

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
    if (len_username > MAX_LEN_USERNAME) exit_with_failure("Username too long", 0);
    if (!username_sanitization((char*) bufferSupp1)) exit_with_failure("Username sanitization fails.\n", 0);

    ret = chdir(MAIN_FOLDER_SERVER);
    if (ret == -1) exit_with_failure("No such directory.\n", 0);
    ret = chdir((char*) bufferSupp1);
    if (ret == -1) exit_with_failure("Error: username doesn't exists...\n", 0);
  
    // Server checks if the user is already online
    for(int i = 0; i < NUM_USER; i++)
    {
        if (strcmp((*user_list+i)->username, (char*)bufferSupp1) == 0)
        {
            if ((*user_list+i)->connected == 1)
            {
                exit_with_failure("User already online", 0);
            }
        }
    }
    printf("User is not online.\n");

    memcpy(*username, bufferSupp1, len_username);
    memcpy(&*(*username+len_username), "\0", 1);

    // Retrieve the client pubkey (from the client cert., already owned by the server)
    path_cert_client_rsa = (char*) malloc(sizeof(char)*(5+len_username+4+1));
    memcpy(path_cert_client_rsa, "cert_", 5);
    memcpy(&*(path_cert_client_rsa+5), *username, len_username);
    memcpy(&*(path_cert_client_rsa+5+len_username), ".pem\0", 4+1);
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
    signature = sign_msg(path_rsa_key, msg_to_sign, msg_to_sign_len, &signature_len, 1);
 
    // Serialize the certificate
    cert_byte = read_cert(path_cert_rsa, &cert_len);

    // Come back to the user directory
    ret = chdir("../database/");
    if (ret == -1) exit_with_failure("No such directory.\n", 0);
    ret = chdir(*username);
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
    free(bufferSupp1);
    free(msg_to_sign);
    free(K);
    EVP_PKEY_free(pub_rsa_client);
    
    // Set user to online
    for(int i = 0; i < NUM_USER; i++)
    {
        if (strcmp((*user_list+i)->username, *username) == 0)
        {
            (*user_list+i)->connected = 1;
            break;
        }
    }
    
    // FUNCTIONAL PART
    // Now that we have the cryptographic elements to have a secure communication with the client we are able to receive function messages
    
    printf("I managed a login request and all was good!\n\n");
    
    //printf("Now the buffer contains %s\n\n", funcBuff);
    while (1)
    {
        memset(funcBuff, 0, BUF_LEN);
        ret = recv(sd, funcBuff, BUF_LEN, 0);
        if (ret < 0)
        {
            perror("Error during recv operation: ");
            exit(-1);
        }
        // We check the first keyword to understand what the Client wants us to do
        memset(funcSupp1, 0, BUF_LEN);
        memcpy(funcSupp1, funcBuff, str_ssplit((unsigned char*) funcBuff, DELIM));


        // ************ LOGIN REQUEST MANAGER ***********
        if (strcmp(funcSupp1, LOGIN_REQUEST) == 0)
        {
            printf("\nWe received a login request but this client is already logged... Something bad happened...\n\n");
        }


        //************ LOGOUT REQUEST MANAGER ************
        else if (strcmp(funcSupp1, LOGOUT_REQUEST) == 0)
        {
            printf("\nA logout request has came up...\n\n");
            // LOGOUT MANAGER: SERVER SIDE
                            
            ret = logoutServer(sd, funcBuff, &nonce_cs, session_key2);
            if (ret == -1)
            {
                printf("Something bad happened during the management of the client logout request...\n\n");
                exit(1);
            }
            else printf("I managed a logout request and all was good!\n\n");

            printf("End of logout request management!\n\n");
            close(sd);
            exit(0);
        }


        // ************* LIST REQUEST MANAGER ***************
        else if (strcmp(funcSupp1, LIST_REQUEST) == 0)
        {
            printf("\nA list request has came up...\n\n");
            // LIST MANAGER: SERVER SIDE
                            
            ret = listServer(sd, funcBuff);
            if (ret == -1)
            {
                printf("Something bad happened during the management of the client list request...\n\n");
                exit(1);
            }
            else printf("I managed a list request and all was good!\n\n");
        }


        //*************** RENAME REQUEST MANAGER *****************
        else if (strcmp(funcSupp1, RENAME_REQUEST) == 0)
        {
            printf("\nA rename request has came up...\n\n");
            // RENAME MANAGER: SERVER SIDE
                            
            ret = renameServer(sd, funcBuff);
            if (ret == -1)
            {
                printf("Something bad happened during the management of the client rename request...\n\n");
                exit(1);
            }
            else printf("End of rename request management!\n\n");
        }


        // **************** DELETE REQUEST MANAGER ******************
        else if (strcmp(funcSupp1, DELETE_REQUEST) == 0)
        {
            printf("\nA delete request has came up...\n\n");
            // DELETE MANAGER: SERVER SIDE
                            
            ret = deleteServer(sd, funcBuff);
            if (ret == -1)
            {
                printf("Something bad happened during the management of the client delete request...\n\n");
                exit(1);
            }
            else printf("I managed a delete request and all was good!\n\n");
        }

        
        // *************** DOWNLOAD REQUEST MANAGER ****************
        else if (strcmp(funcSupp1, DOWNLOAD_REQUEST) == 0)
        {
            printf("\nA download request has came up...\n\n");

            // DOWNLOAD MANAGER: SERVER SIDE
                            
            ret = downloadServer(sd, funcBuff, username, &nonce_cs, session_key1, session_key2);
            if (ret == -1)
            {
                printf("Something bad happened during the management of the client download request...\n\n");
                exit(1);
            }
            else printf("I managed a download request and all was good!\n\n");
        }


        // *************** UPLOAD REQUEST MANAGER ***************
        else if (strcmp(funcSupp1, UPLOAD_REQUEST) == 0)
        {
            printf("\nAn upload request has came up...\n\n");
            // UPLOAD MANAGER: SERVER SIDE
                            
            ret = uploadServer(sd, funcBuff);
            if (ret == -1)
            {
                printf("Something bad happened during the management of the client upload request...\n\n");
                exit(1);
            }
            else printf("I managed an upload request and all was good!\n\n");
        }


        // **************** SHARE REQUEST MANAGER ****************
        else if (strcmp(funcSupp1, SHARE_REQUEST) == 0)
        {
            printf("\nA share request has came up...\n\n");
            // SHARE MANAGER: SERVER SIDE
                            
            ret = shareServer(sd, funcBuff);
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

int logoutServer(int sd, char* rec_mex, char* username, user_stat** user_list, int* nonce, unsigned char* session_key1, unsigned char* session_key2)
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
    *nonce = *nonce + 1;
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
    if (ret == -1) operation_denied(sd, "Wrong logout request hash", LOGOUT_DENIED, session_key1, session_key2, nonce);
    

    free(bufferSupp1);
    free(bufferSupp2);
    free(bufferSupp3);
    free(temp);
    free(digest);
    free(msg_to_hash);

    // Set user to offline
    for(int i = 0; i < NUM_USER; i++)
    {
        if (strcmp((*user_list+i)->username, username) == 0)
        {
            (*user_list+i)->connected = 0;
            break;
        }
    }


    return 1;

}

int listServer(int sd, char* rec_mex, char* username, int* nonce, unsigned char* session_key1, unsigned char* session_key2)
{
    DIR* d;
    struct dirent *files;
    char* path_documents;

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
    // ret = RAND_bytes((unsigned char*)&iv[0], IV_LEN);
    // if (ret != 1) exit_with_failure("RAND_bytes failed\n", 0);

    // Build path
    path_documents = (char*) malloc((15+strlen(username)+11+1)*sizeof(char));
    memcpy(path_documents, "../../database/", 15);
    memcpy(&*(path_documents+15), username, strlen(username));
    memcpy(&*(path_documents+15+strlen(username)), "/documents/\0", (11+1));

    /* ---- Parse the list request (req., hash(req, iv, nonce), iv) ---- */
    *nonce = *nonce+1;

    bufferSupp1 = (unsigned char*) malloc(HASH_LEN*sizeof(unsigned char));
    if (!bufferSupp1) exit_with_failure("Malloc bufferSupp1 failed", 1);

    // Parsing
    old_offset = strlen(LIST_REQUEST)+BLANK_SPACE;
    memcpy(bufferSupp1, &*(rec_mex+old_offset), HASH_LEN); // hash
    old_offset += HASH_LEN+BLANK_SPACE;
    memcpy(iv, &*(rec_mex+old_offset), IV_LEN); // iv

    // Compare the hash
    msg_to_hash_len = strlen(LIST_REQUEST)+BLANK_SPACE+IV_LEN+BLANK_SPACE+LEN_SIZE;
    msg_to_hash = (unsigned char*) malloc(sizeof(unsigned char)*msg_to_hash_len);
    if (!msg_to_hash) exit_with_failure("Malloc msg_to_hash failed", 1);
    temp = (char*) malloc(sizeof(char)*LEN_SIZE);
    if (!temp) exit_with_failure("Malloc temp failed", 1);

    sprintf(temp, "%d", *nonce);
    memcpy(msg_to_hash, LIST_REQUEST, strlen(LIST_REQUEST));  // list req
    memcpy(&*(msg_to_hash+strlen(LIST_REQUEST)), " ", BLANK_SPACE);
    memcpy(&*(msg_to_hash+strlen(LIST_REQUEST)+BLANK_SPACE), iv, IV_LEN); // iv
    memcpy(&*(msg_to_hash+strlen(LIST_REQUEST)+BLANK_SPACE+IV_LEN), " ", BLANK_SPACE);
    memcpy(&*(msg_to_hash+strlen(LIST_REQUEST)+BLANK_SPACE+IV_LEN+BLANK_SPACE), \
    temp, LEN_SIZE); // nonce
    
    digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len);

    ret = CRYPTO_memcmp(digest, bufferSupp1, HASH_LEN);
    
    free(iv);
    free(bufferSupp1);
    free(msg_to_hash);
    free(digest);
    free(temp);
    
    if (ret == -1) // If the hash comparison failed
    {
        operation_denied(sd, "Hash incorrect", LIST_DENIED, session_key1, session_key2, nonce);
        return 1;
    }

    printf("List request message parsed successfully\n\n");




    /* ---- Prepare the list of filenames (num_file, len. encr., encr. list, hash(num_file, encr. list, iv, nonce), iv) ---- */
    offset = 0;
    len_filename = 0;
    num_file = 0;
    tot_num_file = 0;

    while (num_file != -1) {
        // Build the filenames' list
        bufferSupp1 = (unsigned char*) malloc((CHUNK_SIZE+1)*sizeof(unsigned char));
        if (!bufferSupp1) exit_with_failure("Malloc bufferSupp1 failed", 1);

        d = opendir(path_documents);        
        
        // If this is the second list of filenames, reset the pointer to the prev. position
        for (int i = 0; i < tot_num_file; i++) files = readdir(d);

        num_file = 0;
        if(d)
        {
            while((files = readdir(d)) != NULL)
            {
                // Skip these two files
                if (!strcmp(files->d_name, ".") || !strcmp(files->d_name, "..")) continue;
                
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
        closedir(d);

        // Encrypt the list
        iv = (unsigned char*) malloc(sizeof(unsigned char)*IV_LEN);
        if (!iv) exit_with_failure("Malloc iv failed", 1);
        ret = RAND_bytes(iv, IV_LEN);
        if (ret != 1) exit_with_failure("RAND_bytes failed\n", 0);
        ciphertext = (unsigned char*) malloc((offset+BLOCK_SIZE)*sizeof(unsigned char));
        if (!ciphertext) exit_with_failure("Malloc ciphertext failed", 1);
        encrypt_AES_128_CBC(&ciphertext, &cipher_len, bufferSupp1, offset, iv, session_key1);
        if (cipher_len > (CHUNK_SIZE+BLOCK_SIZE)) exit_with_failure("Wrong ciphertext length, more than CHUNK+BLOCK size", 0);

        // Prepare the hash
        *nonce = *nonce + 1;
        msg_to_hash_len = LEN_SIZE+BLANK_SPACE+cipher_len+BLANK_SPACE+IV_LEN+BLANK_SPACE+LEN_SIZE;
        msg_to_hash = (unsigned char*) malloc(sizeof(unsigned char)*msg_to_hash_len);
        if (!msg_to_hash) exit_with_failure("Malloc msg_to_hash failed", 1);
        temp = (char*) malloc(sizeof(char)*LEN_SIZE);
        if (!temp) exit_with_failure("Malloc temp failed", 1);

        sprintf(temp, "%d", num_file);
        memcpy(msg_to_hash, temp, LEN_SIZE);  // num. file
        memcpy(&*(msg_to_hash+LEN_SIZE), " ", BLANK_SPACE);
        memcpy(&*(msg_to_hash+LEN_SIZE+BLANK_SPACE), ciphertext, cipher_len); // encr. list
        memcpy(&*(msg_to_hash+LEN_SIZE+BLANK_SPACE+cipher_len), " ", BLANK_SPACE);
        memcpy(&*(msg_to_hash+LEN_SIZE+BLANK_SPACE+cipher_len+BLANK_SPACE), \
        iv, IV_LEN); // iv
        memcpy(&*(msg_to_hash+LEN_SIZE+BLANK_SPACE+cipher_len+BLANK_SPACE+IV_LEN), \
        " ", BLANK_SPACE);
        sprintf(temp, "%d", *nonce);
        memcpy(&*(msg_to_hash+LEN_SIZE+BLANK_SPACE+cipher_len+BLANK_SPACE+IV_LEN+ \
        BLANK_SPACE), temp, LEN_SIZE); // nonce

        digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len);  

        // Build the message
        msg_len = LEN_SIZE+BLANK_SPACE+LEN_SIZE+BLANK_SPACE+cipher_len+BLANK_SPACE+HASH_LEN \
        +BLANK_SPACE+IV_LEN+1; // max. length
        buffer = (unsigned char*) malloc(sizeof(unsigned char)*msg_len);
        if (!buffer) exit_with_failure("Malloc buffer failed", 1);

        sprintf(temp, "%d", num_file);
        memcpy(buffer, temp, LEN_SIZE); // num. file
        memcpy(&*(buffer+LEN_SIZE), " ", BLANK_SPACE);
        sprintf(temp, "%d", cipher_len);
        memcpy(&*(buffer+LEN_SIZE+BLANK_SPACE), temp, LEN_SIZE); // len. encr.
        memcpy(&*(buffer+LEN_SIZE+BLANK_SPACE+LEN_SIZE), " ", BLANK_SPACE);
        memcpy(&*(buffer+LEN_SIZE+BLANK_SPACE+LEN_SIZE+BLANK_SPACE), \
        ciphertext, cipher_len); // encr. list
        memcpy(&*(buffer+LEN_SIZE+BLANK_SPACE+LEN_SIZE+BLANK_SPACE+ \
        cipher_len), " ", BLANK_SPACE);
        memcpy(&*(buffer+LEN_SIZE+BLANK_SPACE+LEN_SIZE+BLANK_SPACE+ \
        cipher_len+BLANK_SPACE), digest, HASH_LEN); // hash
        memcpy(&*(buffer+LEN_SIZE+BLANK_SPACE+LEN_SIZE+BLANK_SPACE+ \
        cipher_len+BLANK_SPACE+HASH_LEN), " ", BLANK_SPACE);
        memcpy(&*(buffer+LEN_SIZE+BLANK_SPACE+LEN_SIZE+BLANK_SPACE+ \
        cipher_len+BLANK_SPACE+HASH_LEN+BLANK_SPACE), iv, IV_LEN); // iv

        memcpy(&*(buffer+LEN_SIZE+BLANK_SPACE+LEN_SIZE+BLANK_SPACE+ \
        cipher_len+BLANK_SPACE+HASH_LEN+BLANK_SPACE+IV_LEN), "\0", 1);

        printf("I'm sending to the client the filename's list\n"); 
        ret = send(sd, buffer, msg_len, 0); 
        if (ret == -1) exit_with_failure("Send failed", 1);

        free(temp);
        free(bufferSupp1);
        free(buffer);
        free(ciphertext);
        free(digest);
        free(msg_to_hash);
        free(iv);



        /* ---- Check if the client succeed or failed ---- */
        *nonce = *nonce+1;

        msg_len = strlen(LIST_DENIED)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE+BUF_LEN+BLANK_SPACE+HASH_LEN+BLANK_SPACE+IV_LEN;
        buffer = (unsigned char*) malloc(sizeof(unsigned char)*msg_len);
        if (!buffer) exit_with_failure("Malloc buffer failed", 1);

        ret = recv(sd, buffer, msg_len,0);
        if (ret == -1) exit_with_failure("Receive failed", 0);
        printf("Received the client outcome.\n");

        bufferSupp1 = (unsigned char*) malloc(strlen(LIST_DENIED)*sizeof(unsigned char));
        if (!bufferSupp1) exit_with_failure("Malloc bufferSupp1 failed", 1);
        memcpy(bufferSupp1, buffer, strlen(LIST_DENIED)); // denied or accepted same length

        if (strcmp((char*) bufferSupp1, LIST_DENIED) == 0)
        {
            ret = check_reqden_msg(LIST_DENIED, buffer, *nonce, session_key1, session_key2);
            if (ret == -1) exit_with_failure("Error checking list denied message", 0);
            else 
            {
                free(bufferSupp1);
                free(buffer);
                free(path_documents);

                return 1;
            }
        }
        else if (strcmp((char*) bufferSupp1, LIST_ACCEPTED) == 0)
        {
            ret = check_reqacc_msg(LIST_ACCEPTED, buffer, *nonce, session_key2);
            if (ret == -1) exit_with_failure("Error checking list accepted message", 0);
            if (num_file == 0) num_file = -1;
        }
        else
        {
            printf("We don't know what the client said...\n\n");
            free(bufferSupp1);
            free(buffer);
            free(path_documents);
            return 1;
        }
    }

    free(path_documents);
    return 1;
}

int renameServer(int sd, char* rec_mex, int* nonce, unsigned char* session_key1, unsigned char* session_key2)
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
    //ret = RAND_bytes((unsigned char*)&iv[0], IV_LEN);
    //if (ret != 1) exit_with_failure("RAND_bytes failed\n", 0);


    /* ---- Parse first message (request, len encr., encr(name + new_name), hash(request, encr, iv, nonce), iv) ---- */
    *nonce = *nonce+1;

    bufferSupp2 = (unsigned char*) malloc(HASH_LEN*sizeof(unsigned char));
    if (!bufferSupp2) exit_with_failure("Malloc bufferSupp2 failed", 1);
    temp = (char*) malloc(LEN_SIZE*sizeof(char));
    if (!temp) exit_with_failure("Malloc temp failed", 1);
    
    
    offset = strlen(RENAME_REQUEST)+BLANK_SPACE;
    memcpy(temp, &*(rec_mex+offset), LEN_SIZE); // len. encr.
    offset += LEN_SIZE+BLANK_SPACE;
    encr_len = atoi(temp);

    bufferSupp1 = (unsigned char*) malloc(encr_len*sizeof(unsigned char));

    memcpy(bufferSupp1, &*(rec_mex+offset), encr_len); // encr
    offset += encr_len+BLANK_SPACE;

    memcpy(bufferSupp2, &*(rec_mex+offset), HASH_LEN); // hash
    offset += HASH_LEN+BLANK_SPACE;
    
    memcpy(iv, &*(rec_mex+offset), IV_LEN); // iv
    
    // Check hash
    msg_to_hash_len = strlen(RENAME_REQUEST)+BLANK_SPACE+encr_len+BLANK_SPACE+IV_LEN+BLANK_SPACE+LEN_SIZE;
    msg_to_hash = (unsigned char*) malloc(msg_to_hash_len*sizeof(unsigned char));

    sprintf(temp, "%d", *nonce);
    memcpy(msg_to_hash, RENAME_REQUEST, strlen(RENAME_REQUEST)); // rename req.
    memcpy(&*(msg_to_hash+strlen(RENAME_REQUEST)), " ", BLANK_SPACE);
    memcpy(&*(msg_to_hash+strlen(RENAME_REQUEST)+BLANK_SPACE), bufferSupp1, encr_len); // encr.  
    memcpy(&*(msg_to_hash+strlen(RENAME_REQUEST)+BLANK_SPACE+encr_len), " ", BLANK_SPACE);
    memcpy(&*(msg_to_hash+strlen(RENAME_REQUEST)+BLANK_SPACE+encr_len+BLANK_SPACE), iv, IV_LEN); // iv
    memcpy(&*(msg_to_hash+strlen(RENAME_REQUEST)+BLANK_SPACE+encr_len+BLANK_SPACE+IV_LEN), " ", BLANK_SPACE);
    memcpy(&*(msg_to_hash+strlen(RENAME_REQUEST)+BLANK_SPACE+encr_len+BLANK_SPACE+IV_LEN+BLANK_SPACE), \
    temp, LEN_SIZE); // nonce

    // If hash correct, decrypt
    digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len);

    ret = CRYPTO_memcmp(digest, bufferSupp2, HASH_LEN);
    if (ret == -1) 
    {
        operation_denied(sd, "Wrong rename request hash", RENAME_DENIED, session_key1, session_key2, nonce);
        
        free(bufferSupp1);
        free(bufferSupp2);        
        free(temp);
        free(iv);
        free(msg_to_hash);
        free(digest);

        return -1;
    }

    decrypt_AES_128_CBC(&plaintext, &plain_len, bufferSupp1, encr_len, iv, session_key1);

    free(bufferSupp1);
    free(bufferSupp2);        
    free(temp);
    free(iv);
    free(msg_to_hash);
    free(digest);


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

    filename = (char*) malloc(len_fn*sizeof(char));
    if (!filename) exit_with_failure("Malloc filename failed", 0);
    memcpy(filename, plaintext, len_fn); 

    // New_filename
    old_offset = offset + BLANK_SPACE;
    offset = str_ssplit(&*(plaintext+old_offset), DELIM);
    len_newfn = (int)offset;
    if (len_newfn > MAX_LEN_FILENAME)
    {
        operation_denied(sd, "New_filename too long", RENAME_DENIED, session_key1, session_key2, nonce);
        
        free(plaintext);
        free(filename);
        return -1;
    } 
    
    new_filename = (char*) malloc(len_newfn*sizeof(char));
    if (!new_filename) exit_with_failure("Malloc new_filename failed", 0);
    memcpy(new_filename, &*(plaintext+old_offset), len_newfn);
                   
    ret = filename_sanitization (filename, "/");
    ret += filename_sanitization (new_filename, "/");
    if (ret <= 1) {
        operation_denied(sd, "Filename sanitization failed", RENAME_DENIED, session_key1, session_key2, nonce);

        
        free(plaintext);
        free(filename);
        free(new_filename);
        return -1;
    }

    // Execute the rename if possible, otherwise send failed message to client
    ret = rename(filename, new_filename);
    if (ret == -1) {
        operation_denied(sd, "Something bad happened during the rename operation", RENAME_DENIED, session_key1, session_key2, nonce);

        
        free(plaintext);
        free(filename);
        free(new_filename);
        return -1;
    }
    
    free(plaintext);
    free(filename);
    free(new_filename);


    // Send success message to the client
    operation_succeed(sd, RENAME_ACCEPTED, session_key2, nonce);
    
    return 1;
}

int deleteServer(int sd, char* rec_mex, int* nonce, unsigned char* session_key1, unsigned char* session_key2)
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
    unsigned char* bufferSupp1;
    unsigned char* bufferSupp2;

    char* filename; 
    int len_fn; 

    iv = (unsigned char*) malloc(sizeof(unsigned char)*IV_LEN);
    if (!iv) exit_with_failure("Malloc iv failed", 1);
    ret = RAND_poll(); // Seed OpenSSL PRNG
    if (ret != 1) exit_with_failure("RAND_poll failed\n", 0);
    //ret = RAND_bytes((unsigned char*)&iv[0], IV_LEN);
    //if (ret != 1) exit_with_failure("RAND_bytes failed\n", 0);

    /* ---- Parse first message (request, len encr., encr(name + new_name), hash(request, encr, iv, nonce), iv) ---- */
    *nonce = *nonce + 1;

    bufferSupp2 = (unsigned char*) malloc(HASH_LEN*sizeof(unsigned char));
    if (!bufferSupp2) exit_with_failure("Malloc bufferSupp2 failed", 1);
    temp = (char*) malloc(LEN_SIZE*sizeof(char));
    if (!temp) exit_with_failure("Malloc temp failed", 1);

    offset = strlen(DELETE_REQUEST)+BLANK_SPACE;
    memcpy(temp, &*(rec_mex+offset), LEN_SIZE); // len. encr.
    offset += LEN_SIZE+BLANK_SPACE;
    encr_len = atoi(temp);

    bufferSupp1 = (unsigned char*) malloc(encr_len*sizeof(unsigned char));
    if (!bufferSupp1) exit_with_failure("Malloc bufferSupp1 failed", 1);

    memcpy(bufferSupp1, &*(rec_mex+offset), encr_len); // encr
    offset += encr_len+BLANK_SPACE;

    memcpy(bufferSupp2, &*(rec_mex+offset), HASH_LEN); // hash
    offset += HASH_LEN+BLANK_SPACE;
    
    memcpy(iv, &*(rec_mex+offset), IV_LEN); // iv

    msg_to_hash_len = strlen(DELETE_REQUEST)+BLANK_SPACE+encr_len+BLANK_SPACE+IV_LEN+BLANK_SPACE+LEN_SIZE;
    msg_to_hash = (unsigned char*) malloc(msg_to_hash_len*sizeof(unsigned char));

    sprintf(temp, "%d", *nonce);
    memcpy(msg_to_hash, DELETE_REQUEST, strlen(DELETE_REQUEST)); // rename req.
    memcpy(&*(msg_to_hash+strlen(DELETE_REQUEST)), " ", BLANK_SPACE);
    memcpy(&*(msg_to_hash+strlen(DELETE_REQUEST)+BLANK_SPACE), bufferSupp1, encr_len); // encr.  
    memcpy(&*(msg_to_hash+strlen(DELETE_REQUEST)+BLANK_SPACE+encr_len), " ", BLANK_SPACE);
    memcpy(&*(msg_to_hash+strlen(DELETE_REQUEST)+BLANK_SPACE+encr_len+BLANK_SPACE), iv, IV_LEN); // iv
    memcpy(&*(msg_to_hash+strlen(DELETE_REQUEST)+BLANK_SPACE+encr_len+BLANK_SPACE+IV_LEN), " ", BLANK_SPACE);
    memcpy(&*(msg_to_hash+strlen(DELETE_REQUEST)+BLANK_SPACE+encr_len+BLANK_SPACE+IV_LEN+BLANK_SPACE), \
    temp, LEN_SIZE); // nonce

    digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len);

    ret = CRYPTO_memcmp(digest, bufferSupp2, HASH_LEN);

    free(bufferSupp2);        
    free(temp);
    free(msg_to_hash);
    free(digest);

    if (ret == -1) 
    {
        operation_denied(sd, "Wrong delete request hash", DELETE_DENIED, session_key1, session_key2, nonce);
        
        free(bufferSupp1);
        free(iv);

        return -1;
    }

    // Decrypt the filename
    decrypt_AES_128_CBC(&plaintext, &plain_len, bufferSupp1, encr_len, iv, session_key1);

    free(bufferSupp1);
    free(iv);

    len_fn = plain_len;
    if (len_fn > MAX_LEN_FILENAME) 
    {
        operation_denied(sd, "Filename too long", DELETE_DENIED, session_key1, session_key2, nonce);
        
        free(plaintext);
        return -1;
    }

    filename = (char*) malloc(len_fn*sizeof(char));
    if (!filename) exit_with_failure("Malloc filename failed", 0);
    memcpy(filename, plaintext, len_fn); 

    // Sanitize the filename
    ret = filename_sanitization(filename, "/");
    if (ret != 1) {
        operation_denied(sd, "Filename sanitization failed", RENAME_DENIED, session_key1, session_key2, nonce);

        
        free(plaintext);
        free(filename);
        return -1;
    }

    // Remove the file
    ret = remove(filename);
    if (ret == -1) {
        operation_denied(sd, "Something bad happened during the delete operation", RENAME_DENIED, session_key1, session_key2, nonce);

        
        free(plaintext);
        free(filename);
        return -1;
    }
    
    free(plaintext);
    free(filename);

    // Send success message
    operation_succeed(sd, DELETE_ACCEPTED, session_key2, nonce);

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

int cryptoRenameServer(int sd, char* rec_mex, int* nonce, unsigned char* session_key1, unsigned char* session_key2 )
{
    int ret;
    size_t old_offset;
    size_t offset;
    char* iv;

    unsigned int encr_len;
    unsigned int plain_len;
    unsigned char* plaintext;

    int msg_to_hash_len;
    unsigned int digest_len;
    unsigned char* msg_to_hash;
    unsigned char* digest;

    int msg_len;
    char* temp;
    unsigned char* buffer;
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
    //ret = RAND_bytes((unsigned char*)&iv[0], IV_LEN);
    //if (ret != 1) exit_with_failure("RAND_bytes failed\n", 0);


    /* ---- Parse first message (request, len encr., encr(name + new_name), hash(request, encr, iv, nonce), iv) ---- */
    bufferSupp2 = (unsigned char*) malloc(HASH_LEN*sizeof(unsigned char));
    if (!bufferSupp2) exit_with_failure("Malloc bufferSupp2 failed", 1);
    temp = (char*) malloc(LEN_SIZE*sizeof(char));
    if (!temp) exit_with_failure("Malloc temp failed", 1);
    
    
    offset = strlen(RENAME_REQUEST)+BLANK_SPACE;
    memcpy(temp, &*(buffer+offset), LEN_SIZE); // len. encr.
    offset += LEN_SIZE+BLANK_SPACE;
    encr_len = atoi(temp);

    bufferSupp1 = (unsigned char*) malloc(encr_len*sizeof(unsigned char));

    memcpy(bufferSupp1, &*(buffer+offset), encr_len); // encr
    offset += encr_len+BLANK_SPACE;

    memcpy(bufferSupp2, &*(buffer+offset), HASH_LEN); // hash
    offset += HASH_LEN+BLANK_SPACE;
    
    memcpy(iv, &*(buffer+offset), IV_LEN); // iv
    
    // Check hash
    msg_to_hash_len = strlen(RENAME_REQUEST)+BLANK_SPACE+encr_len+BLANK_SPACE+IV_LEN+BLANK_SPACE+LEN_SIZE;
    msg_to_hash = (unsigned char*) malloc(msg_to_hash_len*sizeof(unsigned char));

    sprintf(temp, "%d", *nonce);
    memcpy(msg_to_hash, RENAME_REQUEST, strlen(RENAME_REQUEST)); // rename req.
    memcpy(&*(msg_to_hash+strlen(RENAME_REQUEST)), " ", BLANK_SPACE);
    memcpy(&*(msg_to_hash+strlen(RENAME_REQUEST)+BLANK_SPACE), bufferSupp1, encr_len); // encr.  
    memcpy(&*(msg_to_hash+strlen(RENAME_REQUEST)+BLANK_SPACE+encr_len), " ", BLANK_SPACE);
    memcpy(&*(msg_to_hash+strlen(RENAME_REQUEST)+BLANK_SPACE+encr_len+BLANK_SPACE), iv, IV_LEN); // iv
    memcpy(&*(msg_to_hash+strlen(RENAME_REQUEST)+BLANK_SPACE+encr_len+BLANK_SPACE+IV_LEN), " ", BLANK_SPACE);
    memcpy(&*(msg_to_hash+strlen(RENAME_REQUEST)+BLANK_SPACE+encr_len+BLANK_SPACE+IV_LEN+BLANK_SPACE), \
    temp, LEN_SIZE); // nonce

    // If hash correct, decrypt
    digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len);

    ret = CRYPTO_memcmp(digest, bufferSupp2, HASH_LEN);
    if (ret == -1) 
    {
        operation_denied(sd, "Wrong rename request hash", RENAME_DENIED);
        
        free(bufferSupp1);
        free(bufferSupp2);        
        free(temp);
        free(iv);
        free(msg_to_hash);
        free(digest);

        return -1;
    }

    decrypt_AES_128_CBC(&plaintext, &plain_len, bufferSupp1, encr_len, iv, session_key1);

    free(bufferSupp1);
    free(bufferSupp2);        
    free(temp);
    free(iv);
    free(msg_to_hash);
    free(digest);


    // Obtain the filenames from the plaintext and sanitize them
    // Filename
    offset = str_ssplit(plaintext, DELIM);
    len_fn = (int)offset;
    if (len_fn > MAX_LEN_FILENAME) 
    {
        operation_denied(sd, "Filename too long", RENAME_DENIED);
        
        free(plaintext);
        return -1;
    }

    filename = (char*) malloc(len_fn*sizeof(char));
    if (!filename) exit_with_failure("Malloc filename failed", 0);
    memcpy(filename, plaintext, len_fn); 

    // New_filename
    old_offset = offset + BLANK_SPACE;
    offset = str_ssplit(&*(plaintext+old_offset), DELIM);
    len_newfn = (int)offset;
    if (len_newfn > MAX_LEN_FILENAME)
    {
        operation_denied(sd, "New_filename too long", RENAME_DENIED);
        
        free(plaintext);
        free(filename);
        return -1;
    } 
    
    new_filename = (char*) malloc(len_newfn*sizeof(char));
    if (!new_filename) exit_with_failure("Malloc new_filename failed", 0);
    memcpy(new_filename, &*(plaintext+old_offset), len_newfn);
                   
    ret = filename_sanitization (filename, "/");
    ret += filename_sanitization (new_filename, "/");
    if (ret <= 1) {
        operation_denied(sd, "Filename sanitization failed", RENAME_DENIED);

        
        free(plaintext);
        free(filename);
        free(new_filename);
        return -1;
    }

    // Execute the rename if possible, otherwise send failed message to client
    /*chdir(MAIN_FOLDER_SERVER);
    ret = chdir(bufferSupp2);
    if (ret == -1)
    {
        printf("Error: username doesn't exists...\n");
        exit(1);
    }*/
    ret = rename(filename, new_filename);
    if (ret == -1) {
        operation_denied(sd, "Something bad happened during the rename operation", RENAME_DENIED);

        
        free(plaintext);
        free(filename);
        free(new_filename);
        return -1;
    }
    
    free(plaintext);
    free(filename);
    free(new_filename);




    // Send success message to client
    *nonce = *nonce+1;
    ret = RAND_bytes((unsigned char*)&iv[0], IV_LEN); // IV for hash randomness
    if (ret != 1) exit_with_failure("RAND_bytes failed\n", 0);

    msg_len = strlen(RENAME_ACCEPTED)+BLANK_SPACE+HASH_LEN+BLANK_SPACE+IV_LEN;
    buffer = (unsigned char*) malloc(msg_len*sizeof(unsigned char));
    if (!buffer) exit_with_failure("Malloc buffer failed", 1);

    // Calculate the hash
    msg_to_hash_len = strlen(RENAME_ACCEPTED)+BLANK_SPACE+IV_LEN+BLANK_SPACE+LEN_SIZE;
    msg_to_hash = (unsigned char*) malloc(msg_to_hash_len*sizeof(unsigned char));
    if (!msg_to_hash) exit_with_failure("Malloc msg_to_hash failed", 0);

    temp = (char*) malloc(LEN_SIZE*sizeof(char));
    if (!temp) exit_with_failure("Malloc temp failed", 0);

    sprintf(temp, "%d", *nonce);
    memcpy(msg_to_hash, RENAME_ACCEPTED, strlen(RENAME_ACCEPTED)); // rename acc.
    memcpy(&*(msg_to_hash+strlen(RENAME_ACCEPTED)), " ", BLANK_SPACE);
    memcpy(&*(msg_to_hash+strlen(RENAME_ACCEPTED)+BLANK_SPACE), iv, IV_LEN); // iv.  
    memcpy(&*(msg_to_hash+strlen(RENAME_ACCEPTED)+BLANK_SPACE+IV_LEN), " ", BLANK_SPACE);
    memcpy(&*(msg_to_hash+strlen(RENAME_ACCEPTED)+BLANK_SPACE+IV_LEN+BLANK_SPACE), temp, LEN_SIZE); // nonce

    digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len);

    // Compose the message
    memcpy(buffer, RENAME_ACCEPTED, strlen(RENAME_ACCEPTED)); // rename acc.
    memcpy(&*(buffer+strlen(RENAME_ACCEPTED)), " ", BLANK_SPACE);
    memcpy(&*(buffer+strlen(RENAME_ACCEPTED)+BLANK_SPACE), digest, HASH_LEN); // hash
    memcpy(&*(buffer+strlen(RENAME_ACCEPTED)+BLANK_SPACE+HASH_LEN), " ", BLANK_SPACE);
    memcpy(&*(buffer+strlen(RENAME_ACCEPTED)+BLANK_SPACE+HASH_LEN+BLANK_SPACE), iv, IV_LEN); // iv

    ret = send(sd, buffer, msg_len, 0);
    if (ret == -1) exit_with_failure("Send failed", 1);
    
    return 1;
}

int cryptoDownloadServer(int sock, char* rec_mex, char* username, int* nonce, unsigned char* session_key1, unsigned char* session_key2)
{
    int ret;
    size_t old_offset;
    size_t offset;
    char* iv;

    unsigned int encr_len;
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

    char payload[CHUNK_SIZE+1];
    char username[MAX_LEN_USERNAME];
    char filename[MAX_LEN_FILENAME];
    struct stat st;
    int i, j, nchunk, ret, start_payload, rest;
    FILE* fd;

    //THE FORMAT OF THE MESSAGE WE RECEIVED SHOULD BE M1: download_request, len encr., encr(filename), hash(download_request, encr, iv, nonce), iv)
    bufferSupp1 = (unsigned char*)malloc(sizeof(unsigned char)*LEN_SIZE);
    if (!bufferSupp2) exit_with_failure("Malloc bufferSupp2 failed", 1);
    memcpy(bufferSupp1, &*(rec_mex+strlen(DOWNLOAD_REQUEST)+BLANK_SPACE), LEN_SIZE);
    encr_len = atoi(bufferSupp1);

    encr_msg = (unsigned char*)malloc(sizeof(unsigned char)*encr_len);
    if (!encr_msg) exit_with_failure("Malloc encr_msg failed", 1);
    memcpy(encr_msg, &*(rec_mex+strlen(DOWNLOAD_ACCEPTED)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE), encr_len); //Now we have the encr_msg, we should confirm the auth and take the iv later to decrypt it
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
    
    rest = atoi(bufferSupp3);
    nchunk = atoi(bufferSupp2);

    printf("The number of chunk of the file is %i", nchunk);

    

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
    int sock, ret, receiverport;
    char buffer[BUF_LEN];
    FILE* f1;
    struct sockaddr_in rec_addr;
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
