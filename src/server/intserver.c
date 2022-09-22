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
    unsigned char* temp;
    unsigned char* bufferSupp1;
    unsigned char* bufferSupp2;
    char* path_pubkey = "../dh_server_pubkey.pem";
    char* path_cert_rsa = "cert.pem";
    char* path_rsa_key = "rsa_prvkey.pem";
    char* path_documents = "./documents/";
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
    char* username;
    unsigned int len_username;

    char funcBuff[BUF_LEN];
    char funcSupp1[BUF_LEN];

    unsigned char* session_key1;
    unsigned char* session_key2;

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

    // Allocate memory for username
    username = (char*) malloc(MAX_LEN_USERNAME*sizeof(char));
    if (!username) exit_with_failure("Malloc username failed", 1);




    /* ---- Parse the first message (login request message + username + DH pubkey) ---- */
    bufferSupp1 = (unsigned char*) malloc(sizeof(unsigned char)*(MAX_LEN_USERNAME+1));
    if (!bufferSupp1) exit_with_failure("Malloc bufferSupp1 failed", 1);
    bufferSupp2 = (unsigned char*) malloc(sizeof(unsigned char)*pubkey_len);
    if (!bufferSupp2) exit_with_failure("Malloc bufferSupp2 failed", 1);

    // Skip the login request field
    old_offset = strlen(LOGIN_REQUEST)+BLANK_SPACE;

    // Parse the username
    offset = str_ssplit(&*((unsigned char*) rec_mex+old_offset), DELIM);
    len_username = offset;
    if(len_username > MAX_LEN_USERNAME)
    {
        free_3(username, bufferSupp1, bufferSupp2);
        printf("Username too long.\n");
        return -1;
    }
    memcpy(bufferSupp1, &*(rec_mex+old_offset), offset); // username
    memcpy(&*(bufferSupp1+offset), "\0", 1);
    old_offset += offset+BLANK_SPACE;

    // Parse pubkey
    memcpy(bufferSupp2, &*(rec_mex+old_offset), pubkey_len); // dh pubkey

    // Sanitize and check username
    if (!username_sanitization((char*) bufferSupp1))
    {
        free_3(username, bufferSupp1, bufferSupp2);
        printf("Username sanitization fails.\n");
        return -1;
    } 

    ret = chdir(MAIN_FOLDER_SERVER);
    if (ret == -1) exit_with_failure("No such directory MAIN_FOLDER_SERVER.\n", 0);
    ret = chdir((char*) bufferSupp1);
    if (ret == -1) 
    {
        free_3(username, bufferSupp1, bufferSupp2);
        printf("User folder doesn't exists...\n");
        return -1;
    }

    memcpy(username, bufferSupp1, (len_username+1));

    // Retrieve the client pubkey (from the client cert., already owned by the server)
    path_cert_client_rsa = (char*) malloc(sizeof(char)*(5+len_username+4+1));
    memcpy(path_cert_client_rsa, "cert_", 5);
    memcpy(&*(path_cert_client_rsa+5), username, len_username);
    memcpy(&*(path_cert_client_rsa+5+len_username), ".pem\0", 4+1);
    pub_rsa_client = get_client_pubkey(path_cert_client_rsa);
    
    // Calculate K = g^a^b mod p, established key
    peer_pubkey = pubkey_to_PKEY(bufferSupp2, pubkey_len);
    K = key_derivation(my_prvkey, peer_pubkey, &K_len);

    // Obtain the two session keys from the established key
    issue_session_keys(K, K_len, &session_key1, &session_key2);
    
    printf("First message is correct. Preparing the response...\n");
    
    free_2(bufferSupp1, path_cert_client_rsa);
    EVP_PKEY_free(my_prvkey);
    EVP_PKEY_free(peer_pubkey);




    /* --- Send response (DH pubkey, signature, len. cert. and cert.) --- */
    // Prepare the digital signature (g^a || g^b)
    msg_to_sign_len = build_msg_2(&msg_to_sign, bufferSupp2, pubkey_len, pubkey_byte, pubkey_len);
    if (msg_to_sign_len == -1) exit_with_failure("Something bad happened building signature for second message...", 0);
    
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
    temp = (unsigned char*) malloc(sizeof(char)*LEN_SIZE);
    if (!temp) exit_with_failure("Malloc temp failed", 1);

    sprintf((char*)temp, "%d", cert_len);
    msg_len = build_msg_4(&buffer, pubkey_byte, pubkey_len, \
                                   signature, SIGN_LEN, \
                                   temp, LEN_SIZE, \
                                   cert_byte, cert_len);
    if (msg_len == 1) exit_with_failure("Something bad happened building the message...", 0);

    printf("I'm sending to the client the response.\n");
    ret = send(sd, buffer, BUF_LEN, 0); 

    free_6(bufferSupp2, temp, buffer, pubkey_byte, cert_byte, signature);
    EVP_PKEY_free(dh_pubkey);

    if (ret == -1)
    {
        free_5(username, K, msg_to_sign, session_key1, session_key2);
        EVP_PKEY_free(pub_rsa_client);
        printf("Send failed.\n");
        return -1;
    } 




    /* Parse the client message and verify the fields */
    buffer = (unsigned char*) malloc(sizeof(unsigned char)*BUF_LEN);
    if (!buffer) exit_with_failure("Malloc buffer failed", 1);
    bufferSupp1 = (unsigned char*) malloc(sizeof(unsigned char)*(SIGN_LEN+1));
    if (!bufferSupp1) exit_with_failure("Malloc bufferSupp1 failed", 1);

    ret = recv(sd, buffer, BUF_LEN, 0);
    if (ret == -1) 
    {
        free_5(username, K, msg_to_sign, session_key1, session_key2);
        free_2(buffer, bufferSupp1);
        EVP_PKEY_free(pub_rsa_client);
        printf("Receive failed.\n");
        return -1;
    } 
 
    // Parse signature
    memcpy(bufferSupp1, buffer, SIGN_LEN);
    memcpy(&*(bufferSupp1+SIGN_LEN), "\0", 1);

    // Verify signature
    ret = verify_signature(msg_to_sign, msg_to_sign_len, bufferSupp1, SIGN_LEN, pub_rsa_client);
    
    free_4(buffer, bufferSupp1, msg_to_sign, K);
    EVP_PKEY_free(pub_rsa_client);
    
    if (ret != 1) 
    {
        free_3(username, session_key1, session_key2);
        printf("Signature verification failed.\n");
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
            printf("\nWe received a login request but this client is already logged... Something bad happened...\n\n");
        }


        //************ LOGOUT REQUEST MANAGER ************
        else if (strcmp(funcSupp1, LOGOUT_REQUEST) == 0)
        {
            printf("\nA logout request has came up...\n\n");
            // LOGOUT MANAGER: SERVER SIDE
                            
            ret = logoutServer(funcBuff, &nonce_cs, session_key2);
            if (ret == -1)
            {
                printf("Something bad happened during the management of the client logout request...\n\n");
                printf("End of logout request management!\n\n");
            }
            else
            {
                printf("I managed a logout request and all was good!\n");
                printf("End of logout request management!\n\n");
                break;
            }
        }


        // ************* LIST REQUEST MANAGER ***************
        else if (strcmp(funcSupp1, LIST_REQUEST) == 0)
        {
            printf("\nA list request has came up...\n\n");
            // LIST MANAGER: SERVER SIDE
        
            ret = listServer(sd, funcBuff, path_documents, &nonce_cs, session_key1, session_key2);
            if (ret == -1)
            {
                printf("Something bad happened during the management of the client list request...\n\n");
                break;
            }
            else printf("I managed a list request and all was good!\n\n");
        }


        //*************** RENAME REQUEST MANAGER *****************
        else if (strcmp(funcSupp1, RENAME_REQUEST) == 0)
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
        else if (strcmp(funcSupp1, DELETE_REQUEST) == 0)
        {
            printf("\nA delete request has came up...\n\n");
            // DELETE MANAGER: SERVER SIDE
                            
            ret = deleteServer(sd, funcBuff, &nonce_cs, session_key1, session_key2);
            if (ret == -1)
            {
                printf("Something bad happened during the management of the client delete request...\n\n");
                break;
            }
            else printf("I managed a delete request and all was good!\n\n");
        }

        
        // *************** DOWNLOAD REQUEST MANAGER ****************
        else if (strcmp(funcSupp1, DOWNLOAD_REQUEST) == 0)
        {
            printf("\nA download request has came up...\n\n");

            // DOWNLOAD MANAGER: SERVER SIDE
                            
            ret = downloadServer(sd, funcBuff, &nonce_cs, session_key1, session_key2);
            if (ret == -1)
            {
                printf("Something bad happened during the management of the client download request...\n\n");
                break;
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
                break;
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
                break;
            }
            else printf("I managed a share request and all was good!\n\n");
        }

        else printf("Unknown type of request by the Client...\n");  
    }

    free_3(username, session_key1, session_key2);
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
    if (ret == -1) 
    {
        printf("Wrong logout request hash.\n");
        return -1;
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
    
    if (ret == -1) // If the hash comparison failed
    {
        operation_denied(sd, "Hash incorrect", LIST_DENIED, session_key1, session_key2, nonce);
        return 1;
    }

    printf("List request message parsed successfully\n");
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

        printf("I'm sending to the client the filename's list\n"); 
        ret = send(sd, buffer, BUF_LEN, 0); 
        
        free_5(temp, bufferSupp1, buffer, ciphertext, digest);
        free_2(msg_to_hash, iv);
        
        if (ret == -1) 
        {
            printf("Send failed.\n");
            return -1;
        }
        else *nonce = *nonce+1;

        


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

        bufferSupp1 = (unsigned char*) malloc((strlen(LIST_DENIED)+1)*sizeof(unsigned char));
        if (!bufferSupp1) exit_with_failure("Malloc bufferSupp1 failed", 1);
        memcpy(bufferSupp1, buffer, strlen(LIST_DENIED)); // denied or accepted same length
        memcpy(&*(bufferSupp1+strlen(LIST_DENIED)), "\0", 1);

        if (strcmp((char*) bufferSupp1, LIST_DENIED) == 0)
        {
            ret = check_reqden_msg(LIST_DENIED, buffer, *nonce, session_key1, session_key2);
            if (ret == -1) exit_with_failure("Error checking list denied message", 0);
            else 
            {
                free_2(bufferSupp1, buffer);
                printf("Received list denied message.\n");
                return 1;
            }
        }
        else if (strcmp((char*) bufferSupp1, LIST_ACCEPTED) == 0)
        {
            ret = check_reqacc_msg(LIST_ACCEPTED, buffer, *nonce, session_key2);
            if (ret == -1) exit_with_failure("Error checking list accepted message", 0);
            if (num_file == 0) num_file = -1;
            free_2(buffer, bufferSupp1);
        }
        else
        {
            printf("We don't know what the client said...\n\n");
            free_2(bufferSupp1, buffer);
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
    *nonce = *nonce+1;

    bufferSupp2 = (unsigned char*) malloc(HASH_LEN*sizeof(unsigned char));
    if (!bufferSupp2) exit_with_failure("Malloc bufferSupp2 failed", 1);
    temp = (char*) malloc(LEN_SIZE*sizeof(char));
    if (!temp) exit_with_failure("Malloc temp failed", 1);
    
    
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
    sprintf((char*)temp, "%d", *nonce);
    msg_to_hash_len= build_msg_4(&msg_to_hash, RENAME_REQUEST, strlen(RENAME_REQUEST),\
                                    bufferSupp1, encr_len,\
                                    iv, IV_LEN,\
                                    temp, LEN_SIZE);
    if (msg_to_hash_len == -1) exit_with_failure("Error during the building of the message", 1);

    // If hash correct, decrypt
    digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len);

    ret = CRYPTO_memcmp(digest, bufferSupp2, HASH_LEN);
    if (ret == -1) 
    {
        operation_denied(sd, "Wrong rename request hash", RENAME_DENIED, session_key1, session_key2, nonce);
        
        free_6(bufferSupp1, bufferSupp2, temp, iv, msg_to_hash, digest);
        return -1;
    }
    else printf("Hash of M1 is correct\n");

    decrypt_AES_128_CBC(&plaintext, &plain_len, bufferSupp1, encr_len, iv, session_key1);

    free_6(bufferSupp1, bufferSupp2, temp, iv, msg_to_hash, digest);

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
        operation_denied(sd, "Something bad happened during the rename operation", RENAME_DENIED, session_key1, session_key2, nonce);

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

    sprintf((char*)temp, "%d", *nonce);
    msg_to_hash_len = build_msg_4(&msg_to_hash, DELETE_REQUEST, strlen(DELETE_REQUEST),\
                                                bufferSupp1, encr_len,\
                                                iv, IV_LEN,\
                                                temp, LEN_SIZE);
    if (ret == -1) exit_with_failure("Error during the building of the message", 1);

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

    filename = (char*) malloc((len_fn+1)*sizeof(char));
    if (!filename) exit_with_failure("Malloc filename failed", 0);
    memcpy(filename, plaintext, len_fn+1); 

    // Sanitize the filename
    ret = filename_sanitization(filename);
    if (ret != 1) {
        operation_denied(sd, "Filename sanitization failed", RENAME_DENIED, session_key1, session_key2, nonce);

        
        free(plaintext);
        free(filename);
        return -1;
    }

    // Remove the file
    ret = chdir("documents/");
    if (ret == -1) exit_with_failure("Can't change directory to path_documents", 1);
    ret = remove(filename);
    if (ret == -1) {
        operation_denied(sd, "Something bad happened during the delete operation", RENAME_DENIED, session_key1, session_key2, nonce);
        ret = chdir("../");
        if (ret == -1) exit_with_failure("Can't change directory", 1);
        
        free(plaintext);
        free(filename);
        return -1;
    }
    
    ret = chdir("../");
    if (ret == -1) exit_with_failure("Can't change directory", 1);


    free(plaintext);
    free(filename);

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
    int i, j;
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

    // HERE WE TAKE THE NONCE IN STRING
    buffer = (unsigned char*)malloc(sizeof(unsigned char)*LEN_SIZE);
    if (!buffer) exit_with_failure("Malloc buffer failed", 1);
    sprintf((char*)buffer, "%u", *nonce);
    
    //Now we prepare the message to hash to compare it with the one we received
    msg_to_hash_len = build_msg_4(&msg_to_hash, DOWNLOAD_REQUEST, strlen(DOWNLOAD_REQUEST), \
                                                encr_msg, encr_len, \
                                                iv, IV_LEN, \
                                                buffer, LEN_SIZE);
    if (msg_to_hash_len == -1) exit_with_failure("Something bad happened building the hash...", 0);

    digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len);    
    if (digest_len != (unsigned int) HASH_LEN) exit_with_failure("Wrong digest len", 0);
    ret = CRYPTO_memcmp(digest, bufferSupp2, HASH_LEN);
    if (ret == -1)
    {
        printf("Wrong rename failed hash\n\n");
        ret = -1;
    } 
    else printf("The MAC is been correctly compared!\n");
    

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
    free_2(buffer, digest);

    chdir("documents");
    fd = fopen(filename, "r");
    if (!(fd))
    {
        printf("File %s doesn't exist...\n\n", filename);
        chdir("..");
        return -1;
    }
    stat(filename, &st);
    chdir("..");
    printf("The size of the file is %ld\n\n", st.st_size);
    nchunk = (st.st_size/CHUNK_SIZE)+1;
    rest = st.st_size - (nchunk-1)*CHUNK_SIZE; // This is the number of bits of the final chunk

    bufferSupp1 = (unsigned char*)malloc((sizeof(unsigned char)*BUF_LEN));
    printf("The number of chunk is %i\n\n", nchunk);    
    sprintf((char*)bufferSupp1, "%s %i %i", DOWNLOAD_ACCEPTED, nchunk, rest); 
    printf("I'm sending %s\n\n", bufferSupp1);

    free(bufferSupp1);




    /* ---- Send download_accepted to the client ---- */ 
    //THE FORMAT OF THE MESSAGE WE SHOULD SEND IS DOWNLOAD_ACCEPTED NCHUNK REST HASH
    //FIRST OF ALL WE SHOULD CALCULATE THE DIGEST OF THE HASH FOR THE MAC: DOWNLOAD_ACCEPTED NONCE NCHUNK REST
    bufferSupp1 = (unsigned char*)malloc(LEN_SIZE);
    if (!bufferSupp1) exit_with_failure("Malloc buffSupp1 failed", 1);
    bufferSupp2 = (unsigned char*)malloc(REST_SIZE);
    if (!bufferSupp2) exit_with_failure("Malloc bufferSupp2 failed", 1);
    temp = (char*)malloc(LEN_SIZE);
    if (!temp) exit_with_failure("Malloc temp failed", 1);

    sprintf((char*)temp, "%u", *nonce); //nonce is put on temp as a string
    sprintf((char*)bufferSupp1, "%i", nchunk); //nchunk is put on bufferSupp1 as a string
    sprintf((char*)bufferSupp2, "%i", rest); //rest is put on bufferSUpp2 as a string
    msg_to_hash_len = build_msg_3(&msg_to_hash, DOWNLOAD_ACCEPTED, strlen(DOWNLOAD_ACCEPTED), \
                                                temp, LEN_SIZE, \
                                                bufferSupp1, LEN_SIZE);
    if (msg_to_hash_len == -1) exit_with_failure("Something bad happened building the hash...", 0);

    digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len);

    msg_len = build_msg_4(&buffer, DOWNLOAD_ACCEPTED, strlen(DOWNLOAD_ACCEPTED), \
                                   bufferSupp1, LEN_SIZE, \
                                   bufferSupp2, REST_SIZE, \
                                   digest, HASH_LEN);
    if (msg_len == -1) exit_with_failure("Something bad happened building the message...", 0);
    *(buffer+msg_len) = '\0';
    printf("We are sending %s\n", (char*)buffer);
    
    ret = send(sock, buffer, BUF_LEN, 0);
    if (ret == -1)
    {
        printf("Send operation gone bad.\n");
        free_6(buffer, bufferSupp1, bufferSupp2, msg_to_hash, temp, digest);
        return -1;
    }
    *nonce += 1;

    free_6(buffer, bufferSupp1, bufferSupp2, msg_to_hash, temp, digest);
    


    /* ---- Send chunks ---- */
    //NOW WE START TO SEND THE CHUNKS
    for (i = 0; i < nchunk; i++)
    {
        msg_to_encr_len = CHUNK_SIZE+1;
        msg_to_encr = (unsigned char*)malloc(msg_to_encr_len);
        if (!msg_to_encr) exit_with_failure("Malloc msg_to_encr failed", 1);
        if (i == nchunk-1)
        {
            for (j = 0; j < rest; j++)
            {
                if (fgets((char*)msg_to_encr+j, 2, fd) == NULL)
                {
                    *(msg_to_encr+j) = '\0';
                    printf("File over!");
                    break;
                }
            }
        }
        else
        {
            for (j = 0; j < CHUNK_SIZE; j++)
            {
                if (fgets((char*)msg_to_encr+j, 2, fd) == NULL)
                {
                    *(msg_to_encr+j) = '\0';
                    printf("File over!");
                    break;
                }
            }
        }

        //ENCRYPT THE MESSAGE SENT
        iv = (unsigned char*) malloc(sizeof(unsigned char)*IV_LEN);
        if (!iv) exit_with_failure("Malloc iv failed", 1);
        ret = RAND_poll(); // Seed OpenSSL PRNG
        if (ret != 1) exit_with_failure("RAND_poll failed\n", 0);
        ret = RAND_bytes((unsigned char*)&iv[0], IV_LEN);
        if (ret != 1) exit_with_failure("RAND_bytes failed\n", 0);
        //printf("I'm sending the chunk %s\n\n", (char*)msg_to_encr);

        encrypt_AES_128_CBC(&encr_msg, &encr_len, msg_to_encr, msg_to_encr_len, iv, session_key1);

        bufferSupp1 = (unsigned char*)malloc(LEN_SIZE); //nonce string;
        if (!bufferSupp1) exit_with_failure("Malloc bufferSupp1 failed", 1);
        sprintf((char*)bufferSupp1, "%u", *nonce);

        //CREATE THE HASH

        msg_len = build_msg_3(&buffer, encr_msg, encr_len, iv, IV_LEN, bufferSupp1, LEN_SIZE);
        if (msg_len == -1) exit_with_failure("Error during the creation of the function", 1);

        digest = hmac_sha256(session_key2, 16, buffer, msg_len, &digest_len);

        free(buffer);
        temp = (char*)malloc(LEN_SIZE*(sizeof(char)));
        if (!temp) exit_with_failure("Malloc temp failed", 1);
        sprintf((char*)temp, "%u", encr_len);
        msg_len = build_msg_4(&buffer, temp, LEN_SIZE, encr_msg, encr_len, digest, HASH_LEN, iv, IV_LEN);
        if (msg_len == -1) exit_with_failure("Error during the creation of the function", 1);

        printf("I'm sending %s", (char*)buffer);

        ret = send(sock, buffer, BUF_LEN, 0);
        if (ret == -1)
        {
            printf("Send operation gone bad\n");
            // Change this later to manage properly the session
            exit(1);
        }
        printf("We are sending the chunk number %i\n", i);
        //NONCE MANAGEMENT
        *nonce += 1;

        free_6(iv, encr_msg, msg_to_encr, buffer, bufferSupp1, digest);
        free(temp);
    }
    fclose(fd);
    buffer = (unsigned char*)malloc(BUF_LEN*(sizeof(unsigned char)));
    ret = recv(sock, buffer, BUF_LEN, 0);
    if (ret == -1)
    {
        printf("Receive operation gone bad!\n\n");
        exit(1);
    }

    // DECRYPT THE BUFFER
    ret = check_reqacc_msg(DOWNLOAD_FINISHED, buffer, *nonce, session_key2);
    if (ret == -1)
    {
        printf("Something bad happened during the download\n\n");
        return -1;
    }
    printf("We have completed successfully the donwload operation!\n\n");
    *nonce += 1;
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
    
    rest = atoi((char*)bufferSupp3);
    nchunk = atoi((char*)bufferSupp2);

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
        sprintf((char*)buffer, "%s %s %s", UPLOAD_ACCEPTED, username, filename);
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
        sprintf((char*)buffer, "%s %s %s", UPLOAD_DENIED, username, filename);
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
    sprintf((char*)buffer, "%s %s %s", DOWNLOAD_FINISHED, username, filename);
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
        sprintf((char*)buffer, "%s %s %s %s", SHARE_DENIED, sharername, filename, receivername);
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
    sprintf((char*)buffer, "%s.txt", receivername);
    if (!(f1 = fopen(buffer, "r")))
    {
        printf("The receiver %s is not online... Try it later\n\n", receivername);
        memset(buffer, 0, strlen(buffer));
        sprintf((char*)buffer, "%s %s %s %s", SHARE_DENIED, sharername, filename, receivername);
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
    receiverport = atoi((char*)buffer);

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
