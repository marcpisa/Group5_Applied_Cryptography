#include "intclient.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include <openssl/rand.h>

int createSocket()
{
    int sock;
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
    {
        printf("\n Socket creation error \n");
        return -1;
    }
    return sock;
}

int loginClient(int *sock, unsigned char* session_key1, unsigned char* session_key2, char* username, struct sockaddr_in srv_addr, X509_STORE* ca_store) {
    /*********************
     * VARIABLES
     ********************/
    char* path_pubkey;
    char* path_rsa_key;
    unsigned int msg_len;
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
    if (connect(*sock, (struct sockaddr*)&srv_addr, sizeof(srv_addr)) < 0) exit_with_failure("asfasfiled", 1);

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
    



    /* ---- 1st message: login request message + username + DH pubkey ---- */
    // Calculate the message length and allocate the memory
    msg_len = strlen(LOGIN_REQUEST)+BLANK_SPACE+strlen(username)+BLANK_SPACE+pubkey_len+1;
    buffer = (unsigned char*) malloc(sizeof(unsigned char)*msg_len);
    if (!buffer) exit_with_failure("Malloc buffer failed", 1);

    // Compose the message and send it to the server
    memcpy(buffer, LOGIN_REQUEST, strlen(LOGIN_REQUEST));  // login req
    memcpy(&*(buffer+strlen(LOGIN_REQUEST)), " ", BLANK_SPACE);
    memcpy(&*(buffer+strlen(LOGIN_REQUEST)+BLANK_SPACE), username, strlen(username)); // username
    memcpy(&*(buffer+strlen(LOGIN_REQUEST)+BLANK_SPACE+strlen(username)), " ", BLANK_SPACE);
    memcpy(&*(buffer+strlen(LOGIN_REQUEST)+BLANK_SPACE+strlen(username)+BLANK_SPACE) \
    , pubkey_byte, pubkey_len); // dh pubkey

    memcpy(&*(buffer+msg_len-1), "\0", 1);

    /*
    for(unsigned int i = 0; i < msg_len; i++) { printf("%c", *(buffer+i)); }
    printf("\n\n");    
    */
    //printf("%d\n%d\n%d\n", pubkey_len, iv_len, signature_len);
    printf("I'm sending to the server the first message.\n");
    ret = send(*sock, buffer, msg_len, 0);
    if (ret == -1) exit_with_failure("Send failed", 1);

    free(buffer);




    /* ---- Obtain and parse response server (DH pubkey, signature, len. cert. and cert.) ----*/
    msg_len = pubkey_len+BLANK_SPACE+SIGN_LEN+BLANK_SPACE+LEN_SIZE+BLANK_SPACE+MAX_CERT_LEN+1;
    buffer = (unsigned char*) malloc(sizeof(unsigned char)*msg_len);
    if (!buffer) exit_with_failure("Malloc buffer failed", 1);
    ret = recv(*sock, buffer, msg_len, 0);
    if (ret == -1) exit_with_failure("Receive failed", 1);
    printf("Received the response of the server.\n");

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
    printf("Cert:%ld %d\n", msg_len-offset, cert_len);
    if (cert_len <= 0 || (msg_len-offset) < (unsigned int) cert_len) exit_with_failure("Incorrect certificate length", 0);


    // The certificate is greater than 1024
    cert_buffer = (unsigned char*) malloc((cert_len+1)*sizeof(unsigned char));
    if (!cert_buffer) exit_with_failure("cert_buffer malloc failed", 1);
    memcpy(cert_buffer, &*(buffer+offset), cert_len); // cert

    // Obtain the public key, derive the established key
    peer_pubkey = pubkey_to_PKEY(bufferSupp1, pubkey_len);
    K = key_derivation(my_prvkey, peer_pubkey, &K_len);

    // Obtain the two session keys from the established key
    issue_session_keys(K, K_len, &session_key1, &session_key2);
   
    // Obtain the RSA public key and verify the certificate of the server
    serv_cert = cert_to_X509(cert_buffer, cert_len);
    if (!serv_cert) exit_with_failure("cert_to_X509 failed", 1);
    pub_rsa_key_serv = get_ver_server_pubkey(serv_cert, ca_store);
    
    // Generate the digital signature expected
    expected_len = pubkey_len+BLANK_SPACE+pubkey_len;
    exp_digsig = (unsigned char*) malloc(sizeof(unsigned char)*expected_len);
    if (!exp_digsig) exit_with_failure("Malloc exp_digsig failed", 1);
    
    memcpy(exp_digsig, pubkey_byte, pubkey_len);
    memcpy(&*(exp_digsig+pubkey_len), " ", BLANK_SPACE);
    memcpy(&*(exp_digsig+pubkey_len+BLANK_SPACE), bufferSupp1, pubkey_len); // peer pubkey
    
    // Verify the digital signature received
    ret = verify_signature(exp_digsig, expected_len, bufferSupp2, SIGN_LEN, pub_rsa_key_serv);
    if (ret != 1) exit_with_failure("Signature verification failed.\n", 0);
    
      
    free(temp);
    free(buffer);
    free(bufferSupp1);
    free(bufferSupp2);
    free(pubkey_byte); // Is this necessary?
    free(cert_buffer);
    X509_free(serv_cert);
    EVP_PKEY_free(pub_rsa_key_serv);
    EVP_PKEY_free(my_prvkey);
    



    /* ---- Generate last message for the server (digital signature) ---- */
    msg_len = SIGN_LEN;
    buffer = (unsigned char*) malloc(sizeof(unsigned char)*msg_len);
    if (!buffer) exit_with_failure("Malloc buffer failed", 1);

    // Generate digital signature
    signature = sign_msg(path_rsa_key, exp_digsig, expected_len, &signature_len);

    // Compose the message
    memcpy(buffer, signature, SIGN_LEN); // dig. sig.

    //printf("%s\n", buffer);
    printf("I'm sending to the server the last message.\n");
    ret = send(*sock, buffer, msg_len, 0); 
    if (ret == -1) exit_with_failure("Send failed", 1);

    free(path_pubkey);
    free(path_rsa_key);
    free(buffer);
    free(signature);
    free(exp_digsig);
    free(K);
 
    return 1;
}

int logoutClient(int sock, int* nonce, unsigned char* session_key2)
{
    unsigned int digest_len;
    int ret;
    unsigned int msg_len;
    unsigned int msg_to_hash_len;

    char* temp;
    unsigned char* buffer;
    unsigned char* msg_to_hash;
    unsigned char* digest;
    unsigned char* iv;    

    /*sock = createSocket();
    if (connect(sock, (struct sockaddr*)&srv_addr, sizeof(srv_addr)) < 0) exit_with_failure("Connect failed", 1);*/

    // Generate the IV
    iv = (unsigned char*) malloc(sizeof(unsigned char)*IV_LEN);
    if (!iv) exit_with_failure("Malloc iv failed", 1);
    RAND_poll(); // Seed OpenSSL PRNG
    ret = RAND_bytes((unsigned char*)&iv[0], IV_LEN);
    if (ret != 1) exit_with_failure("RAND_bytes failed\n", 0);




    /* ---- Create the first message (request + hash + iv) ---- */
    msg_len = strlen(LOGOUT_REQUEST)+BLANK_SPACE+HASH_LEN+BLANK_SPACE+IV_LEN;

    // Generating the hash of the request and the nonce
    msg_to_hash_len = strlen(LOGOUT_REQUEST)+BLANK_SPACE+IV_LEN+BLANK_SPACE+LEN_SIZE;
    msg_to_hash = (unsigned char*) malloc(sizeof(unsigned char)*msg_to_hash_len);
    if (!msg_to_hash) exit_with_failure("Malloc buffer failed", 1);
    temp = (char*) malloc(sizeof(char)*LEN_SIZE);
    if (!temp) exit_with_failure("Malloc temp failed", 1);

    sprintf(temp, "%d", *nonce);
    memcpy(msg_to_hash, LOGOUT_REQUEST, strlen(LOGOUT_REQUEST));  // logout req
    memcpy(&*(msg_to_hash+strlen(LOGOUT_REQUEST)), " ", BLANK_SPACE);
    memcpy(&*(msg_to_hash+strlen(LOGOUT_REQUEST)+BLANK_SPACE), iv, IV_LEN); // iv
    memcpy(&*(msg_to_hash+strlen(LOGOUT_REQUEST)+BLANK_SPACE+IV_LEN), " ", BLANK_SPACE);
    memcpy(&*(msg_to_hash+strlen(LOGOUT_REQUEST)+BLANK_SPACE+IV_LEN+BLANK_SPACE), \
    temp, LEN_SIZE); // nonce

    digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len);    
    if (digest_len != (unsigned int) HASH_LEN) exit_with_failure("Wrong digest len", 0);

    // Compose the message
    buffer = (unsigned char*) malloc(sizeof(unsigned char)*msg_len);
    if (!buffer) exit_with_failure("Malloc buffer failed", 1);

    memcpy(buffer, LOGOUT_REQUEST, strlen(LOGOUT_REQUEST));  // logout req
    memcpy(&*(buffer+strlen(LOGOUT_REQUEST)), " ", BLANK_SPACE);
    memcpy(&*(buffer+strlen(LOGOUT_REQUEST)+BLANK_SPACE), digest, HASH_LEN); // hash
    memcpy(&*(buffer+strlen(LOGOUT_REQUEST)+BLANK_SPACE+HASH_LEN), " ", BLANK_SPACE);
    memcpy(&*(buffer+strlen(LOGOUT_REQUEST)+BLANK_SPACE+HASH_LEN+BLANK_SPACE), \
    iv, IV_LEN); // iv

    printf("I'm sending to the server the logout message.\n");
    ret = send(sock, buffer, msg_len, 0); 
    if (ret == -1) exit_with_failure("Send failed", 1);
    *nonce = *nonce+1; // message sent, nonce increased for the answer or for other messages

    free(temp);
    free(buffer);
    free(msg_to_hash);
    free(digest);
    free(iv);


    /*
    // Check the response (logoutSucceed + nonce + hash)
    msg_len = strlen(LOGOUT_ACCEPTED)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE+HASH_LEN;
    buffer = (unsigned char*) malloc(sizeof(unsigned char)*msg_len);
    if (!buffer) exit_with_failure("Malloc buffer failed", 1);
    ret = recv(sock, buffer, msg_len, 0);
    if (ret == -1) exit_with_failure("Receive failed", 1);
    printf("Received the response of the server.\n");
    temp = (char*) malloc(sizeof(char)*LEN_SIZE);
    if (!temp) exit_with_failure("Malloc temp failed", 1);

    // Parse the server response
    bufferSupp1 = (unsigned char*) malloc(sizeof(unsigned char)*strlen(LOGOUT_ACCEPTED));
    if (!bufferSupp1) exit_with_failure("Malloc bufferSupp1 failed", 1);
    bufferSupp2 = (unsigned char*) malloc(sizeof(unsigned char)*HASH_LEN);
    if (!bufferSupp2) exit_with_failure("Malloc bufferSupp2 failed", 1);

    offset = str_ssplit(buffer, DELIM);
    memcpy(bufferSupp1, buffer, strlen(LOGOUT_ACCEPTED)); // logout accepted
    offset += BLANK_SPACE;

    memcpy(temp, &*(buffer+offset), LEN_SIZE); // nonce
    offset += LEN_SIZE+BLANK_SPACE;
    temp_nonce = atoi(temp);

    memcpy(bufferSupp2, &*(buffer+offset), HASH_LEN); // hash

    // Check logout accepted
    if(!strcmp(LOGOUT_ACCEPTED, bufferSupp1)) exit_with_failure("The field is not logout_accepted, error.", 0);

    // Check nonce
    if (temp_nonce != *nonce) exit_with_failure("Nonce is incorrect, error.", 0);

    // Check hash correctness
    msg_to_hash_len = strlen(LOGOUT_ACCEPTED)+BLANK_SPACE+LEN_SIZE;
    msg_to_hash = (unsigned char*) malloc(sizeof(unsigned char)*msg_to_hash_len);
    if (!msg_to_hash) exit_with_failure("Malloc msg_to_hash failed", 1);
    
    memcpy(msg_to_hash, LOGOUT_ACCEPTED, strlen(LOGOUT_ACCEPTED));
    memcpy(&*(msg_to_hash+strlen(LOGOUT_ACCEPTED)), " ", BLANK_SPACE);
    sprintf(temp, "%d", *nonce);
    memcpy(&*(msg_to_hash+strlen(LOGOUT_ACCEPTED)+BLANK_SPACE), temp, LEN_SIZE); // nonce

    // digest = the correct hash
    digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len);   
    ret = CRYPTO_memcmp(digest, bufferSupp2, HASH_LEN);

    free(msg_to_hash);
    free(digest);
    free(temp);
    free(buffer);
    free(bufferSupp1);
    free(bufferSupp2);
    */
       
    return 1;
}

int listClient(int sock, char* username)
{
    
    int ret;
    char buffer[BUF_LEN];

    
    // SET LIST REQUEST BUFFER
    memset(buffer, 0, BUF_LEN);
    sprintf(buffer, "%s %s", LIST_REQUEST, username);
    buffer[BUF_LEN-1] = '\0';

    // HERE ADD CRYPTOGRAPHIC FUNCTION TO SET PROPERLY THE BUFFER
    printf("I'm sending %s\n", buffer);
    ret = send(sock, buffer, BUF_LEN, 0);
    if (ret == -1)
    {
        printf("Send operation gone bad\n");
        // Change this later to manage properly the session
        exit(1);
    }
    memset(buffer, 0, strlen(buffer));
    printf("List request message sent\n\n");
    ret = recv(sock, buffer, BUF_LEN,0);
    if (ret == -1)
    {
        printf("Receive operation gone bad\n");
        // Change this later to manage properly the session
        exit(1);
    }

    // HERE USE DECRYPTION TO UNDERSTAND WHAT YOU RECEIVE

    // END COMMUNICATION
    
    char *token;
    token = strtok(buffer, " ");
    while (token != NULL) {
        printf("%s\n", token);
        token = strtok(NULL, " ");
    }
    return 1;
}

int renameClient(int sock, char* username, char* filename, char* new_filename)
{
    char* reason;
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
    
    size_t offset;
    int ret;
    unsigned char* buffer, bufferSupp1, bufferSupp2, bufferSupp3;

    // Generate the IV
    iv = (unsigned char*) malloc(sizeof(unsigned char)*IV_LEN);
    if (!iv) exit_with_failure("Malloc iv failed", 1);
    ret = RAND_poll(); // Seed OpenSSL PRNG
    if (ret != 1) exit_with_failure("RAND_poll failed\n", 0);
    ret = RAND_bytes((unsigned char*)&iv[0], IV_LEN);
    if (ret != 1) exit_with_failure("RAND_bytes failed\n", 0);

    // SET RENAME REQUEST BUFFER
    memset(buffer, 0, strlen(buffer));
    printf("The new filename is %s\n\n", new_filename);
    sprintf(buffer, "%s %s %s %s", RENAME_REQUEST, username, filename, new_filename);
    printf("I'm sending to the server the mex %s\n\n", buffer);

    // HERE ADD CRYPTOGRAPHIC FUNCTION TO SET PROPERLY THE BUFFER

    ret = send(sock, buffer, strlen(buffer), 0);
    if (ret == -1)
    {
        printf("Send operation gone bad\n");
        // Change this later to manage properly the session
        exit(1);
    }
    memset(buffer, 0, strlen(buffer));
    printf("Rename request message sent\n");
    ret = recv(sock, buffer, BUF_LEN,0);
    if (ret == -1)
    {
        printf("Receive operation gone bad\n");
        // Change this later to manage properly the session
        exit(1);
    }

    // DECRYPT BUFFER TO UNDERSTAND WHAT IT IS WRITTEN

    sscanf(buffer, "%s %s", bufferSupp1, bufferSupp2); // The two values are the message type and eventually the reason why the request went bad
    
    // SANITIZE THE BUFFER

    if (strcmp(bufferSupp1, RENAME_DENIED) == 0)
    {
        printf("The rename request has been denied: %s\n\n", bufferSupp2);
        return 1;
    }
    else 
        if (strcmp(bufferSupp1, RENAME_ACCEPTED) == 0)
        {
           printf("The rename request has been accepted!\n\n");
           return 1;
        }
        else
        {
            printf("We don't know what the server said...\n\n");
            return -1;
        }
}

// TO TEST
int cryptoRenameClient(int sock, char* username, char* filename, char* new_filename, unsigned char* session_key1, unsigned char* session_key2, int* nonce)
{
    char* reason;
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
    
    size_t offset;

    int ret;
    int msg_len;
    char* temp;
    unsigned char* buffer;
    unsigned char* bufferSupp1;
    unsigned char* bufferSupp2;
    unsigned char* bufferSupp3;

    // Generate the IV
    iv = (unsigned char*) malloc(sizeof(unsigned char)*IV_LEN);
    if (!iv) exit_with_failure("Malloc iv failed", 1);
    ret = RAND_poll(); // Seed OpenSSL PRNG
    if (ret != 1) exit_with_failure("RAND_poll failed\n", 0);
    ret = RAND_bytes((unsigned char*)&iv[0], IV_LEN);
    if (ret != 1) exit_with_failure("RAND_bytes failed\n", 0);




    /* ---- Create the first message (request, len encr., encr(name + new_name), hash(request, encr, iv, nonce), iv) ---- */
    // Encrypt the two names
    msg_to_encr_len = strlen(filename)+BLANK_SPACE+strlen(new_filename);
    msg_to_encr = (unsigned char*) malloc(msg_to_encr_len*sizeof(unsigned char));
    if (!msg_to_encr) exit_with_failure("Malloc msg_to_encr failed", 1);

    memcpy(msg_to_encr, filename, strlen(filename));
    memcpy(&*(msg_to_encr+strlen(filename)), " ", BLANK_SPACE);
    memcpy(&*(msg_to_encr+strlen(filename)+BLANK_SPACE), new_filename, strlen(new_filename));

    encrypt_AES_128_CBC(&encr_msg, &encr_len, msg_to_encr, msg_to_encr_len, iv, session_key1);

    // Create the hash
    msg_to_hash_len = strlen(RENAME_REQUEST)+BLANK_SPACE+encr_len+BLANK_SPACE+IV_LEN+BLANK_SPACE+LEN_SIZE;
    msg_to_hash = (unsigned char*) malloc(sizeof(unsigned char)*msg_to_hash_len);
    if (!msg_to_hash) exit_with_failure("Malloc msg_to_hash failed", 1);
    temp = (char*) malloc(sizeof(char)*LEN_SIZE);
    if (!temp) exit_with_failure("Malloc temp failed", 1);

    sprintf(temp, "%d", *nonce);
    memcpy(msg_to_hash, RENAME_REQUEST, strlen(RENAME_REQUEST));  // rename req
    memcpy(&*(msg_to_hash+strlen(RENAME_REQUEST)), " ", BLANK_SPACE);
    memcpy(&*(msg_to_hash+strlen(RENAME_REQUEST)+BLANK_SPACE), encr_msg, encr_len); // encr
    memcpy(&*(msg_to_hash+strlen(RENAME_REQUEST)+BLANK_SPACE+encr_len), " ", BLANK_SPACE);
    memcpy(&*(msg_to_hash+strlen(RENAME_REQUEST)+BLANK_SPACE+encr_len+BLANK_SPACE), \
    iv, IV_LEN); // iv
    memcpy(&*(msg_to_hash+strlen(RENAME_REQUEST)+BLANK_SPACE+encr_len+BLANK_SPACE+IV_LEN), " ", \
    BLANK_SPACE);
    memcpy(&*(msg_to_hash+strlen(RENAME_REQUEST)+BLANK_SPACE+encr_len+BLANK_SPACE+IV_LEN+BLANK_SPACE), \
    temp, LEN_SIZE); // nonce

    digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len);    
    if (digest_len != (unsigned int) HASH_LEN) exit_with_failure("Wrong digest len", 0);

    // Compose the message
    msg_len = strlen(RENAME_REQUEST)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE+encr_len+BLANK_SPACE+HASH_LEN+ \
    BLANK_SPACE+IV_LEN;

    buffer = (unsigned char*) malloc(sizeof(unsigned char)*msg_len);
    if (!buffer) exit_with_failure("Malloc buffer failed", 1);

    memcpy(buffer, RENAME_REQUEST, strlen(RENAME_REQUEST));  // rename req
    memcpy(&*(buffer+strlen(RENAME_REQUEST)), " ", BLANK_SPACE);
    sprintf(temp, "%d", encr_len);
    memcpy(&*(buffer+strlen(RENAME_REQUEST)+BLANK_SPACE), temp, LEN_SIZE); // len encr
    memcpy(&*(buffer+strlen(RENAME_REQUEST)+BLANK_SPACE+LEN_SIZE), " ", BLANK_SPACE);
    memcpy(&*(buffer+strlen(RENAME_REQUEST)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE), \
    encr_msg, encr_len); // encr
    memcpy(&*(buffer+strlen(RENAME_REQUEST)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE+encr_len), " ", BLANK_SPACE);
    memcpy(&*(buffer+strlen(RENAME_REQUEST)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE+encr_len+BLANK_SPACE), \
    digest, HASH_LEN); // hash
    memcpy(&*(buffer+strlen(RENAME_REQUEST)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE+encr_len+BLANK_SPACE+HASH_LEN), \
     " ", BLANK_SPACE);
    memcpy(&*(buffer+strlen(RENAME_REQUEST)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE+encr_len+BLANK_SPACE+HASH_LEN+ \
    BLANK_SPACE), iv, IV_LEN);// iv


    printf("I'm sending to the server the rename message.\n");
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




    /* ---- Parse the response ---- */
    // Max. size of the msg, RENAME_DENIED and ACCEPTED have the same length
    msg_len = strlen(RENAME_DENIED)+BLANK_SPACE+BUF_LEN+BLANK_SPACE+HASH_LEN+BLANK_SPACE+IV_LEN;
    buffer = (unsigned char*) malloc(sizeof(unsigned char)*msg_len);
    if (!buffer) exit_with_failure("Malloc buffer failed", 1);

    ret = recv(sock, buffer, msg_len,0);
    if (ret == -1) exit_with_failure("Receive failed", 0);
    printf("Received the server's response.\n");

    bufferSupp1 = (unsigned char*) malloc(strlen(RENAME_DENIED)*sizeof(unsigned char));
    if (!bufferSupp1) exit_with_failure("Malloc bufferSupp1 failed", 1);
    memcpy(bufferSupp1, buffer, strlen(RENAME_DENIED)); // denied or accepted same length

    bufferSupp2 = (unsigned char*) malloc(sizeof(unsigned char)*HASH_LEN);
    if (!bufferSupp2) exit_with_failure("Malloc bufferSupp2 failed", 1);
    iv = (unsigned char*) malloc(sizeof(unsigned char)*IV_LEN);
    if (!iv) exit_with_failure("Malloc iv failed", 1);

    // Parse the message based on the server response
    if (strcmp(bufferSupp1, RENAME_DENIED) == 0)
    {
        // M2a: renamedenied, len encr. , encr(reason), hash(renamedenied, encr, iv, nonce), iv
        temp = (char*) malloc(LEN_SIZE*sizeof(char));
        if (!temp) exit_with_failure("Malloc temp failed", 1);

        // Parse the message
        offset = strlen(RENAME_DENIED)+BLANK_SPACE;
        memcpy(temp, &*(buffer+offset), LEN_SIZE); // len. encr.
        offset += LEN_SIZE+BLANK_SPACE;
        
        encr_len = atoi(temp);
        bufferSupp3 = (unsigned char*) malloc(sizeof(unsigned char)*encr_len);
        if (!bufferSupp3) exit_with_failure("Malloc bufferSupp3 failed", 1);

        memcpy(bufferSupp3, &*(buffer+offset), encr_len); // encr.
        offset += encr_len+BLANK_SPACE; 

        memcpy(bufferSupp2, &*(buffer+offset), HASH_LEN); // hash
        offset += HASH_LEN+BLANK_SPACE;

        memcpy(iv, &*(buffer+offset), IV_LEN); // iv

        // Check hash
        msg_to_hash_len = strlen(RENAME_DENIED)+BLANK_SPACE+encr_len+BLANK_SPACE+IV_LEN+BLANK_SPACE+LEN_SIZE; 
        msg_to_hash = (unsigned char*) malloc(msg_to_hash_len*sizeof(unsigned char));
        if (!msg_to_hash) exit_with_failure("Malloc msg_to_hash failed", 1);

        temp = (char*) malloc(sizeof(char)*LEN_SIZE);
        if (!temp) exit_with_failure("Malloc temp failed", 1);

        sprintf(temp, "%d", *nonce);
        memcpy(msg_to_hash, RENAME_DENIED, strlen(RENAME_DENIED));  // rename den
        memcpy(&*(msg_to_hash+strlen(RENAME_DENIED)), " ", BLANK_SPACE);
        memcpy(&*(msg_to_hash+strlen(RENAME_DENIED)+BLANK_SPACE), bufferSupp3, encr_len); // encr
        memcpy(&*(msg_to_hash+strlen(RENAME_DENIED)+BLANK_SPACE+encr_len), " ", BLANK_SPACE);
        memcpy(&*(msg_to_hash+strlen(RENAME_DENIED)+BLANK_SPACE+encr_len+BLANK_SPACE), iv, IV_LEN); // iv
        memcpy(&*(msg_to_hash+strlen(RENAME_DENIED)+BLANK_SPACE+encr_len+BLANK_SPACE+IV_LEN), " ", BLANK_SPACE);
        memcpy(&*(msg_to_hash+strlen(RENAME_DENIED)+BLANK_SPACE+encr_len+BLANK_SPACE+IV_LEN+BLANK_SPACE), \
        temp, LEN_SIZE); // nonce

        digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len);    
        if (digest_len != (unsigned int) HASH_LEN) exit_with_failure("Wrong digest len", 0);

        ret = CRYPTO_memcmp(digest, bufferSupp2, HASH_LEN);
        if (ret == -1)
        {
            printf("Wrong rename failed hash\n\n");
            ret = -1;
        }
        else
        {
            // Decrypt the reason (bufferSupp3)
            decrypt_AES_128_CBC(&plaintext, &plain_len, bufferSupp3, encr_len, iv, session_key1);
            reason = (char*) malloc(plain_len*sizeof(char));
            if (!reason) exit_with_failure("Malloc reason failed", 1);

            printf("The rename request has been denied: %s\n\n", reason);
            
            free(plaintext);
            free(reason);

            ret = 1;
        }

        free(digest);
        free(temp);
        free(msg_to_hash);
        free(bufferSupp3);
    }
    else if (strcmp(bufferSupp1, RENAME_ACCEPTED) == 0)
    {        
        // M2b: renamesucceed, hash(renamesucceed, iv, nonce), iv
        // Parse the message
        memcpy(bufferSupp2, &*(buffer+strlen(RENAME_ACCEPTED)+BLANK_SPACE), HASH_LEN); // hash
        memcpy(iv, &*(buffer+strlen(RENAME_ACCEPTED)+BLANK_SPACE+HASH_LEN+BLANK_SPACE), IV_LEN); // iv    
        
        // Check hash
        msg_to_hash_len = strlen(RENAME_ACCEPTED)+BLANK_SPACE+IV_LEN+BLANK_SPACE+LEN_SIZE; 
        msg_to_hash = (unsigned char*) malloc(msg_to_hash_len*sizeof(unsigned char));
        if (!msg_to_hash) exit_with_failure("Malloc msg_to_hash failed", 1);

        temp = (char*) malloc(sizeof(char)*LEN_SIZE);
        if (!temp) exit_with_failure("Malloc temp failed", 1);

        sprintf(temp, "%d", *nonce);
        memcpy(msg_to_hash, RENAME_ACCEPTED, strlen(RENAME_ACCEPTED));  // rename acc
        memcpy(&*(msg_to_hash+strlen(RENAME_ACCEPTED)), " ", BLANK_SPACE);
        memcpy(&*(msg_to_hash+strlen(RENAME_ACCEPTED)+BLANK_SPACE), iv, IV_LEN); // iv
        memcpy(&*(msg_to_hash+strlen(RENAME_ACCEPTED)+BLANK_SPACE+IV_LEN), " ", BLANK_SPACE);
        memcpy(&*(msg_to_hash+strlen(RENAME_ACCEPTED)+BLANK_SPACE+IV_LEN+BLANK_SPACE), temp, LEN_SIZE); // nonce

        digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len);    
        if (digest_len != (unsigned int) HASH_LEN) exit_with_failure("Wrong digest len", 0);

        ret = CRYPTO_memcmp(digest, bufferSupp2, HASH_LEN);
        if (ret == -1)
        {
            printf("Wrong rename succeed hash\n\n");
            ret = -1;
        }
        else
        {
            printf("The rename request has been accepted!\n\n");
            ret = 1;
        }

        free(digest);
        free(temp);
        free(msg_to_hash);
    }
    else
    {
        printf("We don't know what the server said...\n\n");
        ret = -1;
    }


    free(buffer);
    free(bufferSupp1);
    free(bufferSupp2);
    free(iv);

    return ret;
}



int deleteClient(int sock, char* username, char* filename)
{        
    int ret;
    char buffer[BUF_LEN];
    
    // SET DELETE REQUEST BUFFER
    memset(buffer, 0, BUF_LEN);
    sprintf(buffer, "%s %s %s", DELETE_REQUEST, username, filename);
    buffer[BUF_LEN-1] = '\0';

    // HERE ADD CRYPTOGRAPHIC FUNCTION TO SET PROPERLY THE BUFFER
    ret = send(sock, buffer, BUF_LEN, 0);
    if (ret == -1)
    {
        printf("Send operation gone bad\n");
        // Change this later to manage properly the session
        exit(1);
    }
    printf("Delete request message sent\n");
    memset(buffer, 0, strlen(buffer));
    ret = recv(sock, buffer, BUF_LEN,0);
    if (ret == -1)
    {
        printf("Receive operation gone bad\n");
        // Change this later to manage properly the session
        exit(1);
    }

    // HERE USE DECRYPTION TO UNDERSTAND WHAT YOU RECEIVE

    // END COMMUNICATION

    printf("%s\n", buffer);
    return 1;
}

int downloadClient(int sock, char* username, char* filename)
{
    int ret, nchunk, i, j, k, r, rest;
    char buffer[BUF_LEN];
    FILE* f1;
    char bufferSupp1[BUF_LEN];
    char bufferSupp2[BUF_LEN];
    char bufferSupp3[BUF_LEN];

    int position;

    if (chdir(MAIN_FOLDER_CLIENT) == -1)
	{
		printf("I'm having some problem with the change directory to the main folder of the software...\n\n");
	}
    f1 = fopen(filename, "r");
    if (f1 == NULL) printf("Starting the download...\n\n");
    else
    {
        fclose(f1);
        printf("Filename already exists. Download request over...\n\n");
        return -1;
    }

    // SANITIZE FILENAME(VERY IMPORTANT)

    // SET DOWNLOAD REQUEST BUFFER
    memset(buffer, 0, strlen(buffer));
    sprintf(buffer, "%s %s %s", DOWNLOAD_REQUEST, username, filename);
    printf("I'm sending %s\n\n", buffer);

    // HERE ADD CRYPTOGRAPHIC FUNCTION TO SET PROPERLY THE BUFFER

    ret = send(sock, buffer, strlen(buffer), 0);
    if (ret == -1)
    {
        printf("Send operation gone bad\n");
        // Change this later to manage properly the session
        exit(1);
    }
    memset(buffer, 0, strlen(buffer));

    // I'm going to receive a messsage with this format: download_accepted username number_of_chunk

    ret = recv(sock, buffer, BUF_LEN, 0);
    if (ret == -1)
    {
        printf("Receive operation gone bad\n");
        // Change this later to manage properly the session
        exit(1);
    }
    printf("I'm receiving %s", buffer);
    memset(bufferSupp1, 0, strlen(bufferSupp1));
    memset(bufferSupp2, 0, strlen(bufferSupp2));
    memset(bufferSupp3, 0, strlen(bufferSupp3));
    sscanf(buffer, "%s %s %s", bufferSupp1, bufferSupp2, bufferSupp3); // bufferSupp3 = number_of_chunk
    nchunk = atoi(bufferSupp2);
    rest = atoi(bufferSupp3);
    printf("The number of chunk is %i", nchunk); 
    if (nchunk == 0)
    {
        printf("The number of chunk is 0, this means that the file is empty. Download refused!\n\n");
        return 1;
    }

    f1 = fopen(filename, "w");
    for (i = 0; i < nchunk; i++)
    {
        printf("We are receiving the chunk number %i...\n\n", i);
        memset(buffer, 0, strlen(buffer));
        // I'm receveing a message with this format: download_chunk n_chunk payload
        ret = recv(sock, buffer, BUF_LEN, 0);
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
    ret = send(sock, buffer, BUF_LEN, 0);
    if (ret == -1)
    {
        printf("Send operation gone bad\n");
        // Change this later to manage properly the session
        exit(1);
    }
    printf("Download completed!\n\n");
    return 1;
}


int cryptoDownloadClient(int sock, char* username, char* filename, unsigned char* session_key1, unsigned char* session_key2, int* nonce)
{
    char* reason;
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
    
    size_t offset;
    FILE* f1;
    int position;

    int ret, nchunk, i, j, k, r, rest;
    int msg_len;
    char* temp;
    unsigned char* buffer;
    unsigned char* bufferSupp1;
    unsigned char* bufferSupp2;
    unsigned char* bufferSupp3;
    unsigned char* chunk;

    

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
    msg_to_hash = (unsigned char*) malloc(sizeof(unsigned char)*msg_to_hash_len);
    if (!msg_to_hash) exit_with_failure("Malloc msg_to_hash failed", 1);
    temp = (char*) malloc(sizeof(char)*LEN_SIZE);
    if (!temp) exit_with_failure("Malloc temp failed", 1);

    sprintf(temp, "%d", *nonce); // Now in temp there is the string version of the nonce
    memcpy(msg_to_hash, DOWNLOAD_REQUEST, strlen(DOWNLOAD_REQUEST));
    memcpy(&*(msg_to_hash+strlen(DOWNLOAD_REQUEST)), " ", BLANK_SPACE);
    memcpy(&*(msg_to_hash+strlen(DOWNLOAD_REQUEST)+BLANK_SPACE), encr_msg, encr_len); // encr
    memcpy(&*(msg_to_hash+strlen(DOWNLOAD_REQUEST)+BLANK_SPACE+encr_len), " ", BLANK_SPACE);
    memcpy(&*(msg_to_hash+strlen(DOWNLOAD_REQUEST)+BLANK_SPACE+encr_len+BLANK_SPACE), iv, IV_LEN); // iv
    memcpy(&*(msg_to_hash+strlen(DOWNLOAD_REQUEST)+BLANK_SPACE+encr_len+BLANK_SPACE+IV_LEN), " ", BLANK_SPACE);
    memcpy(&*(msg_to_hash+strlen(DOWNLOAD_REQUEST)+BLANK_SPACE+encr_len+BLANK_SPACE+IV_LEN+BLANK_SPACE), temp, LEN_SIZE); // nonce

    digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len);    
    if (digest_len != (unsigned int) HASH_LEN) exit_with_failure("Wrong digest len", 0);

    // Now that we have both the encryption and the digest of the hash we can initialize the buffer and send the message
    msg_len = strlen(RENAME_REQUEST)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE+encr_len+BLANK_SPACE+HASH_LEN+BLANK_SPACE+IV_LEN;

    buffer = (unsigned char*) malloc(sizeof(unsigned char)*msg_len);
    if (!buffer) exit_with_failure("Malloc buffer failed", 1);

    memcpy(buffer, DOWNLOAD_REQUEST, strlen(DOWNLOAD_REQUEST));  // download req
    memcpy(&*(buffer+strlen(DOWNLOAD_REQUEST)), " ", BLANK_SPACE);
    sprintf(temp, "%d", encr_len); //DONT KNOW IF IT WORKS IN ANY CASE
    memcpy(&*(buffer+strlen(DOWNLOAD_REQUEST)+BLANK_SPACE), temp, LEN_SIZE); // len encr
    memcpy(&*(buffer+strlen(DOWNLOAD_REQUEST)+BLANK_SPACE+LEN_SIZE), " ", BLANK_SPACE);
    memcpy(&*(buffer+strlen(DOWNLOAD_REQUEST)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE), encr_msg, encr_len); // encr
    memcpy(&*(buffer+strlen(DOWNLOAD_REQUEST)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE+encr_len), " ", BLANK_SPACE);
    memcpy(&*(buffer+strlen(DOWNLOAD_REQUEST)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE+encr_len+BLANK_SPACE), digest, HASH_LEN); // hash
    memcpy(&*(buffer+strlen(DOWNLOAD_REQUEST)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE+encr_len+BLANK_SPACE+HASH_LEN), " ", BLANK_SPACE);
    memcpy(&*(buffer+strlen(DOWNLOAD_REQUEST)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE+encr_len+BLANK_SPACE+HASH_LEN+BLANK_SPACE), iv, IV_LEN);// iv
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
    buffer = (unsigned char*) malloc(sizeof(unsigned char)*msg_len);
    if (!buffer) exit_with_failure("Malloc buffer failed", 1);

    ret = recv(sock, buffer, msg_len,0);
    if (ret == -1) exit_with_failure("Receive failed", 0);
    printf("Received the server's response.\n");

    bufferSupp1 = (unsigned char*) malloc(strlen(DOWNLOAD_DENIED)*sizeof(unsigned char));
    if (!bufferSupp1) exit_with_failure("Malloc bufferSupp1 failed", 1);
    memcpy(bufferSupp1, buffer, strlen(DOWNLOAD_DENIED)); // denied or accepted same length


    // Parse the message based on the server response
    if (strcmp(bufferSupp1, DOWNLOAD_DENIED) == 0)
    {
        // WAITING FOR TEO STUFFS
    }
    else if (strcmp(bufferSupp1, DOWNLOAD_ACCEPTED) == 0)
    {        
        //HERE WE SHOULD CHECK THE HASH: the format of the message received should be: DOWNLOAD_ACCEPTED, nchunk, rest, hash, iv
        // Parse the message
        bufferSupp2 = (unsigned char*) malloc(sizeof(unsigned char)*HASH_LEN);
        if (!bufferSupp2) exit_with_failure("Malloc bufferSupp2 failed", 1);
        iv = (unsigned char*) malloc(sizeof(unsigned char)*IV_LEN);
        if (!iv) exit_with_failure("Malloc iv failed", 1);
        memcpy(bufferSupp2, &*(buffer+strlen(DOWNLOAD_ACCEPTED)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE+REST_SIZE+BLANK_SPACE), HASH_LEN); // hash
        memcpy(iv, &*(buffer+strlen(DOWNLOAD_ACCEPTED)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE+REST_SIZE+BLANK_SPACE+HASH_LEN+BLANK_SPACE), IV_LEN); // iv
        
        //SETTING OF THE NCHUNK AND THE REST VARIABLE RECEIVED BY THE SERVER
        free(bufferSupp1);
        bufferSupp1 = (char*)malloc(sizeof(char)*LEN_SIZE); // Here we save the nchunk value of the message
        if (!bufferSupp1) exit_with_failure("Malloc bufferSupp1 for nchunk failed", 1);
        temp = (char*)malloc(sizeof(char)*REST_SIZE); // Here we save the number of bytes of the last chunk
        if (!temp) exit_with_failure("Malloc bufferSupp1 for nchunk failed", 1);
        memcpy(bufferSupp1, &*(buffer+strlen(DOWNLOAD_ACCEPTED)+BLANK_SPACE), LEN_SIZE); //We put the nchunk value on bufferSupp1
        memcpy(temp, &*(buffer+strlen(DOWNLOAD_ACCEPTED)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE), REST_SIZE);
        nchunk = atoi(bufferSupp1);
        rest = atoi(temp);
        free(temp);
        if (nchunk == 0)
        {
            printf("The number of chunk is 0, this means that the file is empty. Download refused!\n\n");
            return 1;
        }
        
        // Check hash on DOWNLOAD_ACCEPTED, NONCE, NCHUNK, REST, IV
        msg_to_hash_len = strlen(DOWNLOAD_ACCEPTED)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE+LEN_SIZE+REST_SIZE+BLANK_SPACE+IV_LEN; 
        msg_to_hash = (unsigned char*) malloc(msg_to_hash_len*sizeof(unsigned char));
        if (!msg_to_hash) exit_with_failure("Malloc msg_to_hash failed", 1);

        temp = (char*) malloc(sizeof(char)*LEN_SIZE); //Here we save the nonce
        if (!temp) exit_with_failure("Malloc temp failed", 1);
        bufferSupp3 = (char*)malloc(sizeof(char)*REST_SIZE); // Here we save the rest value of the message
        if (!bufferSupp3) exit_with_failure("Malloc bufferSupp3 for nchunk failed", 1);

        sprintf(temp, "%d", *nonce);
        memcpy(bufferSupp3, &*(bufferSupp2+strlen(DOWNLOAD_ACCEPTED)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE), REST_SIZE);

        memcpy(msg_to_hash, DOWNLOAD_ACCEPTED, strlen(DOWNLOAD_ACCEPTED));  // download acc
        memcpy(&*(msg_to_hash+strlen(DOWNLOAD_ACCEPTED)), " ", BLANK_SPACE);
        memcpy(&*(msg_to_hash+strlen(DOWNLOAD_ACCEPTED)+BLANK_SPACE), temp, LEN_SIZE); // nonce
        memcpy(&*(msg_to_hash+strlen(RENAME_ACCEPTED)+BLANK_SPACE+LEN_SIZE), " ", BLANK_SPACE);
        memcpy(&*(msg_to_hash+strlen(RENAME_ACCEPTED)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE), bufferSupp1, LEN_SIZE); //nchunk
        memcpy(&*(msg_to_hash+strlen(RENAME_ACCEPTED)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE+LEN_SIZE), " ", BLANK_SPACE);
        memcpy(&*(msg_to_hash+strlen(RENAME_ACCEPTED)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE+LEN_SIZE+BLANK_SPACE), bufferSupp3, REST_SIZE);
        memcpy(&*(msg_to_hash+strlen(RENAME_ACCEPTED)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE+LEN_SIZE+BLANK_SPACE+REST_SIZE), " ", BLANK_SPACE);
        memcpy(&*(msg_to_hash+strlen(RENAME_ACCEPTED)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE+LEN_SIZE+BLANK_SPACE+REST_SIZE+BLANK_SPACE), iv, IV_LEN);  

        digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len);    
        if (digest_len != (unsigned int) HASH_LEN) exit_with_failure("Wrong digest len", 0);

        ret = CRYPTO_memcmp(digest, bufferSupp2, HASH_LEN);
        if (ret == -1)
        {
            printf("Wrong download accepted hash\n\n");
            ret = -1;
        }
        else
        {
            printf("The download request has been accepted!\n\n");
            ret = 1;
        }

        free(digest);
        free(temp);
        free(msg_to_hash);
        free(bufferSupp1);
        free(bufferSupp2);
        free(bufferSupp3);
        free(iv);

        //NOW WE CAN BEGIN DOWNLOAD THE CHUNKS
        f1 = fopen(filename, "w");
        for (i = 0; i < nchunk; i++)
        {
            //THE FORMAT OF THE CHUNK MESSAGE IS LEN_ENC, {FILENAME, CHUNK}K1, H(FILENAME, CHUNK, NONCE)
            msg_len = strlen(filename)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE+BUF_LEN+BLANK_SPACE+HASH_LEN+BLANK_SPACE+IV_LEN;
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
            encr_len = atoi(bufferSupp1);
            bufferSupp2 = (unsigned char*)malloc(encr_len);
            if (!bufferSupp2) exit_with_failure("Malloc bufferSupp2 failed", 1);
            memcpy(bufferSupp2, &*(buffer+LEN_SIZE+BLANK_SPACE), encr_len);
            
            decrypt_AES_128_CBC(&plaintext, &plain_len, bufferSupp2, encr_len, iv, session_key1);
            if (i == nchunk-1)
            {
                chunk = (unsigned char*)malloc(sizeof(unsigned char)*rest);
                memcpy(chunk, plaintext, rest);
            }
            else
            {
                chunk = (unsigned char*)malloc(sizeof(unsigned char)*CHUNK_SIZE);
                memcpy(chunk, plaintext, CHUNK_SIZE);
            }

            free(bufferSupp1);
            free(buffer);

            //NOW WE SHOULD COMPARE THE TWO DIGEST TO AUTHENTICATE THE MESSAGE
            temp = (unsigned char*)malloc(sizeof(unsigned char)*LEN_SIZE);
            sprintf(temp, "%d", nonce);
            bufferSupp3 = (unsigned char*)malloc(HASH_LEN*sizeof(unsigned char*));
            if (!bufferSupp3) exit_with_failure("Malloc bufferSupp3 failed", 1);
            memcpy(bufferSupp3, &*(buffer+LEN_SIZE+BLANK_SPACE+encr_len+BLANK_SPACE), HASH_LEN); //Here we have the hash to compare
            msg_to_hash_len = plain_len + BLANK_SPACE + LEN_SIZE + BLANK_SPACE + IV_LEN;
            msg_to_hash = (unsigned char*)malloc(sizeof(unsigned char)*msg_to_hash_len);
            memcpy(&*(msg_to_hash), bufferSupp2, encr_len);
            memcpy(&*(msg_to_hash+encr_len), " ", BLANK_SPACE);
            memcpy(&*(msg_to_hash+encr_len+BLANK_SPACE), temp, LEN_SIZE);
            memcpy(&*(msg_to_hash+encr_len+BLANK_SPACE+LEN_SIZE), " ", BLANK_SPACE);
            memcpy(&*(msg_to_hash+encr_len+BLANK_SPACE+LEN_SIZE+BLANK_SPACE), iv, IV_LEN);

            digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len);    
            if (digest_len != (unsigned int) HASH_LEN) exit_with_failure("Wrong digest len", 0);

            ret = CRYPTO_memcmp(digest, bufferSupp3, HASH_LEN);
            if (ret == -1)
            {
                printf("Wrong download chunk hash\n\n");
                ret -1;
            }

            free(digest);
            free(temp);
            free(msg_to_hash);
            free(bufferSupp1);
            free(bufferSupp2);
            free(bufferSupp3);
            free(iv);

            if (i == nchunk-1) for (j = 0; j < rest; j++) fprintf(f1, "%c", *(plaintext+j));
	        else for (j = 0; j < CHUNK_SIZE; j++) fprintf(f1, "%c", *(plaintext+j));
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
        msg_to_hash = (unsigned char*) malloc(sizeof(unsigned char)*msg_to_hash_len);
        if (!msg_to_hash) exit_with_failure("Malloc msg_to_hash failed", 1);
        temp = (char*) malloc(sizeof(char)*LEN_SIZE);
        if (!temp) exit_with_failure("Malloc temp failed", 1);

        sprintf(temp, "%d", *nonce); // Now in temp there is the string version of the nonce
        memcpy(msg_to_hash, DOWNLOAD_FINISHED, strlen(DOWNLOAD_FINISHED));
        memcpy(&*(msg_to_hash+strlen(DOWNLOAD_FINISHED)), " ", BLANK_SPACE);
        memcpy(&*(msg_to_hash+strlen(DOWNLOAD_FINISHED)+BLANK_SPACE), temp, LEN_SIZE); // nonce
        memcpy(&*(msg_to_hash+strlen(DOWNLOAD_FINISHED)+BLANK_SPACE+LEN_SIZE), " ", BLANK_SPACE);
        memcpy(&*(msg_to_hash+strlen(DOWNLOAD_FINISHED)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE), iv, IV_LEN); // iv
        
        digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len);    
        if (digest_len != (unsigned int) HASH_LEN) exit_with_failure("Wrong digest len", 0);

        // Now that we have both the encryption and the digest of the hash we can initialize the buffer and send the message
        msg_len = strlen(DOWNLOAD_FINISHED)+BLANK_SPACE+HASH_LEN+BLANK_SPACE+IV_LEN;

        buffer = (unsigned char*) malloc(sizeof(unsigned char)*msg_len);
        if (!buffer) exit_with_failure("Malloc buffer failed", 1);

        memcpy(buffer, DOWNLOAD_FINISHED, strlen(DOWNLOAD_FINISHED));  // download finished
        memcpy(&*(buffer+strlen(DOWNLOAD_FINISHED)), " ", BLANK_SPACE);
        memcpy(&*(buffer+strlen(DOWNLOAD_FINISHED)+BLANK_SPACE), digest, HASH_LEN); // hash
        memcpy(&*(buffer+strlen(DOWNLOAD_FINISHED)+BLANK_SPACE+HASH_LEN), " ", BLANK_SPACE);
        memcpy(&*(buffer+strlen(DOWNLOAD_FINISHED)+BLANK_SPACE+HASH_LEN+BLANK_SPACE), iv, IV_LEN); // encr
        // The message in the buffer now is: DOWNLOAD_FINISHED, hash, iv. We can send it now

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
        sprintf(buffer, "%s %s %s %i %d", UPLOAD_REQUEST, username, filename, nchunk, rest);

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