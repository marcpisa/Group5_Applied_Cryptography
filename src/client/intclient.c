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

int loginClient(unsigned char* session_key1, unsigned char* session_key2, char* username, struct sockaddr_in srv_addr, X509_STORE* ca_store) {
    /*********************
     * VARIABLES
     ********************/
    char* path_pubkey;
    char* path_rsa_key;
    unsigned int msg_len;
    size_t offset;
    size_t K_len;

    // Encryption/Decryption (AES-128-CBC)
    unsigned char* iv;
    unsigned char* ciphertext;
    unsigned char* msg_to_ver;
    
    int iv_len;
    int cipherlen;

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
    int rcv_pubkey_len;
    
    // Certificate
    X509* serv_cert = NULL;
    EVP_PKEY* pub_rsa_key_serv;
    int cert_len;

    int sock, ret;
    char* temp;
    unsigned char* buffer;
    unsigned char* cert_buffer;
    unsigned char bufferSupp1[BUF_LEN];
    unsigned char bufferSupp2[BUF_LEN];
    unsigned char bufferSupp3[BUF_LEN];
    unsigned char bufferSupp4[BUF_LEN];
    /*********************
     * END VARIABLES
     ********************/

    // Creation of socket
    sock = createSocket();
    if (connect(sock, (struct sockaddr*)&srv_addr, sizeof(srv_addr)) < 0) exit_with_failure("Connect failed", 1);

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
    

    /* ---- 1st message: login request message + username + DH pubkey + IV + dig.sig.(IV) ---- */
    // Generate the IV
    iv = (unsigned char*) malloc(sizeof(unsigned char)*IV_LEN);
    if (!iv) exit_with_failure("Malloc iv failed", 1);
    RAND_poll(); // Seed OpenSSL PRNG
    ret = RAND_bytes((unsigned char*)&iv[0], IV_LEN);
    if (ret != 1) exit_with_failure("RAND_bytes failed\n", 0);
    iv_len = IV_LEN;

    // IV digital signature
    signature = sign_msg(path_rsa_key, iv, iv_len, &signature_len);  

    // Calculate the message length and allocate the memory
    msg_len = strlen(LOGIN_REQUEST)+strlen(" ")+strlen(username)+strlen(" ")+LEN_SIZE+ \
    strlen(" ")+pubkey_len+strlen(" ")+LEN_SIZE+strlen(" ")+iv_len+strlen(" ")+ \
    LEN_SIZE+strlen(" ")+signature_len+1;
    buffer = (unsigned char*) malloc(sizeof(unsigned char)*(msg_len+1));
    if (!buffer) exit_with_failure("Malloc buffer failed", 1);
    temp = (char*) malloc(sizeof(char)*LEN_SIZE);
    if (!temp) exit_with_failure("Malloc temp failed", 1);

    /* Compose the message and send it to the server (login_request username len_pubkey pubkey 
    len_iv iv len_digsig signature_iv) */
    memcpy(buffer, LOGIN_REQUEST, strlen(LOGIN_REQUEST));  // login req
    memcpy(&*(buffer+strlen(LOGIN_REQUEST)), " ", strlen(" "));
    memcpy(&*(buffer+strlen(LOGIN_REQUEST)+strlen(" ")), username, strlen(username)); // username
    memcpy(&*(buffer+strlen(LOGIN_REQUEST)+strlen(" ")+strlen(username)), " ", strlen(" "));
    
    sprintf(temp, "%d", pubkey_len);
    memcpy(&*(buffer+strlen(LOGIN_REQUEST)+strlen(" ")+strlen(username)+strlen(" ")), temp, \
    LEN_SIZE); // len pubkey
    
    memcpy(&*(buffer+strlen(LOGIN_REQUEST)+strlen(" ")+strlen(username)+strlen(" ")+LEN_SIZE), \
    " ", strlen(" "));
    memcpy(&*(buffer+strlen(LOGIN_REQUEST)+strlen(" ")+strlen(username)+strlen(" ")+LEN_SIZE+ \
    strlen(" ")), pubkey_byte, pubkey_len); // dh pubkey
    memcpy(&*(buffer+strlen(LOGIN_REQUEST)+strlen(" ")+strlen(username)+strlen(" ")+LEN_SIZE+ \
    strlen(" ")+pubkey_len), " ", strlen(" ")); 
    
    sprintf(temp, "%d", iv_len);
    memcpy(&*(buffer+strlen(LOGIN_REQUEST)+strlen(" ")+strlen(username)+strlen(" ")+LEN_SIZE+ \
    strlen(" ")+pubkey_len+strlen(" ")), temp, LEN_SIZE); // len iv
    
    memcpy(&*(buffer+strlen(LOGIN_REQUEST)+strlen(" ")+strlen(username)+strlen(" ")+LEN_SIZE+ \
    strlen(" ")+pubkey_len+strlen(" ")+LEN_SIZE), " ", strlen(" "));
    memcpy(&*(buffer+strlen(LOGIN_REQUEST)+strlen(" ")+strlen(username)+strlen(" ")+LEN_SIZE+ \
    strlen(" ")+pubkey_len+strlen(" ")+LEN_SIZE+strlen(" ")), iv, iv_len); // iv
    memcpy(&*(buffer+strlen(LOGIN_REQUEST)+strlen(" ")+strlen(username)+strlen(" ")+LEN_SIZE+ \
    strlen(" ")+pubkey_len+strlen(" ")+LEN_SIZE+strlen(" ")+iv_len), " ", strlen(" "));
    
    sprintf(temp, "%d", signature_len);
    memcpy(&*(buffer+strlen(LOGIN_REQUEST)+strlen(" ")+strlen(username)+strlen(" ")+LEN_SIZE+ \
    strlen(" ")+pubkey_len+strlen(" ")+LEN_SIZE+strlen(" ")+iv_len+strlen(" ")), \
    temp, LEN_SIZE); // len dig. sig.
    
    memcpy(&*(buffer+strlen(LOGIN_REQUEST)+strlen(" ")+strlen(username)+strlen(" ")+LEN_SIZE+ \
    strlen(" ")+pubkey_len+strlen(" ")+LEN_SIZE+strlen(" ")+iv_len+strlen(" ")+ \
    LEN_SIZE), " ", strlen(" "));
    memcpy(&*(buffer+strlen(LOGIN_REQUEST)+strlen(" ")+strlen(username)+strlen(" ")+LEN_SIZE+ \
    strlen(" ")+pubkey_len+strlen(" ")+LEN_SIZE+strlen(" ")+iv_len+strlen(" ")+ \
    LEN_SIZE+strlen(" ")), signature, signature_len); // iv dig. sig.

    memcpy(&*(buffer+msg_len-1), "\0", 1);
    /* 
    for(int i = 0; i < msg_len; i++) { printf("%c", *(buffer+i)); }
    printf("\n\n");    
    */
    //printf("%d\n%d\n%d\n", pubkey_len, iv_len, signature_len);
    printf("I'm sending to the server the first message.\n");
    ret = send(sock, buffer, msg_len, 0);
    if (ret == -1) exit_with_failure("Send failed", 1);

    free(buffer);
    free(signature);
    free(temp);




    /* ---- Obtain and parse response server (username, DH pubkey, signature and cert.) ----*/
    msg_len = 4*BUF_LEN;
    buffer = (unsigned char*) malloc(sizeof(unsigned char)*msg_len);
    if (!buffer) exit_with_failure("Malloc buffer failed", 1);
    ret = recv(sock, buffer, msg_len, 0);
    if (ret == -1) exit_with_failure("Receive failed", 1);
    printf("Received the response of the server.\n");
    temp = (char*) malloc(sizeof(char)*LEN_SIZE);
    if (!temp) exit_with_failure("Malloc temp failed", 1);

    // Parse the server response
    memset(bufferSupp1, 0, BUF_LEN);
    memset(bufferSupp2, 0, BUF_LEN);
    memset(bufferSupp3, 0, BUF_LEN);

    offset = str_ssplit(buffer, DELIM);
    memcpy(bufferSupp1, buffer, strlen(username)); // username
    offset += strlen(" ");

    memcpy(temp, &*(buffer+offset), LEN_SIZE); // len dig.sig
    offset += LEN_SIZE+strlen(" ");
    signature_len = atoi(temp);

    memcpy(bufferSupp2, &*(buffer+offset), signature_len); // dig.sig.
    offset += signature_len+strlen(" ");

    memcpy(temp, &*(buffer+offset), LEN_SIZE); // len pubkey
    offset += LEN_SIZE+strlen(" ");
    rcv_pubkey_len = atoi(temp);
    if(rcv_pubkey_len != pubkey_len) exit_with_failure("Wrong pubkey len", 0);

    memcpy(bufferSupp3, &*(buffer+offset), rcv_pubkey_len); // g^b
    offset += rcv_pubkey_len+strlen(" ");

    memcpy(temp, &*(buffer+offset), LEN_SIZE); // len cert
    offset += LEN_SIZE+strlen(" ");
    cert_len = atoi(temp);

    // The certificate is greater than 1024
    cert_buffer = (unsigned char*) malloc((cert_len+1)*sizeof(unsigned char));
    if (!cert_buffer) exit_with_failure("cert_buffer malloc failed", 1);
    memcpy(cert_buffer, &*(buffer+offset), cert_len); // cert
    
    free(temp);
    free(buffer);

    // Sanitization username and check validity
    if (!username_sanitization((char*) bufferSupp1)) exit_with_failure("Username sanitization fails\n", 0);    
    if (strcmp(username, (char*) bufferSupp1) != 0) exit_with_failure("Wrong username\n", 0);

    // Obtain the public key, derive the established key
    peer_pubkey = pubkey_to_PKEY(bufferSupp3, pubkey_len);
    K = key_derivation(my_prvkey, peer_pubkey, &K_len);

    // Obtain the two session keys from the established key
    issue_session_keys(K, K_len, &session_key1, &session_key2);
    
    // Decrypt the message (digital signature) (bufferSupp2)
    msg_to_ver = (unsigned char*) malloc(sizeof(unsigned char) * BUF_LEN);
    if (!msg_to_ver) exit_with_failure("Malloc msg_to_ver failed", 1);
    decrypt_AES_128_CBC(&msg_to_ver, &msg_len, bufferSupp2, signature_len, iv, K);
   
    // Obtain the RSA public key and verify the certificate of the server
    serv_cert = cert_to_X509(cert_buffer, cert_len);
    if (!serv_cert) exit_with_failure("cert_to_X509 failed", 1);
    pub_rsa_key_serv = get_ver_server_pubkey(serv_cert, ca_store);
    X509_free(serv_cert);
    free(cert_buffer);

    // Generate the digital signature expected
    expected_len = pubkey_len+strlen(" ")+pubkey_len;
    exp_digsig = (unsigned char*) malloc(sizeof(unsigned char)*expected_len);
    if (!exp_digsig) exit_with_failure("Malloc exp_digsig failed", 1);
    
    memcpy(exp_digsig, pubkey_byte, pubkey_len);
    memcpy(&*(exp_digsig+pubkey_len), " ", strlen(" "));
    memcpy(&*(exp_digsig+pubkey_len+strlen(" ")), bufferSupp3, pubkey_len); // peer pubkey is still inside bufferSupp3
    
    // Verify the digital signature received (decrypted in the previous step)
    ret = verify_signature(exp_digsig, expected_len, msg_to_ver, msg_len, pub_rsa_key_serv);
    if (ret != 1) exit_with_failure("Signature verification failed.\n", 0);
    
    free(pubkey_byte);
    free(msg_to_ver);
    EVP_PKEY_free(pub_rsa_key_serv);
    EVP_PKEY_free(my_prvkey);




    /* Generate last message for the server (username + digital signature) */
    // Sign exp_digsig with private key of client and encrypt the signature with K
    signature = sign_msg(path_rsa_key, exp_digsig, expected_len, &signature_len);
    ciphertext = (unsigned char*) malloc(signature_len + BLOCK_SIZE);
    if (!ciphertext) exit_with_failure("Malloc ciphertext failed", 1);
    encrypt_AES_128_CBC(&ciphertext, &cipherlen, signature, signature_len, iv, K);
    
    msg_len = strlen(username) + strlen(" ") + LEN_SIZE + strlen(" ") + cipherlen;
    buffer = (unsigned char*) malloc(sizeof(unsigned char)*msg_len);
    if (!buffer) exit_with_failure("Malloc buffer failed", 1);
    temp = (char*) malloc(sizeof(char)*LEN_SIZE);
    if (!temp) exit_with_failure("Malloc temp failed", 1);

    // Compose the message (username len_digsig signature)
    memcpy(buffer, username, strlen(username)); // username
    memcpy(&*(buffer+strlen(username)), " ", strlen(" "));

    sprintf(temp, "%d", cipherlen);
    memcpy(&*(buffer+strlen(username)+strlen(" ")), temp, LEN_SIZE); // len dig. sig.

    memcpy(&*(buffer+strlen(username)+strlen(" ")+LEN_SIZE), " ", strlen(" "));
    memcpy(&*(buffer+strlen(username)+strlen(" ")+LEN_SIZE+strlen(" ")), ciphertext, \
    cipherlen); // signature
    
    //printf("%s\n", buffer);
    printf("I'm sending to the server the last message.\n");
    ret = send(sock, buffer, msg_len, 0); 
    if (ret == -1) exit_with_failure("Send failed", 1);

    free(path_pubkey);
    free(path_rsa_key);

    free(temp);
    free(buffer);
    free(ciphertext);
    free(signature);
    free(exp_digsig);
    free(iv);
    free(K);



    /*CHECK IF ALL IS CORRECT WITH THE LAST MESSAGE OF THE SERVER */
    
    return 1;
}

int logoutClient(int* nonce, unsigned char* session_key2, struct sockaddr_in srv_addr)
{
    int sock;
    int digest_len;
    int ret;
    int temp_nonce;
    unsigned int msg_len;
    unsigned int msg_to_hash_len;

    size_t offset;

    char* temp;
    unsigned char* buffer;
    unsigned char* bufferSupp1;
    unsigned char* bufferSupp2;
    unsigned char* msg_to_hash;
    unsigned char* digest;

    sock = createSocket();
    if (connect(sock, (struct sockaddr*)&srv_addr, sizeof(srv_addr)) < 0) exit_with_failure("Connect failed", 1);

    // Message length of the first message (request + nonce + hash)
    msg_len = strlen(LOGOUT_REQUEST)+strlen(" ")+LEN_SIZE+strlen(" ")+HASH_LEN;

    // Generating the hash of the request and the nonce
    msg_to_hash_len = strlen(LOGOUT_REQUEST)+strlen(" ")+LEN_SIZE;
    msg_to_hash = (unsigned char*) malloc(sizeof(unsigned char)*msg_to_hash_len);
    if (!msg_to_hash) exit_with_failure("Malloc buffer failed", 1);
    temp = (char*) malloc(sizeof(char)*LEN_SIZE);
    if (!temp) exit_with_failure("Malloc temp failed", 1);

    sprintf(temp, "%d", *nonce);
    memcpy(msg_to_hash, LOGOUT_REQUEST, strlen(LOGOUT_REQUEST));  // logout req
    memcpy(&*(msg_to_hash+strlen(LOGOUT_REQUEST)), " ", strlen(" "));
    memcpy(&*(msg_to_hash+strlen(LOGOUT_REQUEST)+strlen(" ")), temp, LEN_SIZE); // nonce

    digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, digest_len);    
    if (digest_len != HASH_LEN) exit_with_failure("Wrong digest len", 0);

    // Compose the message
    buffer = (unsigned char*) malloc(sizeof(unsigned char)*msg_len);
    if (!buffer) exit_with_failure("Malloc buffer failed", 1);

    memcpy(buffer, msg_to_hash, msg_to_hash_len);  // logout req + nonce
    memcpy(&*(buffer+msg_to_hash_len), " ", strlen(" "));
    memcpy(&*(buffer+msg_to_hash_len+strlen(" ")), digest, HASH_LEN); // hash

    printf("I'm sending to the server the logout message.\n");
    ret = send(sock, buffer, msg_len, 0); 
    if (ret == -1) exit_with_failure("Send failed", 1);
    *nonce = *nonce+1; // message sent, nonce increased for the answer

    free(temp);
    free(buffer);
    free(msg_to_hash);
    free(digest);



    // Check the response (logoutSucceed + nonce + hash)
    msg_len = strlen(LOGOUT_ACCEPTED)+strlen(" ")+LEN_SIZE+strlen(" ")+HASH_LEN;
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
    offset += strlen(" ");

    memcpy(temp, &*(buffer+offset), LEN_SIZE); // nonce
    offset += LEN_SIZE+strlen(" ");
    temp_nonce = atoi(temp);

    memcpy(bufferSupp2, &*(buffer+offset), HASH_LEN); // hash

    // Check logout accepted
    if(!strcmp(LOGOUT_ACCEPTED, bufferSupp1)) exit_with_failure("The field is not logout_accepted, error.", 0);

    // Check nonce
    if (temp_nonce != *nonce) exit_with_failure("Nonce is incorrect, error.", 0);

    // Check hash correctness
    msg_to_hash_len = strlen(LOGOUT_ACCEPTED)+strlen(" ")+LEN_SIZE;
    msg_to_hash = (unsigned char*) malloc(sizeof(unsigned char)*msg_to_hash_len);
    if (!msg_to_hash) exit_with_failure("Malloc buffer failed", 1);
    
    memcpy(msg_to_hash, LOGOUT_ACCEPTED, strlen(LOGOUT_ACCEPTED));
    memcpy(&*(msg_to_hash+strlen(LOGOUT_ACCEPTED)), " ", strlen(" "));
    memcpy(&*(msg_to_hash+strlen(LOGOUT_ACCEPTED)+strlen(" ")), temp, LEN_SIZE); // nonce

    digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, digest_len);   
    ret = CRYPTO_memcmp(digest, bufferSupp2, HASH_LEN);

    free(msg_to_hash);
    free(digest);
    free(temp);
    free(buffer);
    free(bufferSupp1);
    free(bufferSupp2);
       
    return ret;
}

int listClient(char* username, struct sockaddr_in srv_addr)
{
    
    int sock, ret;
    char buffer[BUF_LEN];
    sock = createSocket();

    if (connect(sock, (struct sockaddr*)&srv_addr, sizeof(srv_addr)) < 0) 
    {
        printf("\nConnection Failed \n");
        exit(1);
    }

    
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
    printf("List request message sent\n");
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

int renameClient(char* username,char* filename, char* new_filename, struct sockaddr_in srv_addr)
{
    int sock, ret;
    char buffer[BUF_LEN];
    char bufferSupp1[BUF_LEN];
    char bufferSupp2[BUF_LEN];
    sock = createSocket();

    if (connect(sock, (struct sockaddr*)&srv_addr, sizeof(srv_addr)) < 0) 
    {
        printf("\nConnection Failed \n");
        exit(1);
    }


    //Add: show message when filename is to long to user --> check server side though. 

    // SANITIZE FILENAME AND NEW_FILENAME (VERY IMPORTANT)

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



int deleteClient(char* username, char* filename, struct sockaddr_in srv_addr)
{        
    int sock, ret;
    char buffer[BUF_LEN];
    sock = createSocket();

    if (connect(sock, (struct sockaddr*)&srv_addr, sizeof(srv_addr)) < 0) 
    {
        printf("\nConnection Failed \n");
        exit(1);
    }

    
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

int downloadClient(char* username, char* filename, struct sockaddr_in srv_addr)
{
    int sock, ret, nchunk, i, j, k, r, rest;
    char buffer[BUF_LEN];
    FILE* f1;
    char bufferSupp1[BUF_LEN];
    char bufferSupp2[BUF_LEN];
    char bufferSupp3[BUF_LEN];

    int position;

    sock = createSocket();

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

    if (connect(sock, (struct sockaddr*)&srv_addr, sizeof(srv_addr)) < 0) 
    {
        printf("\nConnection Failed \n");
        exit(1);
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


int uploadClient(char* username, char* filename, struct sockaddr_in srv_addr)
{
    // We received a message with this format: download_request username filenameù
    char buffer[BUF_LEN];
    char bufferSupp1[BUF_LEN];
    char bufferSupp2[BUF_LEN];
    char bufferSupp3[BUF_LEN];
    char payload[CHUNK_SIZE+1];
    struct stat st;
    int i, j, nchunk, ret, start_payload, sock, rest;
    FILE* fd;

    sock = createSocket();

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
        if (connect(sock, (struct sockaddr*)&srv_addr, sizeof(srv_addr)) < 0) 
        {
            printf("\nConnection Failed \n");
            exit(1);
        }

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
        sprintf(bufferSupp1, "%s %s ", DOWNLOAD_CHUNK, filename); //Format of the message sent is: type_mex filename payload
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
    if (!(strcmp(bufferSupp1, DOWNLOAD_FINISHED)==0) || !(strcmp(bufferSupp2, username)==0) || !(strcmp(bufferSupp3, filename)==0))
    {
        printf("Error in the last message sent: message of end download\n\n");
        return -1;
    }
    printf("We have completed successfully the donwload operation!\n\n");
    return 1;
}



int shareClient(char* username, char* filename, char* peername, struct sockaddr_in srv_addr)
{
    char buffer[BUF_LEN];
    char bufferSupp1[BUF_LEN];
    char bufferSupp2[BUF_LEN];
    char bufferSupp3[BUF_LEN];
    int sock, ret;

    sock = createSocket();

    memset(buffer, 0, strlen(buffer));
    memset(bufferSupp1, 0, strlen(bufferSupp1));
    memset(bufferSupp2, 0, strlen(bufferSupp2));
    memset(bufferSupp3, 0, strlen(bufferSupp3));

    if (connect(sock, (struct sockaddr*)&srv_addr, sizeof(srv_addr)) < 0) 
    {
        printf("\nConnection Failed \n");
        exit(1);
    }

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
    int ret, i;
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
}