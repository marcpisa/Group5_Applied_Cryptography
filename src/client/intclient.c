#include "intclient.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include <openssl/rand.h>

/*********************************************
 *          AUXILIARY FUNCTIONS 
 *********************************************/




/*********************************************
 *                 INTERFACES
 ********************************************/
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

int loginClient(char* session_key1, char* session_key2, char* username, struct sockaddr_in srv_addr, X509_STORE* ca_store) {
    /*********************
     * VARIABLES
     ********************/
    char* path_pubkey = "../dh_client1_pubkey.pem"; // TO CHANGE (for multiple clients)
    char* path_rsa_key = "../rsa_teo.pem"; // TO CHANGE
    char* password = "password";
    unsigned int msg_len;
    size_t offset;
    size_t old_offset;

    // Encryption/Decryption (AES-128-CBC)
    unsigned char* iv;
    int iv_len;
    unsigned char* ciphertext;
    unsigned char* msg_to_ver;
    int cipherlen;

    // Hashing and digital signature
    unsigned char* digest;
    unsigned char* exp_digsig;
    unsigned char* signature;
    EVP_MD_CTX* ctx_digest;
    unsigned int digestlen;
    int expected_len;
    unsigned int signature_len;

    // Diffie-Hellman
    EVP_PKEY* dh_params;
    EVP_PKEY_CTX* ctx_dh;
    EVP_PKEY* my_prvkey = NULL;
    EVP_PKEY* peer_pubkey;
    unsigned char* K;
    unsigned char* K_trunc;
    unsigned char* pubkey_byte;
    int pubkey_len = 0;
    EVP_PKEY_CTX* ctx_drv;
    size_t secretlen;
    EVP_PKEY* dh_pubkey;

    // Certificate
    X509* serv_cert;
    EVP_PKEY* pub_rsa_key_serv;
    X509_STORE_CTX* ctx_cert;

    int sock, ret;
    char* temp;
    unsigned char* buffer;
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

    // Generate DH asymmetric key(s)
    dh_params = EVP_PKEY_new();
    ret = EVP_PKEY_set1_DH(dh_params, DH_get_1024_160());
    if (ret != 1) exit_with_failure("EVP_PKEY_set1_DH failed", 1);

    ctx_dh = EVP_PKEY_CTX_new(dh_params, NULL);
    if(!ctx_dh) exit_with_failure("EVP_PKEY_CTX_new failed", 1);
    
    ret = EVP_PKEY_keygen_init(ctx_dh);
    if (ret != 1) exit_with_failure("keygen_init failed", 1);
    ret = EVP_PKEY_keygen(ctx_dh, &my_prvkey);
    if (ret != 1) exit_with_failure("keygen failed", 1);

    // Save DH key in PEM format and retrieve the public key
    dh_pubkey = save_read_PUBKEY(path_pubkey, my_prvkey);
    pubkey_byte = pubkey_to_byte(dh_pubkey, &pubkey_len);
 
    free(ctx_dh);
    free(dh_params);




    /* ---- 1st message: login request message + username + DH pubkey + IV + dig.sig.(IV) ---- */
    // Generate the IV and the related hash
    iv = (unsigned char*)malloc(IV_LEN);
    if (iv == NULL) exit_with_failure("Malloc iv failed", 1);
    RAND_poll(); // Seed OpenSSL PRNG
    ret = RAND_bytes((unsigned char*)&iv[0], IV_LEN);
    if (ret != 1) exit_with_failure("RAND_bytes failed\n", 0);
    iv_len = strlen((char*) iv);
    signature = sign_msg(path_rsa_key, password, iv, &signature_len);

    msg_len = strlen(LOGIN_REQUEST)+strlen(" ")+strlen(username)+strlen(" ")+sizeof(unsigned int)+ \
    strlen(" ")+pubkey_len+strlen(" ")+sizeof(unsigned int)+strlen(" ")+iv_len+strlen(" ")+ \
    sizeof(unsigned int)+strlen(" ")+signature_len;
    buffer = (unsigned char*) malloc(sizeof(unsigned char)*msg_len);
    if (buffer == NULL) exit_with_failure("Malloc buffer failed", 1);
    temp = (char*) malloc(sizeof(char)*4);
    if (temp == NULL) exit_with_failure("Malloc temp failed", 1);

    // Compose the message and send it to the server
    memcpy(buffer, LOGIN_REQUEST, strlen(LOGIN_REQUEST));  // login req
    memcpy(&*(buffer+strlen(LOGIN_REQUEST)), " ", strlen(" "));
    memcpy(&*(buffer+strlen(LOGIN_REQUEST)+strlen(" ")), username, strlen(username)); // username
    memcpy(&*(buffer+strlen(LOGIN_REQUEST)+strlen(" ")+strlen(username)), " ", strlen(" "));
    sprintf(temp, "%d", pubkey_len);
    memcpy(&*(buffer+strlen(LOGIN_REQUEST)+strlen(" ")+strlen(username)+strlen(" ")), temp, \
    4); // len pubkey
    memcpy(&*(buffer+strlen(LOGIN_REQUEST)+strlen(" ")+strlen(username)+strlen(" ")+sizeof(unsigned int)), \
    " ", strlen(" "));
    memcpy(&*(buffer+strlen(LOGIN_REQUEST)+strlen(" ")+strlen(username)+strlen(" ")+sizeof(unsigned int)+ \
    strlen(" ")), pubkey_byte, pubkey_len); // dh pubkey
    memcpy(&*(buffer+strlen(LOGIN_REQUEST)+strlen(" ")+strlen(username)+strlen(" ")+sizeof(unsigned int)+ \
    strlen(" ")+pubkey_len), " ", strlen(" ")); 
    sprintf(temp, "%d", iv_len);
    memcpy(&*(buffer+strlen(LOGIN_REQUEST)+strlen(" ")+strlen(username)+strlen(" ")+sizeof(unsigned int)+ \
    strlen(" ")+pubkey_len+strlen(" ")), temp, 4); // len iv
    memcpy(&*(buffer+strlen(LOGIN_REQUEST)+strlen(" ")+strlen(username)+strlen(" ")+sizeof(unsigned int)+ \
    strlen(" ")+pubkey_len+strlen(" ")+sizeof(unsigned int)), " ", strlen(" "));
    memcpy(&*(buffer+strlen(LOGIN_REQUEST)+strlen(" ")+strlen(username)+strlen(" ")+sizeof(unsigned int)+ \
    strlen(" ")+pubkey_len+strlen(" ")+sizeof(unsigned int)+strlen(" ")), iv, iv_len); // iv
    memcpy(&*(buffer+strlen(LOGIN_REQUEST)+strlen(" ")+strlen(username)+strlen(" ")+sizeof(unsigned int)+ \
    strlen(" ")+pubkey_len+strlen(" ")+sizeof(unsigned int)+strlen(" ")+iv_len), " ", strlen(" "));
    sprintf(temp, "%d", signature_len);
    memcpy(&*(buffer+strlen(LOGIN_REQUEST)+strlen(" ")+strlen(username)+strlen(" ")+sizeof(unsigned int)+ \
    strlen(" ")+pubkey_len+strlen(" ")+sizeof(unsigned int)+strlen(" ")+iv_len+strlen(" ")), \
    temp, 4); // len dig. sig.
    memcpy(&*(buffer+strlen(LOGIN_REQUEST)+strlen(" ")+strlen(username)+strlen(" ")+sizeof(unsigned int)+ \
    strlen(" ")+pubkey_len+strlen(" ")+sizeof(unsigned int)+strlen(" ")+iv_len+strlen(" ")+ \
    sizeof(unsigned int)), " ", strlen(" "));
    memcpy(&*(buffer+strlen(LOGIN_REQUEST)+strlen(" ")+strlen(username)+strlen(" ")+sizeof(unsigned int)+ \
    strlen(" ")+pubkey_len+strlen(" ")+sizeof(unsigned int)+strlen(" ")+iv_len+strlen(" ")+ \
    sizeof(unsigned int)+strlen(" ")), signature, signature_len); // iv dig. sig.

    printf("I'm sending to the server the first message.\n");
    ret = send(sock, buffer, msg_len, 0);
    if (ret == -1) exit_with_failure("Send failed", 1);

    free(buffer);
    free(signature);
    free(temp);




    /* ---- Obtain and parse response server (username, DH pubkey, signature and cert.) ----*/
    buffer = (unsigned char*) malloc(sizeof(unsigned char)*4*BUF_LEN);
    if (buffer == NULL) exit_with_failure("Malloc buffer failed", 1);
    ret = recv(sock, buffer, 4*BUF_LEN, 0);
    if (ret == -1) exit_with_failure("Receive failed", 1);
    
    printf("MSG: %s\n", buffer);

    // Parse the server response
    memset(bufferSupp1, 0, BUF_LEN);
    memset(bufferSupp2, 0, BUF_LEN);
    memset(bufferSupp3, 0, BUF_LEN);
    memset(bufferSupp4, 0, BUF_LEN);

    offset = str_ssplit(buffer, DELIM);
    memcpy(bufferSupp1, buffer, strlen(username)); // username
    old_offset = offset;

    offset = str_ssplit(&*(buffer+offset), DELIM);
    memcpy(bufferSupp2, &*(buffer+old_offset), offset); // dig.sig.
    old_offset = offset;

    offset = str_ssplit(&*(buffer+offset), DELIM);
    memcpy(bufferSupp3, &*(buffer+old_offset), offset); // g^b
    old_offset = offset;

    offset = str_ssplit(&*(buffer+offset), DELIM);
    memcpy(bufferSupp4, &*(buffer+old_offset), offset); // cert
    //old_offset = offset;

    free(buffer);

    // Sanitization username and check validity
    if (!username_sanitization((char*) bufferSupp1)) exit_with_failure("Username sanitization fails\n", 0);    
    //printf("%s %s\n", username, (char*) bufferSupp1);
    if (strcmp(username, (char*) bufferSupp1) != 0) exit_with_failure("Wrong username\n", 0);

    // Obtain the public key, derive the established key
    peer_pubkey = pubkey_to_PKEY(bufferSupp3, pubkey_len);
    
    ctx_drv = EVP_PKEY_CTX_new(my_prvkey, NULL);
    if (!ctx_drv) exit_with_failure("EVP_PKEY_CTX_new failed", 1);
    
    ret = EVP_PKEY_derive_init(ctx_drv);
    if (ret != 1) exit_with_failure("PKEY_derive_init failed", 1);
    ret = EVP_PKEY_derive_set_peer(ctx_drv, peer_pubkey);
    if (ret != 1) exit_with_failure("PKEY_derive_set_peer failed", 1);
    ret = EVP_PKEY_derive(ctx_drv, NULL, &secretlen);
    if (ret != 1) exit_with_failure("PKEY_derive failed", 1);

    // Deriving shared secret K = g^a^b mod p
    K = (unsigned char*)malloc(secretlen); // 128 byte = 1024 bit
    if (K == NULL) exit_with_failure("Malloc K failed", 1);

    ret = EVP_PKEY_derive(ctx_drv, K, &secretlen);
    if (ret != 1) exit_with_failure("PKEY_derive failed", 1);

    // Obtain the two session keys
    digest = (unsigned char*)malloc(EVP_MD_size(EVP_sha256()));
    if (digest == NULL) exit_with_failure("Malloc digest failed", 1);

    ctx_digest = EVP_MD_CTX_new();
    if (!ctx_digest) exit_with_failure("EVP_MD_CTX_new failed", 1);
    ret = EVP_DigestInit(ctx_digest, EVP_sha256());
    if (ret != 1) exit_with_failure("DigestInit failed", 1);
    ret = EVP_DigestUpdate(ctx_digest, K, sizeof(K));
    if (ret != 1) exit_with_failure("DigestUpdate failed", 1);
    ret = EVP_DigestFinal(ctx_digest, digest, &digestlen);
    if (ret != 1) exit_with_failure("DigestFinal failed", 1);

    EVP_MD_CTX_free(ctx_digest);

    memcpy(session_key1, digest, 16); // 16 byte = 128 bit
    memcpy(session_key2, &*(digest+16), 16);
    //printf("Digest:%s\nS1:%s\nS2:%s\n", digest, session_key1, session_key2);
    free(digest);

    // TEST ---- K from 1024 to 128 bit for symm. encr.
    K_trunc = (unsigned char*) malloc(sizeof(unsigned char) * 16); 
    if (K_trunc ==  NULL) exit_with_failure("Malloc K_trunc failed", 1);
    memcpy(K_trunc, K, EVP_CIPHER_key_length(EVP_aes_128_cbc()));
    free(K);

    // Decrypt the message (bufferSupp2)
    msg_to_ver = (unsigned char*) malloc(sizeof(unsigned char) * BUF_LEN);
    if (msg_to_ver ==  NULL) exit_with_failure("Malloc msg_to_ver failed", 1);
    decrypt_AES_128_CBC(msg_to_ver, &msg_len, bufferSupp2, iv, K_trunc);
    free(K_trunc);

    // Obtain the RSA public key and verify the certificate
    serv_cert = cert_to_X509(bufferSupp4, sizeof(bufferSupp4));
    pub_rsa_key_serv = X509_get_pubkey(serv_cert);

    ctx_cert = X509_STORE_CTX_new();
    if (!ctx_cert) exit_with_failure("X509_STORE_CTX_new failed", 1);
    ret = X509_STORE_CTX_init(ctx_cert, ca_store, serv_cert, NULL);
    if (ret != 1) exit_with_failure("X509_STORE_CTX_init failed", 1);
    ret = X509_verify_cert(ctx_cert);
    if (ret != 1) exit_with_failure("X509_verify_cert failed", 1);

    X509_STORE_CTX_free(ctx_cert);

    // Generate the digital signature expected
    expected_len = pubkey_len+strlen(" ")+pubkey_len;
    exp_digsig = (unsigned char*) malloc(sizeof(unsigned char)*expected_len);
    if (exp_digsig == NULL) exit_with_failure("Malloc exp_digsig failed", 1);
    
    memcpy(exp_digsig, pubkey_byte, pubkey_len);
    memcpy(&*(exp_digsig+pubkey_len), " ", strlen(" "));
    memcpy(&*(exp_digsig+pubkey_len+strlen(" ")), bufferSupp3, pubkey_len); // peer pubkey is still inside bufferSupp3
    
    // Verify the digital signature received
    ret = verify_signature(exp_digsig, msg_to_ver, pub_rsa_key_serv);
    if (ret != 1) exit_with_failure("Signature verification failed.\n", 0);

    free(pubkey_byte);
    free(msg_to_ver);




    /* Generate last message for the server (username + digital signature) */
    // Sign exp_digsig with private key of client and encrypt the signature with K
    signature = sign_msg(path_rsa_key, password, exp_digsig, &signature_len);
    ciphertext = (unsigned char*)malloc(sizeof(signature) + BLOCK_SIZE);
    if (ciphertext == NULL) exit_with_failure("Malloc ciphertext failed", 1);
    encrypt_AES_128_CBC(ciphertext, &cipherlen, signature, iv, K_trunc);
    if (cipherlen > 1023) exit_with_failure("Ciphertext too long", 0);

    msg_len = strlen(username) + strlen(" ") + cipherlen;
    buffer = (unsigned char*) malloc(sizeof(unsigned char)*msg_len);
    if (buffer == NULL) exit_with_failure("Malloc buffer failed", 1);
 
    memcpy(buffer, username, strlen(username));
    memcpy(&*(buffer+strlen(username)), " ", strlen(" "));
    memcpy(&*(buffer+strlen(username)+strlen(" ")), ciphertext, cipherlen);
    
    //printf("%s\n", buffer);
    printf("I'm sending to the server the mex %s\n\n", buffer);
    ret = send(sock, buffer, msg_len, 0); 
    if (ret == -1) exit_with_failure("Send failed", 1);

    free(buffer);
    free(ciphertext);
    free(signature);
    free(exp_digsig);
    free(iv);
    
    return 1;
}