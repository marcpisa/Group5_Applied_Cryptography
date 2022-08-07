#include "intclient.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include <openssl/rand.h>

/*********************************************
 *          AUXILIARY FUNCTIONS 
 *********************************************/
unsigned char* pubkey_to_byte(EVP_PKEY* pub_key, int* pub_key_len) 
{
    BIO *bio = NULL;
    unsigned char *key = NULL;
    int key_len = 0;
    int ret;

    bio = BIO_new(BIO_s_mem());
    ret = PEM_write_bio_PUBKEY(bio, pub_key);
    if (ret != 1) exit_with_failure("PEM_write_bio_PUBKEY failed", 1);

    key_len = BIO_pending(bio);
    *pub_key_len = key_len;

    key = (unsigned char *) malloc(sizeof(unsigned char) * key_len);

    BIO_read(bio, key, key_len);
    BIO_free(bio);

    return key;
}

EVP_PKEY* pubkey_to_PKEY(unsigned char* public_key, int len)
{
    BIO* mbio = BIO_new(BIO_s_mem());
    BIO_write(mbio, public_key, len);

    EVP_PKEY* pk = NULL;
    pk = PEM_read_bio_PUBKEY(mbio, NULL, NULL, NULL);
    BIO_free(mbio);

    return pk;
}

X509* cert_to_X509(unsigned char* cert, int cert_len)
{
    BIO* mbio = BIO_new(BIO_s_mem());
    BIO_write(mbio, cert, cert_len);

    X509* crt = PEM_read_bio_X509(mbio, NULL, NULL, NULL);
    BIO_free(mbio);

    return crt;
}


size_t str_ssplit(unsigned char* a_str, const unsigned char a_delim)
{
    size_t count = 0;
    unsigned char* tmp = a_str;
    
    // Count how many elements there are before delim
    while (*tmp)
    {
        if (a_delim == *tmp)
        {
            count++;
            break;
        }
        tmp++;
    }

    return count;
}

EVP_PKEY* save_read_PUBKEY(char* path_pubkey, EVP_PKEY* my_prvkey)
{
    FILE* file_pubkey_pem = fopen(path_pubkey, "w");
    if (file_pubkey_pem == NULL) exit_with_failure("Fopen failed", 1);
    int ret = PEM_write_PUBKEY(file_pubkey_pem, my_prvkey);
    fclose(file_pubkey_pem);
    if (ret != 1) exit_with_failure("PEM_write_PUBKEY failed", 1);
    
    // Retrieve the saved public key
    file_pubkey_pem = fopen(path_pubkey, "r");
    if (file_pubkey_pem == NULL) exit_with_failure("Fopen failed", 1);
    EVP_PKEY* dh_pubkey = PEM_read_PUBKEY(file_pubkey_pem, NULL, NULL, NULL);
    fclose(file_pubkey_pem);
    if (dh_pubkey == NULL) exit_with_failure("PEM_read_PUBKEY failed", 1);

    return dh_pubkey;
}

void exit_with_failure(char* err, int perror_enable) {
    if (perror_enable) 
    {
        perror(err);
    }
    else 
    {
        printf("%s\n", err);
    }
    exit(EXIT_FAILURE);
}

void encrypt_AES_128_CBC(unsigned char* out, int* out_len, unsigned char* in, unsigned char* iv, unsigned char* key)
{
    int ret;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx) exit_with_failure("EVP_CIPHER_CTX_new failed", 1);

    ret = EVP_EncryptInit(ctx, EVP_aes_128_cbc(), key, iv);
    if (ret != 1) exit_with_failure("EncryptInit failed", 1);
    
    int update_len = 0; // bytes encrypted at each chunk
    int total_len = 0; // total encrypted bytes

    ret = EVP_EncryptUpdate(ctx, out, &update_len, in, strlen((char*)in));
    printf("%d\n", update_len);
    if (ret != 1) exit_with_failure("EncryptUpdate failed", 1);
    total_len += update_len;

    ret = EVP_EncryptFinal(ctx, out + total_len, &update_len);
    if (ret != 1) exit_with_failure("EncryptFinal failed", 1);
    total_len += update_len;
    *out_len = total_len;

    EVP_CIPHER_CTX_free(ctx);  
}

void decrypt_AES_128_CBC(unsigned char* out, int* out_len, unsigned char* in, unsigned char* iv, unsigned char* key)
{
    int ret;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx) exit_with_failure("EVP_CIPHER_CTX_new failed", 1);
    
    ret = EVP_DecryptInit(ctx, EVP_aes_128_cbc(), key, iv);
    if (ret != 1) exit_with_failure("DecryptInit failed", 1);

    int update_len = 0; // bytes decrypted at each chunk
    int total_len = 0; // total decrypted bytes
   
    ret = EVP_DecryptUpdate(ctx, out, &update_len, in, strlen((char*)in));
    if (ret != 1) exit_with_failure("DecryptUpdate failed", 1);
    total_len += update_len;

    ret = EVP_DecryptFinal(ctx, out + total_len, &update_len);
    if (ret != 1) exit_with_failure("DecryptFinal failed", 1);
    total_len += update_len;
    *out_len = total_len;

    EVP_CIPHER_CTX_free(ctx);   
}

unsigned char* hash_SHA256(char* msg)
{
    unsigned char* digest;
    int digestlen;
    EVP_MD_CTX* ctx;
    int ret;

    /* Buffer allocation for the digest */
    digest = (unsigned char*)malloc(HASH_LEN);

    /* Context allocation */
    ctx = EVP_MD_CTX_new();
    if(!ctx) exit_with_failure("EVP_MD_CTX_new failed", 1);

    /* Hashing */
    ret = EVP_DigestInit(ctx, EVP_sha256());
    if (ret != 1) exit_with_failure("DigestUpdate failed", 1);
    ret = EVP_DigestUpdate(ctx, (unsigned char*)msg, strlen(msg));
    if (ret != 1) exit_with_failure("DigestUpdate failed", 1);
    ret = EVP_DigestFinal(ctx, digest, &digestlen);
    if (ret != 1) exit_with_failure("DigestFinal failed", 1);

    /* Context deallocation */
    EVP_MD_CTX_free(ctx);
    
    return digest;
}

unsigned char* sign_msg(char* path_key, char* password, unsigned char* msg_to_sign, int* signature_len)
{
    int ret;

    FILE* file_prvkey_pem = fopen(path_key, 'r');
    if(file_prvkey_pem == NULL) exit_with_failure("Open failed", 1);

    EVP_PKEY* rsa_prvkey = PEM_read_PrivateKey(file_prvkey_pem, NULL, NULL, password);
    fclose(file_prvkey_pem);
    if (rsa_prvkey == NULL) exit_with_failure("PEM_read_PrivateKey failed", 1);

    EVP_MD_CTX* ctx_digsig = EVP_MD_CTX_new();
    if(!ctx_digsig) exit_with_failure("EVP_MD_CTX_new failed", 1);

    unsigned char* signature = malloc(EVP_PKEY_size(rsa_prvkey));
    
    ret = EVP_SignInit(ctx_digsig, EVP_sha256());
    if (ret != 1) exit_with_failure("SignInit failed", 1);
    ret = EVP_SignUpdate(ctx_digsig, msg_to_sign, strlen((char*)msg_to_sign));
    if (ret != 1) exit_with_failure("SignUpdate failed", 1);
    ret = EVP_SignFinal(ctx_digsig, signature, &signature_len, rsa_prvkey);
    if (ret != 1) exit_with_failure("SignFinal failed", 1);

    EVP_MD_CTX_free(ctx_digsig);

    return signature;
}

int verify_signature(unsigned char* exp_digsig, unsigned char* msg_to_ver, EVP_PKEY* pub_rsa_key)
{
    int ret;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if(!ctx) exit_with_failure("EVP_MD_CTX_new failed", 1);
    
    ret = EVP_VerifyInit(ctx, EVP_sha256());
    if (ret != 1) exit_with_failure("VerifyInit failed", 1);
    ret = EVP_VerifyUpdate(ctx, exp_digsig, strlen((char*)exp_digsig));
    if (ret != 1) exit_with_failure("VerifyUpdate failed", 1);
    ret = EVP_VerifyFinal(ctx, msg_to_ver, strlen((char*)msg_to_ver), pub_rsa_key);
    if (ret != 1) return 0;

    EVP_MD_CTX_free(ctx);
    return 1;
}



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
    const unsigned char delim = ' ';
    char* path_pubkey = "../dh_client1_pubkey.pem"; // TO CHANGE (for multiple clients)
    char* path_rsa_key = "../rsa_client1.pem"; // TO CHANGE
    char* password = "password";
    int msg_len;
    size_t offset;
    size_t old_offset;

    FILE* file_prvkey_pem;
    EVP_PKEY* priv_rsa_key_client;

    // Encryption/Decryption (AES-128-CBC)
    unsigned char* iv;
    unsigned char* ciphertext;
    unsigned char* msg_to_ver;
    int cipherlen;

    // Hashing and digital signature
    unsigned char* digest;
    unsigned char* exp_digsig;
    unsigned char* signature;
    EVP_MD_CTX* ctx_digest;
    int digestlen;
    int expected_len;
    int signature_len;

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
    FILE* file_pubkey_pem;
    EVP_PKEY* dh_pubkey;

    // Certificate
    X509* serv_cert;
    EVP_PKEY* pub_rsa_key_serv;
    X509_STORE_CTX* ctx_cert;

    int sock, ret;
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
    ret = RAND_bytes((unsigned char*)&iv[0],IV_LEN);
    if (ret != 1) exit_with_failure("RAND_bytes failed\n", 0);

    signature = sign_msg(path_rsa_key, password, iv, &signature_len);

    // msg_len = strlen(LOGIN_REQUEST)+strlen(" ")+strlen(username)+strlen(" ")+DH_PUBKEY_SIZE+ \
    strlen(" ")+IV_LEN+signature_len;
    msg_len = MAX_LEN_REQUEST+strlen(" ")+MAX_LEN_USERNAME+strlen(" ")+DH_PUBKEY_SIZE+ \
    strlen(" ")+IV_LEN+signature_len;
    buffer = (unsigned char*) malloc(sizeof(unsigned char)*msg_len);
    if (buffer == NULL) exit_with_failure("Malloc buffer failed", 1);
    
    // Compose the message and send it to the server
    memcpy(buffer, LOGIN_REQUEST, MAX_LEN_REQUEST);  // login req
    memcpy(&*(buffer+MAX_LEN_REQUEST), " ", strlen(" "));
    memcpy(&*(buffer+MAX_LEN_REQUEST+strlen(" ")), username, MAX_LEN_USERNAME); // username
    memcpy(&*(buffer+MAX_LEN_REQUEST+strlen(" ")+MAX_LEN_USERNAME), " ", strlen(" "));
    memcpy(&*(buffer+MAX_LEN_REQUEST+strlen(" ")+MAX_LEN_USERNAME+strlen(" ")), pubkey_byte, \
    DH_PUBKEY_SIZE); // dh pubkey
    memcpy(&*(buffer+MAX_LEN_REQUEST+strlen(" ")+MAX_LEN_USERNAME+strlen(" ")+DH_PUBKEY_SIZE), \
    " ", strlen(" "));
    memcpy(&*(buffer+MAX_LEN_REQUEST+strlen(" ")+MAX_LEN_USERNAME+strlen(" ")+DH_PUBKEY_SIZE+ \
    strlen(" ")), iv, IV_LEN); // iv
    memcpy(&*(buffer+MAX_LEN_REQUEST+strlen(" ")+MAX_LEN_USERNAME+strlen(" ")+DH_PUBKEY_SIZE+ \
    strlen(" ")+IV_LEN), " ", strlen(" "));
    memcpy(&*(buffer+MAX_LEN_REQUEST+strlen(" ")+MAX_LEN_USERNAME+strlen(" ")+DH_PUBKEY_SIZE+ \
    strlen(" ")+IV_LEN+strlen(" ")), signature, signature_len); // iv dig. sig.

    //printf("%s\n", buffer);
    printf("I'm sending to the server the mex %s\n\n", buffer);
    ret = send(sock, buffer, msg_len, 0); 
    if (ret == -1) exit_with_failure("Send failed", 1);

    free(buffer);
    free(signature);




    /* ---- Obtain and parse response server (username, DH pubkey, signature and cert.) ----*/
    buffer = (unsigned char*) malloc(sizeof(unsigned char)*4*BUF_LEN);
    if (buffer == NULL) exit_with_failure("Malloc buffer failed", 1);
    ret = recv(sock, buffer, 4*BUF_LEN, 0);
    if (ret == -1) exit_with_failure("Receive failed", 1);
    
    // Parse the server response
    memset(bufferSupp1, 0, strlen(bufferSupp1));
    memset(bufferSupp2, 0, strlen(bufferSupp2));
    memset(bufferSupp3, 0, strlen(bufferSupp3));
    memset(bufferSupp4, 0, strlen(bufferSupp4));

    offset = str_ssplit(buffer, delim);
    memcpy(bufferSupp1, buffer, offset); // username
    old_offset = offset;

    offset = str_ssplit(&*(buffer+offset), delim);
    memcpy(bufferSupp2, &*(buffer+old_offset), offset); // dig.sig.
    old_offset = offset;

    offset = str_ssplit(&*(buffer+offset), delim);
    memcpy(bufferSupp3, &*(buffer+old_offset), offset); // g^b
    old_offset = offset;

    offset = str_ssplit(&*(buffer+offset), delim);
    memcpy(bufferSupp4, &*(buffer+old_offset), offset); // cert
    //old_offset = offset;

    free(buffer);

    // Sanitization username and check validity
    if (!username_sanitization(bufferSupp1)) exit_with_failure("Username sanitization fails\n", 0);    
    if (strcmp(username, bufferSupp1) != 0) exit_with_failure("Wrong username\n", 0);

    // Obtain the public key, derive the established key
    peer_pubkey = pubkey_to_PKEY(bufferSupp3, DH_PUBKEY_SIZE);
    
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
    decrypt_AES_128_CBC(&msg_to_ver, &msg_len, bufferSupp2, iv, K_trunc);
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
    expected_len = DH_PUBKEY_SIZE+strlen(" ")+DH_PUBKEY_SIZE;
    exp_digsig = (unsigned char*) malloc(sizeof(unsigned char)*expected_len);
    if (exp_digsig == NULL) exit_with_failure("Malloc exp_digsig failed", 1);
    
    memcpy(exp_digsig, pubkey_byte, pubkey_len);
    memcpy(&*(exp_digsig+DH_PUBKEY_SIZE), " ", strlen(" "));
    memcpy(&*(exp_digsig+DH_PUBKEY_SIZE+strlen(" ")), bufferSupp3, DH_PUBKEY_SIZE); // peer pubkey is still inside bufferSupp3
    
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
    encrypt_AES_128_CBC(&ciphertext, &cipherlen, signature, iv, K_trunc);
    if (cipherlen > 1023) exit_with_failure("Ciphertext too long", 0);

    msg_len = MAX_LEN_USERNAME + strlen(" ") + cipherlen;
    buffer = (unsigned char*) malloc(sizeof(unsigned char)*msg_len);
    if (buffer == NULL) exit_with_failure("Malloc buffer failed", 1);
 
    memcpy(buffer, username, MAX_LEN_USERNAME);
    memcpy(&*(buffer+MAX_LEN_USERNAME), " ", strlen(" "));
    memcpy(&*(buffer+MAX_LEN_USERNAME+strlen(" ")), ciphertext, cipherlen);
    
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