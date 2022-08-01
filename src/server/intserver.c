#include "intserver.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <sys/sendfile.h>
#include <openssl/x509.h>

/*********************************************
 *          AUXILIARY FUNCTIONS 
 ********************************************/

unsigned char* pubkey_to_byte(EVP_PKEY* pub_key, int* pub_key_len) 
{
    BIO *bio = NULL;
    unsigned char *key = NULL;
    int key_len = 0;

    bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, pub_key);

    key_len = BIO_pending(bio);
    *pub_key_len = key_len;

    key = (unsigned char *) malloc(sizeof(unsigned char) * key_len);

    BIO_read(bio, key, key_len);
    BIO_free(bio);

    return key;
}

unsigned char* cert_to_byte(X509* cert, int* cert_len)
{
    BIO *bio = NULL;
    unsigned char *c = NULL;
    int c_len = 0;

    bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio, cert);

    c_len = BIO_pending(bio);
    *cert_len = c_len;

    c = (unsigned char *) malloc(sizeof(unsigned char) * c_len);

    BIO_read(bio, c, c_len);
    BIO_free(bio);

    return c;
}

EVP_PKEY* pubkey_to_PKEY(unsigned char* public_key, int len){
    BIO* mbio = BIO_new(BIO_s_mem());
    BIO_write(mbio, public_key, len);

    EVP_PKEY* pk = NULL;
    pk =  PEM_read_bio_PUBKEY(mbio, NULL, NULL, NULL);
    BIO_free(mbio);

    return pk;
}

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

int loginServer(int sd, char* rec_mex, char* session_key1, char* session_key2)
{   
    unsigned char* buffer;
    unsigned char* msg_to_sign;
    unsigned char bufferSupp1[BUF_LEN];
    unsigned char bufferSupp2[BUF_LEN];
    unsigned char bufferSupp3[BUF_LEN];
    unsigned char bufferSupp4[BUF_LEN];
    char* path_pubkey = "../dh_server_pubkey.pem";
    char* path_peer_pubkey = "../dh_peer1_pubkey.pem";
    char* path_cert_rsa = "../cert.pem";
    char* path_rsa_key = "../key.pem";
    int ret;
    int msg_len;
    char username [MAX_SIZE_USERNAME];

    // Certificate
    X509* cert_rsa;
    FILE* file_cert_rsa;
    unsigned char* cert_byte;
    int cert_len = 0;

    // Symmetric encryption
    unsigned char* ciphertext;
    EVP_CIPHER_CTX* ctx_symmencr;
    int cipherlen;
    int outlen;

    // Hashing
    unsigned char* digest;
    int digestlen;
    EVP_MD_CTX* ctx_digest;

    // Digital Signature variables
    unsigned char* signature;
    int signature_len;
    EVP_MD_CTX* ctx_digsig;
    EVP_PKEY* rsa_prvkey;
    FILE* file_prvkey_pem;
    char* password = "password";

    // Diffie-Hellman variables
    EVP_PKEY* dh_params;
    EVP_PKEY_CTX* ctx;
    EVP_PKEY* my_prvkey = NULL;
    EVP_PKEY* peer_pubkey;
    unsigned char* K;
    unsigned char* pubkey_byte;
    int pubkey_len = 0;
    unsigned char* peer_pubkey_byte;
    int peer_pubkey_len = 0;
    EVP_PKEY_CTX* ctx_drv;
    size_t secretlen;
    FILE* file_pubkey_pem;
    EVP_PKEY* dh_pubkey;

    // REMEMBER TO SANITIZE PROPERLY THE BUFFER (VERY IMPORTANT)

    /* ---- Parse the first message ---- */
    memset(bufferSupp1, 0, BUF_LEN);
    memset(bufferSupp2, 0, BUF_LEN);
    memset(bufferSupp3, 0, BUF_LEN);
    memcpy(bufferSupp1, rec_mex, MAX_SIZE_REQUEST);
    memcpy(bufferSupp2, &*(rec_mex+MAX_SIZE_REQUEST+strlen(" ")), MAX_SIZE_USERNAME);
    memcpy(bufferSupp3, &*(rec_mex+MAX_SIZE_REQUEST+strlen(" ")+MAX_SIZE_USERNAME+strlen(" ")), MAX_SIZE_PUBKEY);
    //printf("%s\n%s\n%s\n", bufferSupp1, bufferSupp2, bufferSupp3);
    
    
    //SANITIZE AND CHECK THE CORRECTNESS OF BUFFERS' CONTENTS

    // Check username
    chdir(MAIN_FOLDER_SERVER);
    ret = chdir(bufferSupp2);
    if (ret == -1)
    {
        printf("Error: username doesn't exists...\n");
        exit(1);
    }
    memset(username, 0, MAX_SIZE_USERNAME);
    memcpy(username, bufferSupp2, BUF_LEN);

    peer_pubkey = pubkey_to_PKEY(bufferSupp3, MAX_SIZE_PUBKEY);

    /* ---- Generate a DH asymmetric key(s) ---- */
    dh_params = EVP_PKEY_new();
    EVP_PKEY_set1_DH(dh_params, DH_get_1024_160());

    ctx = EVP_PKEY_CTX_new(dh_params, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_keygen(ctx, &my_prvkey);

    // Save public key
    file_pubkey_pem = fopen(path_pubkey, "w");
    if (file_pubkey_pem == NULL) 
    { 
        printf("Error writing to PEM file.\n");
        // Change this later to manage properly the session
        exit(1);
    } 
    
    ret = PEM_write_PUBKEY(file_pubkey_pem, my_prvkey);
    fclose(file_pubkey_pem);
    if (ret != 1) {
        printf("Error on saving DH pubkey.\n");
        // Change this later to manage properly the session
        exit(1);
    }
    
    free(ctx);
    free(dh_params);
    // Retrieve the saved public key
    file_pubkey_pem = fopen(path_pubkey, "r"); // to fix path
    if (file_pubkey_pem == NULL) 
    { 
        printf("Error reading PEM file.\n");
        // Change this later to manage properly the session
        exit(1);
    } 
    
    dh_pubkey = PEM_read_PUBKEY(file_pubkey_pem, NULL, NULL, NULL);
    fclose(file_pubkey_pem);
    if (dh_pubkey == NULL) {
        printf("Error on reading DH pubkey from file.\n");
        // Change this later to manage properly the session
        exit(1);
    }
 
    /* ---- Calculate K = g^a^b mod p ---- */ 
    ctx_drv = EVP_PKEY_CTX_new(my_prvkey, NULL);
    EVP_PKEY_derive_init(ctx_drv);
    EVP_PKEY_derive_set_peer(ctx_drv, peer_pubkey);
    
    // Retrieving shared secret’s length
    EVP_PKEY_derive(ctx_drv, NULL, &secretlen);

    // Deriving shared secret
    K = (unsigned char*)malloc(secretlen); // 128 byte = 1024 bit
    EVP_PKEY_derive(ctx_drv, K, &secretlen);

    // Obtain the two session keys
    digest = (unsigned char*)malloc(EVP_MD_size(EVP_sha256()));
    ctx_digest = EVP_MD_CTX_new();
    EVP_DigestInit(ctx_digest, EVP_sha256());
    EVP_DigestUpdate(ctx, K, sizeof(K));
    EVP_DigestFinal(ctx, digest, &digestlen);
    EVP_MD_CTX_free(ctx);

    memcpy(session_key1, digest, 16); // 16 byte = 128 bit
    memcpy(session_key2, &*(digest+16), 16);
    printf("Digest:%s\nS1:%s\nS2:%s\n", digest, session_key1, session_key2);
    free(K);
    free(digest);

    /* --- Send response (username, dig.sign and DH pubkey+cert) --- */
    pubkey_byte = pubkey_to_byte(dh_pubkey, &pubkey_len);
    if (pubkey_len > MAX_SIZE_PUBKEY) //TO CHANGE
    {
        printf("Pubkey too long.\n");
        exit(-1);
    }

    // Prepare the digital signature
    msg_len = MAX_SIZE_PUBKEY+strlen(" ")+pubkey_len;
    msg_to_sign = (unsigned char*) malloc(sizeof(unsigned char)*msg_len);
    memcpy(msg_to_sign, bufferSupp3, MAX_SIZE_PUBKEY); // peer pubkey is still inside bufferSupp3
    memcpy(&*(buffer+MAX_SIZE_PUBKEY), " ", strlen(" "));
    memcpy(&*(buffer+MAX_SIZE_PUBKEY+strlen(" ")), pubkey_byte, pubkey_len);
    
    // Signature generation
    file_prvkey_pem = fopen(path_rsa_key, 'r');
    if(file_prvkey_pem == NULL) 
    {
        printf("Impossible to open prvkey file\n\n");
        exit(-1);
    }
    rsa_prvkey = PEM_read_PrivateKey(file_prvkey_pem, NULL, NULL, password);
    fclose(file_prvkey_pem);
    if (rsa_prvkey == NULL) {
        printf("Error on reading RSA prvkey from file.\n");
        // Change this later to manage properly the session
        exit(-1);
    }
    ctx_digsig = EVP_MD_CTX_new();
    signature = malloc(EVP_PKEY_size(rsa_prvkey));
    EVP_SignInit(ctx_digsig, EVP_sha256());
    EVP_SignUpdate(ctx_digsig, msg_to_sign, sizeof(msg_to_sign));
    EVP_SignFinal(ctx_digsig, signature, &signature_len, rsa_prvkey);
    EVP_MD_CTX_free(ctx_digsig);

    // Encrypt the signature (with first session key)
    ciphertext = (unsigned char*)malloc(sizeof(signature) + 16);
    ctx_symmencr = EVP_CIPHER_CTX_new();
    EVP_EncryptInit(ctx_symmencr, EVP_aes_128_ecb(), session_key1, NULL);
    EVP_EncryptUpdate(ctx_symmencr, ciphertext, &outlen, signature, sizeof(signature));
    cipherlen = outlen;
    EVP_EncryptFinal(ctx_symmencr, ciphertext + cipherlen, &outlen);
    cipherlen += outlen;
    EVP_CIPHER_CTX_free(ctx_symmencr);

    // Serialize the certificate
    file_cert_rsa = fopen(path_cert_rsa, 'r');
    if (file_cert_rsa == NULL)
    {
        printf("Impossible read certificate\n");
        exit(-1);
    }
    cert_rsa = PEM_read_X509(file_cert_rsa, NULL, NULL, NULL);
    cert_byte = cert_to_byte(cert_rsa, &cert_len);

    if (cipherlen > 1023 || pubkey_len > 1023 || cert_len > 1023)
    {
        printf("Too long\n");
        exit(-1);
    }
    msg_len = MAX_SIZE_USERNAME+strlen(" ")+cipherlen+strlen(" ")+pubkey_len+strlen(" ")+cert_len;
    buffer = (unsigned char*) malloc(sizeof(unsigned char)*msg_len);
 
    // Compose the message
    memcpy(buffer, username, MAX_SIZE_USERNAME);
    memcpy(&*(buffer+MAX_SIZE_USERNAME), " ", strlen(" "));
    memcpy(&*(buffer+MAX_SIZE_USERNAME+strlen(" ")), ciphertext, cipherlen);
    memcpy(&*(buffer+MAX_SIZE_USERNAME+strlen(" ")+cipherlen), " ", strlen(" "));
    memcpy(&*(buffer+MAX_SIZE_USERNAME+strlen(" ")+cipherlen+strlen(" ")), pubkey_byte, MAX_SIZE_PUBKEY);
    memcpy(&*(buffer+MAX_SIZE_USERNAME+strlen(" ")+cipherlen+strlen(" ")+MAX_SIZE_PUBKEY), " ", strlen(" "));
    memcpy(&*(buffer+MAX_SIZE_USERNAME+strlen(" ")+cipherlen+strlen(" ")+MAX_SIZE_PUBKEY+strlen(" ")), cert_byte, cert_len);

    printf("%s\n", buffer);
    printf("I'm sending to the client the mex %s\n\n", buffer);
    ret = send(sd, buffer, msg_len, 0); 
    if (ret == -1)
    {
        printf("Send operation gone bad\n");
        // Change this later to manage properly the session
        exit(1);
    }

    free(buffer);
    free(pubkey_byte);
    free(cert_byte);
    free(msg_to_sign);
    free(ciphertext);

    exit(1);





    /*
    // CHECK IF THE FILE EXISTS, otherwise send a message of error to the client

    ret = rename(bufferSupp3, bufferSupp4);
    if (ret == -1) 
    {
        printf("Something bad happened during the rename operation\n\n");
        exit(1);
    }
    memset(bufferSupp1, 0, strlen(bufferSupp1));
    memset(bufferSupp2, 0, strlen(bufferSupp2));
    memset(bufferSupp3, 0, strlen(bufferSupp3));
    memset(bufferSupp4, 0, strlen(bufferSupp4));
    sprintf(bufferSupp1, "%s", RENAME_ACCEPTED); //Format of the message sent is: type_mex
    ret = send(sd, bufferSupp1, strlen(bufferSupp1), 0);
    if (ret == -1)
    {
        printf("Send operation gone bad\n");
        // Change this later to manage properly the session
        exit(1);
    }
    return 1;
    */

   //free(); ... search for mallocs
}
