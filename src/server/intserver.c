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

EVP_PKEY* save_read_PUBKEY(char* path_pubkey, EVP_PKEY* my_prvkey)
{
    FILE* file_pubkey_pem = fopen(path_pubkey, "w");
    if (file_pubkey_pem == NULL) 
    { 
        printf("Error writing to PEM file.\n");
        // Change this later to manage properly the session
        exit(1);
    } 
    
    int ret = PEM_write_PUBKEY(file_pubkey_pem, my_prvkey);
    fclose(file_pubkey_pem);
    if (ret != 1) {
        printf("Error on saving DH pubkey.\n");
        // Change this later to manage properly the session
        exit(1);
    }
    
    // Retrieve the saved public key
    file_pubkey_pem = fopen(path_pubkey, "r");
    if (file_pubkey_pem == NULL) 
    { 
        printf("Error reading PEM file.\n");
        // Change this later to manage properly the session
        exit(1);
    } 

    EVP_PKEY* dh_pubkey = PEM_read_PUBKEY(file_pubkey_pem, NULL, NULL, NULL);
    fclose(file_pubkey_pem);
    if (dh_pubkey == NULL) {
        printf("Error on reading DH pubkey from file.\n");
        // Change this later to manage properly the session
        exit(-1);
    }

    return dh_pubkey;
}

int verify_signature(unsigned char* exp_digsig, unsigned char* msg_to_ver, EVP_PKEY* pub_rsa_key)
{
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_VerifyInit(ctx, EVP_sha256());
    EVP_VerifyUpdate(ctx, exp_digsig, strlen(exp_digsig));
    int ret = EVP_VerifyFinal(ctx, msg_to_ver, strlen(msg_to_ver), pub_rsa_key);
    if (ret != 1) return 0;

    EVP_MD_CTX_free(ctx);
    return 1;
}

unsigned char* sign_msg(char* path_key, char* password, unsigned char* msg_to_sign, int* signature_len)
{
    FILE* file_prvkey_pem = fopen(path_key, 'r');
    if(file_prvkey_pem == NULL) exit_with_failure("Open failed: ", 1);

    EVP_PKEY* rsa_prvkey = PEM_read_PrivateKey(file_prvkey_pem, NULL, NULL, password);
    fclose(file_prvkey_pem);
    if (rsa_prvkey == NULL) exit_with_failure("PEM_read_PrivateKey failed: ", 1);

    EVP_MD_CTX* ctx_digsig = EVP_MD_CTX_new();
    unsigned char* signature = malloc(EVP_PKEY_size(rsa_prvkey));
    EVP_SignInit(ctx_digsig, EVP_sha256());
    EVP_SignUpdate(ctx_digsig, msg_to_sign, sizeof(msg_to_sign));
    EVP_SignFinal(ctx_digsig, signature, &signature_len, rsa_prvkey);
    EVP_MD_CTX_free(ctx_digsig);

    return signature;
}

void decrypt_AES_128_CBC(unsigned char* out, int* out_len, unsigned char* in, unsigned char* iv, unsigned char* key)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx) exit_with_failure("EVP_CIPHER_CTX_new failed: ", 1);
    int ret = EVP_DecryptInit(ctx, EVP_aes_128_cbc(), key, iv);
    if(ret != 1) exit_with_failure("DecryptInit failed: ", 1);

    int update_len = 0; // bytes decrypted at each chunk
    int total_len = 0; // total decrypted bytes
   
    // more than one call???
    ret = EVP_DecryptUpdate(ctx, out, &update_len, in, sizeof(in));
    if(ret != 1) exit_with_failure("DecryptUpdate failed: ", 1);
    total_len += update_len;
   
    ret = EVP_DecryptFinal(ctx, out + total_len, &update_len);
    if(ret != 1) exit_with_failure("DecryptFinal failed: ", 1);
    total_len += update_len;
    out_len = total_len;

    EVP_CIPHER_CTX_free(ctx);   
}

void encrypt_AES_128_CBC(unsigned char* out, int* out_len, unsigned char* in, unsigned char* iv, unsigned char* key)
{

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx) exit_with_failure("EVP_CIPHER_CTX_new failed: ", 1);
    int ret = EVP_EncryptInit(ctx, EVP_aes_128_cbc(), key, iv);
    if(ret != 1) exit_with_failure("EncryptInit failed: ", 1);
    
    int update_len = 0; // bytes encrypted at each chunk
    int total_len = 0; // total encrypted bytes

    // more than one call???
    ret = EVP_EncryptUpdate(ctx, out, &update_len, in, sizeof(in));
    if(ret != 1) exit_with_failure("EncryptUpdate failed: ", 1);
    total_len += update_len;

    ret = EVP_EncryptFinal(ctx, out + total_len, &update_len);
    if(ret != 1) exit_with_failure("EncryptFinal failed: ", 1);
    total_len += update_len;
    out_len = total_len;
    
    EVP_CIPHER_CTX_free(ctx);  
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
    const unsigned char delim = ' ';
    unsigned char* buffer;
    unsigned char* msg_to_sign;
    unsigned char bufferSupp1[BUF_LEN];
    unsigned char bufferSupp2[BUF_LEN];
    unsigned char bufferSupp3[BUF_LEN];
    unsigned char bufferSupp4[BUF_LEN];
    char* path_pubkey = "../dh_server_pubkey.pem";
    char* path_peer_pubkey = "../dh_peer1_pubkey.pem";
    char* path_cert_rsa = "../cert.pem";
    char* path_cert_client_rsa = "../cert_client.pem";
    char* path_rsa_key = "../key.pem";
    int ret;
    int msg_len;
    char username [MAX_SIZE_USERNAME];
    int offset, old_offset;

    // Certificate
    X509* cert_rsa;
    FILE* file_cert_rsa;
    unsigned char* cert_byte;
    int cert_len = 0;

    X509* client_cert;
    EVP_PKEY* pub_rsa_client;

    // Symmetric encryption
    unsigned char* ciphertext;
    unsigned char* iv;
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
    unsigned char* K_trunc;
    unsigned char* pubkey_byte;
    int pubkey_len = 0;
    unsigned char* peer_pubkey_byte;
    int peer_pubkey_len = 0;
    EVP_PKEY_CTX* ctx_drv;
    size_t secretlen;
    FILE* file_pubkey_pem;
    EVP_PKEY* dh_pubkey;

    // REMEMBER TO SANITIZE PROPERLY THE BUFFER (VERY IMPORTANT)

    // Generate DH asymmetric key(s)
    dh_params = EVP_PKEY_new();
    EVP_PKEY_set1_DH(dh_params, DH_get_1024_160());

    ctx = EVP_PKEY_CTX_new(dh_params, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_keygen(ctx, &my_prvkey);

    // Save DH key in PEM format and retrieve the public key
    dh_pubkey = save_read_PUBKEY(path_pubkey, my_prvkey);
    pubkey_byte = pubkey_to_byte(dh_pubkey, &pubkey_len);
    
    free(ctx);
    free(dh_params);
 




    /* ---- Parse the first message ---- */
    memset(bufferSupp1, 0, BUF_LEN);
    memset(bufferSupp2, 0, BUF_LEN);
    memset(bufferSupp3, 0, BUF_LEN);
    memset(bufferSupp4, 0, BUF_LEN);
    memcpy(bufferSupp1, &*(rec_mex+MAX_SIZE_REQUEST+strlen(" ")), \
    MAX_SIZE_USERNAME);
    memcpy(bufferSupp2, &*(rec_mex+MAX_SIZE_REQUEST+strlen(" ")+ \
    MAX_SIZE_USERNAME+strlen(" ")), DH_PUBKEY_SIZE);
    memcpy(bufferSupp3, &*(rec_mex+MAX_SIZE_REQUEST+strlen(" ")+ \
    MAX_SIZE_USERNAME+strlen(" ")+DH_PUBKEY_SIZE+strlen(" ")), IV_LEN);

    old_offset = MAX_SIZE_REQUEST+strlen(" ")+MAX_SIZE_USERNAME+strlen(" ") \
    +DH_PUBKEY_SIZE+strlen(" ")+IV_LEN;
    offset = str_ssplit(&*(rec_mex+old_offset), delim);
    memcpy(bufferSupp4, &*(rec_mex+old_offset), offset); // signature
    //old_offset = offset;

    //printf("%s\n%s\n%s\n", bufferSupp1, bufferSupp2, bufferSupp3);
    
    //SANITIZE AND CHECK THE CORRECTNESS OF BUFFERS' CONTENTS

    // Check username
    chdir(MAIN_FOLDER_SERVER);
    ret = chdir(bufferSupp1);
    if (ret == -1)
    {
        printf("Error: username doesn't exists...\n");
        exit(1);
    }
    memset(username, 0, MAX_SIZE_USERNAME);
    memcpy(username, bufferSupp1, BUF_LEN);

    // Retrieve the client pubkey
    file_cert_rsa = fopen(path_cert_client_rsa, 'r');
    client_cert = PEM_read_X509(file_cert_rsa, NULL, NULL, NULL);
    pub_rsa_client = X509_get_pubkey(client_cert);
    fclose(file_cert_rsa);

    peer_pubkey = pubkey_to_PKEY(bufferSupp2, DH_PUBKEY_SIZE);

    // Calculate K = g^a^b mod p 
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
    EVP_DigestUpdate(ctx_digest, K, sizeof(K));
    EVP_DigestFinal(ctx_digest, digest, &digestlen);
    EVP_MD_CTX_free(ctx_digest);

    memcpy(session_key1, digest, 16); // 16 byte = 128 bit
    memcpy(session_key2, &*(digest+16), 16);
    //printf("Digest:%s\nS1:%s\nS2:%s\n", digest, session_key1, session_key2);
    free(digest);

    // TEST ---- K from 1024 to 128 bit for symm. encr.
    K_trunc = (unsigned char*) malloc(sizeof(unsigned char) * 16); 
    memcpy(K_trunc, K, EVP_CIPHER_key_length(EVP_aes_128_cbc()));
    
    free(K);

    // Retrieve the IV
    iv = (unsigned char*)malloc(IV_LEN);
    memcpy(iv, bufferSupp3, IV_LEN);

    // Verify the digital signature (bufferSupp4)
    ret = verify_signature(bufferSupp3, bufferSupp4, pub_rsa_client);
    if (ret != 1) exit_with_failure("Signature verification failed.\n", 0);




    /* --- Send response (username, dig.sign, DH pubkey, cert) --- */
    pubkey_byte = pubkey_to_byte(dh_pubkey, &pubkey_len);
    if (pubkey_len != DH_PUBKEY_SIZE)
    {
        printf("ERROr with pubkey size.\n");
        exit(-1);
    }

    // Prepare the digital signature
    msg_len = DH_PUBKEY_SIZE+strlen(" ")+DH_PUBKEY_SIZE;
    msg_to_sign = (unsigned char*) malloc(sizeof(unsigned char)*msg_len);
    memcpy(msg_to_sign, buffer, DH_PUBKEY_SIZE); // peer pubkey is still inside bufferSupp2
    memcpy(&*(buffer+DH_PUBKEY_SIZE), " ", strlen(" "));
    memcpy(&*(buffer+DH_PUBKEY_SIZE+strlen(" ")), pubkey_byte, DH_PUBKEY_SIZE);
    
    signature = sign_msg(path_rsa_key, password, msg_to_sign, &signature_len);

    // Encrypt the signature
    ciphertext = (unsigned char*)malloc(sizeof(signature) + BLOCK_SIZE);
    encrypt_AES_128_CBC(ciphertext, &cipherlen, signature, iv, K_trunc);


    // Serialize the certificate
    file_cert_rsa = fopen(path_cert_rsa, 'r');
    if (file_cert_rsa == NULL) exit_with_failure("Fopen failed: ", 1);
    cert_rsa = PEM_read_X509(file_cert_rsa, NULL, NULL, NULL);
    cert_byte = cert_to_byte(cert_rsa, &cert_len);
    fclose(file_cert_rsa);

    if (cipherlen > 1023 || cert_len > 1023) exit_with_failure("Ciphertext or certificate too long", 0);
    msg_len = MAX_SIZE_USERNAME+strlen(" ")+cipherlen+strlen(" ")+DH_PUBKEY_SIZE+strlen(" ")+cert_len;
    buffer = (unsigned char*) malloc(sizeof(unsigned char)*msg_len);
 
    // Compose the message
    memcpy(buffer, username, MAX_SIZE_USERNAME);
    memcpy(&*(buffer+MAX_SIZE_USERNAME), " ", strlen(" "));
    memcpy(&*(buffer+MAX_SIZE_USERNAME+strlen(" ")), ciphertext, cipherlen);
    memcpy(&*(buffer+MAX_SIZE_USERNAME+strlen(" ")+cipherlen), " ", strlen(" "));
    memcpy(&*(buffer+MAX_SIZE_USERNAME+strlen(" ")+cipherlen+strlen(" ")), pubkey_byte, DH_PUBKEY_SIZE);
    memcpy(&*(buffer+MAX_SIZE_USERNAME+strlen(" ")+cipherlen+strlen(" ")+DH_PUBKEY_SIZE), " ", strlen(" "));
    memcpy(&*(buffer+MAX_SIZE_USERNAME+strlen(" ")+cipherlen+strlen(" ")+DH_PUBKEY_SIZE+strlen(" ")), cert_byte, cert_len);

    //printf("%s\n", buffer);
    printf("I'm sending to the client the mex %s\n\n", buffer);
    ret = send(sd, buffer, msg_len, 0); 
    if (ret == -1) exit_with_failure("Send failed: ", 1);

    free(buffer);
    free(pubkey_byte);
    free(cert_byte);
    free(ciphertext);
    free(signature);

    
    /* Parse the client message and verify the fields */
    buffer = (unsigned char*) malloc(sizeof(unsigned char)*2*BUF_LEN);
    ret = recv(sd, buffer, 2*BUF_LEN, 0);
    if (ret == -1) exit_with_failure("Receive failed: ", 1);

    memset(bufferSupp1, 0, BUF_LEN);
    memset(bufferSupp2, 0, BUF_LEN);
    memcpy(bufferSupp1, buffer, MAX_SIZE_USERNAME);

    old_offset = MAX_SIZE_USERNAME+strlen(" ");
    offset = str_ssplit(&*(buffer+old_offset), delim);
    memcpy(bufferSupp2, &*(buffer+old_offset), offset); // signature

    if (strcmp(username, bufferSupp1) != 0) exit_with_failure("Wrong username.\n", 0);

    // Decrypt and verify signature
    signature = malloc(EVP_PKEY_size(rsa_prvkey));
    decrypt_AES_128_CBC(signature, &signature_len, bufferSupp2, iv, K_trunc);

    ret = verify_signature(msg_to_sign, signature, pub_rsa_client);
    if (ret != 1) exit_with_failure("Signature verification failed.\n", 0);

    free(msg_to_sign);
    free(signature)
    free(buffer);

    return 1;
}
