#include "util.h"

static char username_allowed_chars[] = {"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-"};

int username_sanitization(const char* username) {
    if(strspn(username, username_allowed_chars) < strlen(username)) return 0;
    return 1;
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
    exit(0);
}

size_t str_ssplit(unsigned char* a_str, const unsigned char a_delim)
{
    size_t count = 0;
    unsigned char* tmp = a_str;
    
    // Count how many elements there are before delim
    while (*tmp)
    {
        printf("%s\n", *tmp);
        if (a_delim == *tmp)
        {
            count++;
            break;
        }
        tmp++;
    }

    return count;
}

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

void decrypt_AES_128_CBC(unsigned char* out, unsigned int* out_len, unsigned char* in, unsigned char* iv, unsigned char* key)
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
    unsigned int digestlen;
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

unsigned char* sign_msg(char* path_key, char* password, unsigned char* msg_to_sign, unsigned int* signature_len)
{
    int ret;

    FILE* file_prvkey_pem = fopen(path_key, "r");
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
    ret = EVP_SignFinal(ctx_digsig, signature, signature_len, rsa_prvkey);
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

unsigned char* cert_to_byte(X509* cert, int* cert_len)
{
    BIO *bio = NULL;
    unsigned char *c = NULL;
    int c_len = 0;
    int ret;

    bio = BIO_new(BIO_s_mem());
    ret = PEM_write_bio_X509(bio, cert);
    if (ret != 1) exit_with_failure("PEM_write_bip_X509 failed", 1);

    c_len = BIO_pending(bio);
    *cert_len = c_len;

    c = (unsigned char *) malloc(sizeof(unsigned char) * c_len);

    BIO_read(bio, c, c_len);
    BIO_free(bio);

    return c;
}
