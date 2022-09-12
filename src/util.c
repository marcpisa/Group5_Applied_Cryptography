#include "util.h"

static char allowed_chars[] = {"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-"};
static char *const commands[] = {LOGIN, LOGOUT, LIST, RENAME, DELETE, DOWNLOAD, UPLOAD, SHARE, HELP, EXIT};

int username_sanitization(const char* username) {
    if(strspn(username, allowed_chars) < strlen(username)) return 0;
    return 1;
}

int input_sanitization_commands(const char* input) {

    int i;
    for (i = 0; i < COMM_NUMB; i++) {
        if (strncmp(commands[i], input, COM_LEN) == 0) return i + 1;
    }
    return 0;
}

void rec_buffer_sanitization(char *received_buff, char *buffer_sanitized[]) {
    int j, i;
    i = 0;
    char *token;
    token = strtok(received_buff, " ");
    while (token != NULL) {
        buffer_sanitized[i] = token;
        token = strtok(NULL, " ");
        i++;
    }

    //for(j = 1; j < i; j++) {
        
    //}

    //SANIFICATION: username it is checked in the if block server side.
}

int file_name_sanitization(const char* file_name, const char* root_dir) {

    char buf[BUF_LEN];

    if(strspn(file_name, allowed_chars) < strlen(file_name)) return 0;
    char *canon_file_name = realpath(file_name, buf);
    if(!canon_file_name) return 0;
    if(strncmp(canon_file_name, root_dir, strlen(root_dir)) != 0) return -1;
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
    while (*tmp != '\0')
    {
        if (a_delim == *tmp)
        {
            break;
        }
        count++;
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
    X509* crt = NULL;
    BIO* mbio = NULL;
    
    mbio = BIO_new(BIO_s_mem());
    if (!mbio) exit_with_failure("BIO_new failed", 1);
    BIO_write(mbio, cert, cert_len);

    crt = PEM_read_bio_X509(mbio, NULL, NULL, NULL);
    if (!crt) exit_with_failure("PEM_read_bio_X509 failed", 1);

    BIO_free(mbio);

    return crt;
}

EVP_PKEY* save_read_PUBKEY(char* path_pubkey, EVP_PKEY* my_prvkey)
{
    int ret;
    EVP_PKEY* dh_pubkey = NULL;
    FILE* file_pubkey_pem;
    
    file_pubkey_pem = fopen(path_pubkey, "w");
    if (!file_pubkey_pem) exit_with_failure("Fopen (save_read_PUBKEY) failed", 1);
    
    ret = PEM_write_PUBKEY(file_pubkey_pem, my_prvkey);
    fclose(file_pubkey_pem);
    if (ret != 1) exit_with_failure("PEM_write_PUBKEY failed", 1);
    
    // Retrieve the saved public key
    file_pubkey_pem = fopen(path_pubkey, "r");
    if (!file_pubkey_pem) exit_with_failure("Fopen failed", 1);
    dh_pubkey = PEM_read_PUBKEY(file_pubkey_pem, NULL, NULL, NULL);
    fclose(file_pubkey_pem);
    if (!dh_pubkey) exit_with_failure("PEM_read_PUBKEY failed", 1);

    return dh_pubkey;
}

void encrypt_AES_128_CBC(unsigned char** out, int* out_len, unsigned char* in, unsigned int inl, unsigned char* iv, unsigned char* key)
{
    int ret;
    EVP_CIPHER_CTX *ctx;

    ctx = EVP_CIPHER_CTX_new();
    if(!ctx) exit_with_failure("EVP_CIPHER_CTX_new failed", 1);

    ret = EVP_EncryptInit(ctx, EVP_aes_128_cbc(), key, iv);
    if (ret != 1) exit_with_failure("EncryptInit failed", 1);
    
    int update_len = 0; // bytes encrypted at each chunk
    int total_len = 0; // total encrypted bytes

    ret = EVP_EncryptUpdate(ctx, *out, &update_len, in, inl);
    if (ret != 1) exit_with_failure("EncryptUpdate failed", 1);
    total_len += update_len;

    ret = EVP_EncryptFinal(ctx, *out+total_len, &update_len);
    if (ret != 1) exit_with_failure("EncryptFinal failed", 1);
    total_len += update_len;
    
    *out_len = total_len;

    EVP_CIPHER_CTX_free(ctx);  
}

void decrypt_AES_128_CBC(unsigned char** out, unsigned int* out_len, unsigned char* in, unsigned int inl, unsigned char* iv, unsigned char* key)
{
    int ret;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx) exit_with_failure("EVP_CIPHER_CTX_new failed", 1);
    
    ret = EVP_DecryptInit(ctx, EVP_aes_128_cbc(), key, iv);
    if (ret != 1) exit_with_failure("DecryptInit failed", 1);

    int update_len = 0; // bytes decrypted at each chunk
    int total_len = 0; // total decrypted bytes
   
    ret = EVP_DecryptUpdate(ctx, *out, &update_len, in, inl);
    if (ret != 1) exit_with_failure("DecryptUpdate failed", 1);
    total_len += update_len;

    ret = EVP_DecryptFinal(ctx, *out+total_len, &update_len);
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

unsigned char* sign_msg(char* path_key, unsigned char* msg_to_sign, int msg_len, unsigned int* signature_len)
{
    int ret;
    EVP_PKEY* rsa_prvkey = NULL;
    EVP_MD_CTX* ctx = NULL;

    FILE* file_prvkey_pem = fopen(path_key, "r");
    if(!file_prvkey_pem) exit_with_failure("Fopen failed", 1);

    rsa_prvkey = PEM_read_PrivateKey(file_prvkey_pem, NULL, NULL, NULL);
    fclose(file_prvkey_pem);
    if (!rsa_prvkey) exit_with_failure("PEM_read_PrivateKey failed", 1);

    ctx = EVP_MD_CTX_new();
    if(!ctx) exit_with_failure("EVP_MD_CTX_new failed", 1);

    unsigned char* signature = (unsigned char*) malloc(sizeof(unsigned char)*EVP_PKEY_size(rsa_prvkey));

    ret = EVP_SignInit(ctx, EVP_sha256());
    if (ret != 1) exit_with_failure("SignInit failed", 1);
    ret = EVP_SignUpdate(ctx, msg_to_sign, msg_len);
    if (ret != 1) exit_with_failure("SignUpdate failed", 1);
    ret = EVP_SignFinal(ctx, signature, signature_len, rsa_prvkey);
    if (ret != 1) exit_with_failure("SignFinal failed", 1);

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(rsa_prvkey);

    return signature;
}

int verify_signature(unsigned char* exp_digsig, int len_exp_digsig, unsigned char* msg_to_ver, int len_msg_ver, EVP_PKEY* pub_rsa_key)
{
    int ret;
    EVP_MD_CTX* ctx;
    
    ctx = EVP_MD_CTX_new();
    if(!ctx) exit_with_failure("EVP_MD_CTX_new failed", 1);
    
    ret = EVP_VerifyInit(ctx, EVP_sha256());
    if (ret != 1) exit_with_failure("VerifyInit failed", 1);
    ret = EVP_VerifyUpdate(ctx, exp_digsig, len_exp_digsig);
    if (ret != 1) exit_with_failure("VerifyUpdate failed", 1);
    ret = EVP_VerifyFinal(ctx, msg_to_ver, len_msg_ver, pub_rsa_key);
    
    EVP_MD_CTX_free(ctx);
    
    if (ret != 1) return 0;
    return 1;
}

unsigned char* read_cert(char* path_cert, int* cert_len)
{
    FILE* file_cert = fopen(path_cert, "r");
    if(!file_cert) exit_with_failure("Fopen failed", 1);

    X509* server_cert = PEM_read_X509(file_cert, NULL, NULL, NULL);
    if(!server_cert) {
        fclose(file_cert);
        exit_with_failure("PEM_read_X509 failed", 1);
    }
    fclose(file_cert);

    // Write cert into bio
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio, server_cert);

    // Serialize the certificate
    unsigned char* cert_byte = NULL;
    *cert_len = BIO_get_mem_data(bio, &cert_byte);
    if((*cert_len) < 0) exit_with_failure("BIO_get_mem_data failed", 1);

    unsigned char* result = (unsigned char*) malloc((*cert_len)*sizeof(unsigned char));
    memcpy(result, cert_byte, *cert_len);

    // Free
    //free(cert_byte);
    X509_free(server_cert);
    BIO_free(bio);

    return result;

}

unsigned char* cert_to_byte(X509* cert, int* cert_len)
{
    BIO *bio = NULL;
    unsigned char *c = NULL;
    int c_len = 0;
    int ret;

    bio = BIO_new(BIO_s_mem());
    ret = PEM_write_bio_X509(bio, cert);
    if (ret != 1) exit_with_failure("PEM_write_bio_X509 failed", 1);

    c_len = BIO_pending(bio);
    *cert_len = c_len;

    c = (unsigned char *) malloc(sizeof(unsigned char) * c_len);

    BIO_read(bio, c, c_len);
    BIO_free(bio);

    return c;
}

unsigned char* key_derivation(EVP_PKEY* prvkey, EVP_PKEY* peer_pubkey, size_t* secretlen)
{
    int ret;
    unsigned char* K;

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(prvkey, NULL);
    if (!ctx) exit_with_failure("EVP_PKEY_CTX_new failed", 1);
    
    ret = EVP_PKEY_derive_init(ctx);
    if (ret != 1) exit_with_failure("PKEY_derive_init failed", 1);
    ret = EVP_PKEY_derive_set_peer(ctx, peer_pubkey);
    if (ret != 1) exit_with_failure("PKEY_derive_set_peer failed", 1);
    ret = EVP_PKEY_derive(ctx, NULL, secretlen);
    if (ret != 1) exit_with_failure("PKEY_derive failed", 1);

    // Deriving shared secret K = g^a^b mod p
    K = (unsigned char*)malloc(*secretlen); // 128 byte = 1024 bit
    if (!K) exit_with_failure("Malloc K failed", 1);

    ret = EVP_PKEY_derive(ctx, K, secretlen);
    if (ret != 1) exit_with_failure("PKEY_derive failed", 1);

    // Free
    EVP_PKEY_CTX_free(ctx);

    return K;
}

unsigned char* gen_dh_keys(char* path_pubkey, EVP_PKEY** my_prvkey, EVP_PKEY** dh_pubkey, int* pubkey_len)
{
    int ret;
    EVP_PKEY* dh_params;
    EVP_PKEY_CTX* ctx;
    unsigned char* pubkey_byte;

    dh_params = EVP_PKEY_new();
    ret = EVP_PKEY_set1_DH(dh_params, DH_get_1024_160());
    if (ret != 1) exit_with_failure("EVP_PKEY_set1_DH failed", 1);

    ctx = EVP_PKEY_CTX_new(dh_params, NULL);
    if(!ctx) exit_with_failure("EVP_PKEY_CTX_new failed", 1);

    ret = EVP_PKEY_keygen_init(ctx);
    if (ret != 1) exit_with_failure("keygen_init failed", 1);
    ret = EVP_PKEY_keygen(ctx, my_prvkey);
    if (ret != 1 || (!(*my_prvkey))) exit_with_failure("keygen failed", 1);

    // Save DH key in PEM format and retrieve the public key
    *dh_pubkey = save_read_PUBKEY(path_pubkey, *my_prvkey);

    //if (!dh_pubkey) exit_with_failure("save_read_PUBKEY failed", 0);
    pubkey_byte = pubkey_to_byte(*dh_pubkey, pubkey_len);
    if (!pubkey_byte) exit_with_failure("pubkey_to_byte failed", 0);

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(dh_params);

    return pubkey_byte;
}

EVP_PKEY* get_client_pubkey(char* path_cert_client_rsa)
{
    EVP_PKEY* pub_rsa_client;
    X509* client_cert;

    FILE* file_cert_rsa = fopen(path_cert_client_rsa, "r");
    if (!file_cert_rsa) exit_with_failure("Fopen failed", 1);
    client_cert = PEM_read_X509(file_cert_rsa, NULL, NULL, NULL);
    if (!client_cert) 
    {
        fclose(file_cert_rsa);
        exit_with_failure("PEM_read_X509 failed", 1);
    }
    fclose(file_cert_rsa);
    pub_rsa_client = X509_get_pubkey(client_cert);
    if (!pub_rsa_client) exit_with_failure("X509_get_pubkey failed", 1);

    X509_free(client_cert);

    return pub_rsa_client;
}

void issue_session_keys(unsigned char* K, int K_len, unsigned char** session_key1, unsigned char** session_key2)
{
    int ret;
    EVP_MD_CTX* ctx;
    unsigned char* digest = (unsigned char*) malloc(EVP_MD_size(EVP_sha256()));
    if (!digest) exit_with_failure("Malloc digest failed", 1);

    ctx = EVP_MD_CTX_new();
    if (!ctx) exit_with_failure("EVP_MD_CTX_new failed", 1);
    ret = EVP_DigestInit(ctx, EVP_sha256());
    if (ret != 1) exit_with_failure("DigestInit failed", 1);
    ret = EVP_DigestUpdate(ctx, K, K_len);
    if (ret != 1) exit_with_failure("DigestUpdate failed", 1);
    ret = EVP_DigestFinal(ctx, digest, NULL);
    if (ret != 1) exit_with_failure("DigestFinal failed", 1);

    EVP_MD_CTX_free(ctx);

    memcpy(*session_key1, digest, 16); // 16 byte = 128 bit
    memcpy(*session_key2, &*(digest+16), 16);
    
    free(digest);
}

EVP_PKEY* get_ver_server_pubkey(X509* serv_cert, X509_STORE* ca_store)
{
    int ret;
    X509_STORE_CTX* ctx;
    EVP_PKEY* pub_rsa_key_serv;

    pub_rsa_key_serv = X509_get_pubkey(serv_cert);
    
    ctx = X509_STORE_CTX_new();
    if (!ctx) exit_with_failure("X509_STORE_CTX_new failed", 1);
    ret = X509_STORE_CTX_init(ctx, ca_store, serv_cert, NULL);
    if (ret != 1) exit_with_failure("X509_STORE_CTX_init failed", 1);
    ret = X509_verify_cert(ctx);
    if (ret != 1) exit_with_failure("X509_verify_cert failed", 1);

    X509_STORE_CTX_free(ctx);

    return pub_rsa_key_serv;
}


unsigned char* hmac_sha256(unsigned char* key, int keylen, unsigned char* msg, int msg_len, unsigned int* out_len)
{
    HMAC_CTX* hmac_ctx;
    int ret;
    unsigned char* digest;

    digest = (unsigned char*) malloc(sizeof(unsigned char)*HASH_LEN);
    if (!digest) exit_with_failure("Malloc digest failed", 1);

    hmac_ctx = HMAC_CTX_new();
    if (!hmac_ctx) exit_with_failure("HMAC_CTX_new failed", 1);
    ret = HMAC_Init_ex(hmac_ctx, key, keylen, EVP_sha256(), NULL);
    if (ret != 1) exit_with_failure("HMAC_Init_ex failed", 1);
    ret = HMAC_Update(hmac_ctx, msg, msg_len);
    if (ret != 1) exit_with_failure("HMAC_Update failed", 1);
    ret = HMAC_Final(hmac_ctx, digest, out_len);
    if (ret != 1) exit_with_failure("HMAC_Final failed", 1);

    HMAC_CTX_free(hmac_ctx);

    return digest;
}

void operation_denied(int sock, char* reason, char* req_denied, unsigned char* key1, unsigned char* key2, int* nonce)
{
    int ret;

    int msg_len;
    unsigned int encr_len;
    unsigned char* ciphertext; 

    unsigned int msg_to_hash_len;
    unsigned int digest_len;
    unsigned char* msg_to_hash;
    unsigned char* digest;

    unsigned char* buffer;
    char* iv;
    char* temp;

    // Seed for the IV
    iv = (unsigned char*) malloc(sizeof(unsigned char)*IV_LEN);
    if (!iv) exit_with_failure("Malloc iv failed", 1);
    ret = RAND_poll(); // Seed OpenSSL PRNG
    if (ret != 1) exit_with_failure("RAND_poll failed\n", 0);
    ret = RAND_bytes((unsigned char*)&iv[0], IV_LEN);
    if (ret != 1) exit_with_failure("RAND_bytes failed\n", 0);

    // Increment nonce for new message
    *nonce = *nonce + 1;

    // Encrypt the reason
    encrypt_AES_128_CBC(&ciphertext, &encr_len, (unsigned char*) reason, strlen(reason), iv, key1);

    // Calculate the hash
    msg_to_hash_len = strlen(req_denied)+BLANK_SPACE+encr_len+BLANK_SPACE+IV_LEN+BLANK_SPACE+LEN_SIZE;
    msg_to_hash = (unsigned char*) malloc(msg_to_hash_len*sizeof(unsigned char));
    if (!msg_to_hash) exit_with_failure("Malloc msg_to_hash failed", 0);

    temp = (char*) malloc(LEN_SIZE*sizeof(char));
    if (!temp) exit_with_failure("Malloc temp failed", 0);

    sprintf(temp, "%d", *nonce);
    memcpy(msg_to_hash, req_denied, strlen(req_denied)); // denied req.
    memcpy(&*(msg_to_hash+strlen(req_denied)), " ", BLANK_SPACE);
    memcpy(&*(msg_to_hash+strlen(req_denied)+BLANK_SPACE), ciphertext, encr_len); // encr.  
    memcpy(&*(msg_to_hash+strlen(req_denied)+BLANK_SPACE+encr_len), " ", BLANK_SPACE);
    memcpy(&*(msg_to_hash+strlen(req_denied)+BLANK_SPACE+encr_len+BLANK_SPACE), iv, IV_LEN); // iv
    memcpy(&*(msg_to_hash+strlen(req_denied)+BLANK_SPACE+encr_len+BLANK_SPACE+IV_LEN), " ", BLANK_SPACE);
    memcpy(&*(msg_to_hash+strlen(req_denied)+BLANK_SPACE+encr_len+BLANK_SPACE+IV_LEN+BLANK_SPACE), \
    temp, LEN_SIZE); // nonce

    digest = hmac_sha256(key2, 16, msg_to_hash, msg_to_hash_len, &digest_len);   


    // Compose and send the message
    msg_len = strlen(req_denied)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE+encr_len+BLANK_SPACE+ \
    HASH_LEN+BLANK_SPACE+IV_LEN;
    buffer = (unsigned char*) malloc(msg_len*sizeof(unsigned char));
    if (!buffer) exit_with_failure("Malloc buffer failed", 0);

    memcpy(buffer, req_denied, strlen(req_denied)); // req. denied
    memcpy(&*(buffer+strlen(req_denied)), " ", BLANK_SPACE);
    sprintf(temp, "%d", encr_len);
    memcpy(&*(buffer+strlen(req_denied)+BLANK_SPACE), temp, LEN_SIZE); // len. encr.
    memcpy(&*(buffer+strlen(req_denied)+BLANK_SPACE+LEN_SIZE), " ", BLANK_SPACE);
    memcpy(&*(buffer+strlen(req_denied)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE), ciphertext, encr_len); // encr. reason
    memcpy(&*(buffer+strlen(req_denied)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE+encr_len), " ", BLANK_SPACE);
    memcpy(&*(buffer+strlen(req_denied)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE+encr_len+BLANK_SPACE), \
    digest, HASH_LEN); // hash
    memcpy(&*(buffer+strlen(req_denied)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE+encr_len+BLANK_SPACE+HASH_LEN), \
    " ", BLANK_SPACE);
    memcpy(&*(buffer+strlen(req_denied)+BLANK_SPACE+LEN_SIZE+BLANK_SPACE+encr_len+BLANK_SPACE+HASH_LEN+ \
    BLANK_SPACE), iv, IV_LEN); // iv
    
    ret = send(sock, buffer, msg_len, 0);
    if (ret == -1) exit_with_failure("Send failed", 0);

    free(iv);
    free(ciphertext);
    free(msg_to_hash);
    free(temp);
    free(digest);
    free(buffer);
}

void operation_succeed(int sock, char* req_accepted, unsigned char* key, int* nonce)
{
    int ret;
    int msg_len;

    unsigned int msg_to_hash_len;
    unsigned int digest_len;
    unsigned char* msg_to_hash;
    unsigned char* digest;

    unsigned char* buffer;
    char* iv;
    char* temp;

    // Seed for the IV
    iv = (unsigned char*) malloc(sizeof(unsigned char)*IV_LEN);
    if (!iv) exit_with_failure("Malloc iv failed", 1);
    ret = RAND_poll(); // Seed OpenSSL PRNG
    if (ret != 1) exit_with_failure("RAND_poll failed\n", 0);
    ret = RAND_bytes((unsigned char*)&iv[0], IV_LEN);
    if (ret != 1) exit_with_failure("RAND_bytes failed\n", 0);

    // Increment nonce for new message
    *nonce = *nonce + 1;

    msg_len = strlen(req_accepted)+BLANK_SPACE+HASH_LEN+BLANK_SPACE+IV_LEN;
    buffer = (unsigned char*) malloc(msg_len*sizeof(unsigned char));
    if (!buffer) exit_with_failure("Malloc buffer failed", 1);

    // Calculate the hash
    msg_to_hash_len = strlen(req_accepted)+BLANK_SPACE+IV_LEN+BLANK_SPACE+LEN_SIZE;
    msg_to_hash = (unsigned char*) malloc(msg_to_hash_len*sizeof(unsigned char));
    if (!msg_to_hash) exit_with_failure("Malloc msg_to_hash failed", 0);

    temp = (char*) malloc(LEN_SIZE*sizeof(char));
    if (!temp) exit_with_failure("Malloc temp failed", 0);

    sprintf(temp, "%d", *nonce);
    memcpy(msg_to_hash, req_accepted, strlen(req_accepted)); // req. acc.
    memcpy(&*(msg_to_hash+strlen(req_accepted)), " ", BLANK_SPACE);
    memcpy(&*(msg_to_hash+strlen(req_accepted)+BLANK_SPACE), iv, IV_LEN); // iv.  
    memcpy(&*(msg_to_hash+strlen(req_accepted)+BLANK_SPACE+IV_LEN), " ", BLANK_SPACE);
    memcpy(&*(msg_to_hash+strlen(req_accepted)+BLANK_SPACE+IV_LEN+BLANK_SPACE), temp, LEN_SIZE); // nonce

    digest = hmac_sha256(key, 16, msg_to_hash, msg_to_hash_len, &digest_len);

    // Compose the message
    memcpy(buffer, req_accepted, strlen(req_accepted)); // req. acc.
    memcpy(&*(buffer+strlen(req_accepted)), " ", BLANK_SPACE);
    memcpy(&*(buffer+strlen(req_accepted)+BLANK_SPACE), digest, HASH_LEN); // hash
    memcpy(&*(buffer+strlen(req_accepted)+BLANK_SPACE+HASH_LEN), " ", BLANK_SPACE);
    memcpy(&*(buffer+strlen(req_accepted)+BLANK_SPACE+HASH_LEN+BLANK_SPACE), iv, IV_LEN); // iv

    ret = send(sock, buffer, msg_len, 0);
    if (ret == -1) exit_with_failure("Send failed", 1);

    free(iv);
    free(buffer);
    free(msg_to_hash);
    free(digest);
}



int check_reqden_msg (unsigned char* req_denied, unsigned char* msg, int* nonce, unsigned char* session_key1, unsigned char* session_key2)
{
    unsigned char* bufferSupp1;
    unsigned char* bufferSupp2;
    unsigned char* bufferSupp3;

    unsigned char* msg_to_hash;
    unsigned int msg_to_hash_len;

    unsigned char* digest;
    unsigned int digest_len;

    unsigned char* plaintext;
    unsigned int plain_len;
    int encr_len;

    char* temp;
    char* reason;

    size_t offset;
    int ret;
    unsigned char* iv;


    // Allocate the dynamic arrays
    temp = (char*) malloc(LEN_SIZE*sizeof(char));
    if (!temp) exit_with_failure("Malloc temp failed", 1);
    bufferSupp2 = (unsigned char*) malloc(sizeof(unsigned char)*HASH_LEN);
    if (!bufferSupp2) exit_with_failure("Malloc bufferSupp2 failed", 1);
    iv = (unsigned char*) malloc(sizeof(unsigned char)*IV_LEN);
    if (!iv) exit_with_failure("Malloc iv failed", 1);


    // Parse the message
    offset = strlen(DELETE_DENIED)+BLANK_SPACE;
    memcpy(temp, &*(msg+offset), LEN_SIZE); // len. encr.
    offset += LEN_SIZE+BLANK_SPACE;
        
    encr_len = atoi(temp);
    bufferSupp3 = (unsigned char*) malloc(sizeof(unsigned char)*encr_len);
    if (!bufferSupp3) exit_with_failure("Malloc bufferSupp3 failed", 1);

    memcpy(bufferSupp3, &*(msg+offset), encr_len); // encr.
    offset += encr_len+BLANK_SPACE; 

    memcpy(bufferSupp2, &*(msg+offset), HASH_LEN); // hash
    offset += HASH_LEN+BLANK_SPACE;

    memcpy(iv, &*(msg+offset), IV_LEN); // iv

    // Check hash
    msg_to_hash_len = strlen(DELETE_DENIED)+BLANK_SPACE+encr_len+BLANK_SPACE+IV_LEN+BLANK_SPACE+LEN_SIZE; 
    msg_to_hash = (unsigned char*) malloc(msg_to_hash_len*sizeof(unsigned char));
    if (!msg_to_hash) exit_with_failure("Malloc msg_to_hash failed", 1);

    sprintf(temp, "%d", *nonce);
    memcpy(msg_to_hash, DELETE_DENIED, strlen(DELETE_DENIED));  // delete den
    memcpy(&*(msg_to_hash+strlen(DELETE_DENIED)), " ", BLANK_SPACE);
    memcpy(&*(msg_to_hash+strlen(DELETE_DENIED)+BLANK_SPACE), bufferSupp3, encr_len); // encr
    memcpy(&*(msg_to_hash+strlen(DELETE_DENIED)+BLANK_SPACE+encr_len), " ", BLANK_SPACE);
    memcpy(&*(msg_to_hash+strlen(DELETE_DENIED)+BLANK_SPACE+encr_len+BLANK_SPACE), iv, IV_LEN); // iv
    memcpy(&*(msg_to_hash+strlen(DELETE_DENIED)+BLANK_SPACE+encr_len+BLANK_SPACE+IV_LEN), " ", BLANK_SPACE);
    memcpy(&*(msg_to_hash+strlen(DELETE_DENIED)+BLANK_SPACE+encr_len+BLANK_SPACE+IV_LEN+BLANK_SPACE), \
    temp, LEN_SIZE); // nonce

    digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len);    
    if (digest_len != (unsigned int) HASH_LEN) exit_with_failure("Wrong digest len", 0);

    ret = CRYPTO_memcmp(digest, bufferSupp2, HASH_LEN);
    if (ret == -1)
    {
        printf("Wrong hash\n\n");
        ret = -1;
    }
    else
    {
        // Decrypt the reason (bufferSupp3)
        decrypt_AES_128_CBC(&plaintext, &plain_len, bufferSupp3, encr_len, iv, session_key1);
        reason = (char*) malloc(plain_len*sizeof(char));
        if (!reason) exit_with_failure("Malloc reason failed", 1);

        printf("The request has been denied: %s\n\n", reason);
            
        free(plaintext);
        free(reason);

        ret = 1;
    }

    free(digest);
    free(temp);
    free(iv);
    free(msg_to_hash);
    free(bufferSupp2);
    free(bufferSupp3); 

    return ret;
}

int check_reqacc_msg(unsigned char* req_accepted, unsigned char* msg, int* nonce, unsigned char* key)
{
    unsigned char* bufferSupp1;
    unsigned char* bufferSupp2;
    unsigned char* bufferSupp3;

    unsigned char* msg_to_hash;
    unsigned int msg_to_hash_len;

    unsigned char* digest;
    unsigned int digest_len;

    unsigned char* plaintext;
    unsigned int plain_len;
    int encr_len;

    char* temp;
    char* reason;
    unsigned char* buffer;
    unsigned int msg_len;

    size_t offset;
    int ret;
    unsigned char* iv;


    // Allocate the dynamic arrays
    temp = (char*) malloc(LEN_SIZE*sizeof(char));
    if (!temp) exit_with_failure("Malloc temp failed", 1);
    bufferSupp2 = (unsigned char*) malloc(sizeof(unsigned char)*HASH_LEN);
    if (!bufferSupp2) exit_with_failure("Malloc bufferSupp2 failed", 1);
    iv = (unsigned char*) malloc(sizeof(unsigned char)*IV_LEN);
    if (!iv) exit_with_failure("Malloc iv failed", 1);

        
    // Parse the message
    offset = strlen(req_accepted)+BLANK_SPACE;
    memcpy(bufferSupp2, &*(msg+offset), HASH_LEN); // hash
    offset += HASH_LEN+BLANK_SPACE;
    memcpy(iv, &*(msg+offset), IV_LEN); // iv    
        
    // Check hash
    msg_to_hash_len = strlen(req_accepted)+BLANK_SPACE+IV_LEN+BLANK_SPACE+LEN_SIZE; 
    msg_to_hash = (unsigned char*) malloc(msg_to_hash_len*sizeof(unsigned char));
    if (!msg_to_hash) exit_with_failure("Malloc msg_to_hash failed", 1);

    temp = (char*) malloc(sizeof(char)*LEN_SIZE);
    if (!temp) exit_with_failure("Malloc temp failed", 1);

    sprintf(temp, "%d", *nonce);
    memcpy(msg_to_hash, req_accepted, strlen(req_accepted));  // req acc
    memcpy(&*(msg_to_hash+strlen(req_accepted)), " ", BLANK_SPACE);
    memcpy(&*(msg_to_hash+strlen(req_accepted)+BLANK_SPACE), iv, IV_LEN); // iv
    memcpy(&*(msg_to_hash+strlen(req_accepted)+BLANK_SPACE+IV_LEN), " ", BLANK_SPACE);
    memcpy(&*(msg_to_hash+strlen(req_accepted)+BLANK_SPACE+IV_LEN+BLANK_SPACE), temp, LEN_SIZE); // nonce

    digest = hmac_sha256(key, 16, msg_to_hash, msg_to_hash_len, &digest_len);   

    ret = CRYPTO_memcmp(digest, bufferSupp2, HASH_LEN);
    if (ret == -1)
    {
        printf("Wrong hash\n\n");
        ret = -1;
    }
    else
    {
        printf("The request has been accepted!\n\n");
        ret = 1;
    }

    free(digest);
    free(temp);
    free(msg_to_hash);
    free(bufferSupp2);

    return ret;
}