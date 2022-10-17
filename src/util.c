#include "util.h"


static char allowed_chars[] = {"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_.-"};
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
    int i;
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

int filename_sanitization(const char* file_name) {

    if(strspn(file_name, allowed_chars) < strlen(file_name)) return 0;
    /*char *canon_file_name = realpath(file_name, buf);
    free(buf);
    if(!canon_file_name) return 0;
    if(strncmp(canon_file_name, root_dir, strlen(root_dir)) != 0) return -1;*/

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
    
    BIO_free_all(mbio);

    return pk;
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

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    *out = (unsigned char*) malloc((inl+BLOCK_SIZE)*sizeof(unsigned char));
    if (!(*out)) exit_with_failure("Malloc out failed", 0);    

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

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    *out = (unsigned char*) malloc(inl*sizeof(unsigned char));
    //printf("%d\n", inl);
    if (!(*out)) exit_with_failure("Malloc out failed", 0);    

    ret = EVP_DecryptInit(ctx, EVP_aes_128_cbc(), key, iv);
    if (ret != 1) exit_with_failure("DecryptInit failed", 1);

    int update_len = 0; // bytes decrypted at each chunk
    int total_len = 0; // total decrypted bytes
   
    ret = EVP_DecryptUpdate(ctx, *out, &update_len, in, inl);
    if (ret != 1) exit_with_failure("DecryptUpdate failed", 1);
    total_len += update_len;
    
    ret = EVP_DecryptFinal(ctx, *out+total_len, &update_len);
    if (ret != 1) 
    {
        ERR_print_errors_fp(stderr);
        exit(1); 
    }//exit_with_failure("DecryptFinal failed", 1);
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

unsigned char* sign_msg(char* path_key, unsigned char* msg_to_sign, int msg_len, unsigned int* signature_len, int server)
{
    int ret;
    EVP_PKEY* rsa_prvkey = NULL;
    EVP_MD_CTX* ctx = NULL;

    FILE* file_prvkey_pem = fopen(path_key, "r");
    if(!file_prvkey_pem) exit_with_failure("Fopen failed", 1);

    if (server) // The server knows its password 
    { 
        rsa_prvkey = PEM_read_PrivateKey(file_prvkey_pem, NULL, NULL, "password");
    } 
    else // The client should inserts the password to proves its identity
    {
        rsa_prvkey = PEM_read_PrivateKey(file_prvkey_pem, NULL, NULL, NULL);
    }
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

    unsigned char* result = (unsigned char*) malloc(((*cert_len)+1)*sizeof(unsigned char));
    memcpy(result, cert_byte, *cert_len);
    memcpy(result+(*cert_len), "\0", 1);

    // Free
    //free(cert_byte);
    X509_free(server_cert);
    BIO_free_all(bio);

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

int issue_session_keys(EVP_PKEY* prvkey, unsigned char* pk_buff, int pk_len, unsigned char** session_key1, unsigned char** session_key2)
{
    int ret;
    unsigned char* K;
    size_t K_len;
    EVP_PKEY* peer_pubkey;


    // Convert the peer pubkey buff in PKEY
    peer_pubkey = pubkey_to_PKEY(pk_buff, pk_len);

    // Create context
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(prvkey, NULL);
    if (!ctx) 
    {
        EVP_PKEY_free(peer_pubkey);
        printf("EVP_PKEY_CTX_new failed\n");
        return -1;
    }
    
    // Init the environment context
    ret = EVP_PKEY_derive_init(ctx);
    if (ret != 1)
    {
        EVP_PKEY_free(peer_pubkey);
        EVP_PKEY_CTX_free(ctx);
        printf("PKEY_derive_init failed\n");
        return -1;
    }
    ret = EVP_PKEY_derive_set_peer(ctx, peer_pubkey);
    if (ret != 1) 
    {
        EVP_PKEY_free(peer_pubkey);
        EVP_PKEY_CTX_free(ctx);
        printf("PKEY_derive_set_peer failed\n");
        return -1;
    }
    ret = EVP_PKEY_derive(ctx, NULL, &K_len);
    if (ret != 1) 
    {
        EVP_PKEY_free(peer_pubkey);
        EVP_PKEY_CTX_free(ctx);
        printf("PKEY_derive failed\n");
        return -1;
    }

    // Deriving shared secret K = g^a^b mod p
    K = (unsigned char*)malloc(K_len); // 128 byte = 1024 bit
    if (!K)
    {
        EVP_PKEY_free(peer_pubkey);
        EVP_PKEY_CTX_free(ctx);
        printf("Malloc K failed\n");
        return -1;
    }

    ret = EVP_PKEY_derive(ctx, K, &K_len);
    if (ret != 1)
    {
        EVP_PKEY_free(peer_pubkey);
        EVP_PKEY_CTX_free(ctx);
        free(K);
        printf("PKEY_derive failed\n");
        return -1;
    }

    // Free
    EVP_PKEY_free(peer_pubkey);
    EVP_PKEY_CTX_free(ctx);


    // When K is derived we can issue the session keys
    unsigned char* digest = (unsigned char*) malloc(EVP_MD_size(EVP_sha256()));
    if (!digest) 
    {
        free(K);
        printf("Malloc digest failed\n");
        return -1;
    }

    EVP_MD_CTX* ctx_md = EVP_MD_CTX_new();
    if (!ctx_md) 
    {
        free_n(2, K, digest);
        printf("EVP_MD_CTX_new failed\n");
        return -1;
    }

    ret = EVP_DigestInit(ctx_md, EVP_sha256());
    if (ret != 1)
    {
        free_n(2, K, digest);
        EVP_MD_CTX_free(ctx_md);
        printf("DigestInit failed\n");
        return -1;
    }
    ret = EVP_DigestUpdate(ctx_md, K, K_len);
    if (ret != 1) 
    {
        free_n(2, K, digest);
        EVP_MD_CTX_free(ctx_md);
        printf("DigestUpdate failed\n");
        return -1;
    }
    ret = EVP_DigestFinal(ctx_md, digest, NULL);
    if (ret != 1)
    {
        free_n(2, K, digest);
        EVP_MD_CTX_free(ctx_md);
        printf("DigestFinal failed\n");
        return -1;
    }

    // Free
    EVP_MD_CTX_free(ctx_md);

    *session_key1 = (unsigned char*) malloc(16*sizeof(unsigned char)); // 128 bit
    *session_key2 = (unsigned char*) malloc(16*sizeof(unsigned char)); // 128 bit
    if(!(*session_key1) || !(*session_key2)) 
    {
        free_n(2, K, digest);
        printf("Unable to allocate session keys\n");
        return -1;
    }

    memcpy(*session_key1, digest, 16); // 16 byte = 128 bit
    memcpy(*session_key2, &*(digest+16), 16);
    
    // Free
    free_n(2, K, digest);

    return 0;
}

unsigned char* gen_dh_keys(char* path_pubkey, EVP_PKEY** my_prvkey, int* pubkey_len)
{
    int ret;
    EVP_PKEY* dh_params;
    EVP_PKEY* dh_pubkey;
    EVP_PKEY_CTX* ctx;
    unsigned char* pubkey_byte;
    DH* params;

    dh_params = EVP_PKEY_new();
    params = DH_get_1024_160();
    ret = EVP_PKEY_set1_DH(dh_params, params);
    if (ret != 1) exit_with_failure("EVP_PKEY_set1_DH failed", 1);

    ctx = EVP_PKEY_CTX_new(dh_params, NULL);
    if(!ctx) exit_with_failure("EVP_PKEY_CTX_new failed", 1);

    ret = EVP_PKEY_keygen_init(ctx);
    if (ret != 1) exit_with_failure("keygen_init failed", 1);
    ret = EVP_PKEY_keygen(ctx, my_prvkey);
    if (ret != 1 || (!(*my_prvkey))) exit_with_failure("keygen failed", 1);

    // Save DH key in PEM format and retrieve the public key
    dh_pubkey = save_read_PUBKEY(path_pubkey, *my_prvkey);
    pubkey_byte = pubkey_to_byte(dh_pubkey, pubkey_len);
    if (!pubkey_byte) exit_with_failure("pubkey_to_byte failed", 0);

    EVP_PKEY_free(dh_pubkey);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(dh_params);
    DH_free(params);

    return pubkey_byte;
}

EVP_PKEY* get_client_pubkey(char* username)
{
    EVP_PKEY* pub_rsa_client;
    X509* client_cert;
    char path_cert_client_rsa[5+MAX_LEN_USERNAME+4+1];
    
    memset(path_cert_client_rsa, 0, 5+MAX_LEN_USERNAME+4+1);
    memcpy(path_cert_client_rsa, "\0", 1);
    strcat(path_cert_client_rsa, "cert_");
    strncat(path_cert_client_rsa, username, strlen(username));
    strcat(path_cert_client_rsa, ".pem");

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

EVP_PKEY* get_ver_server_pubkey(unsigned char* cert, int cert_len, X509_STORE* ca_store)
{
    int ret;
    X509_STORE_CTX* ctx;
    EVP_PKEY* pub_rsa_key_serv;
    X509* crt = NULL;
    BIO* mbio = NULL;
    
    // Obtain the X509 certificate
    mbio = BIO_new(BIO_s_mem());
    if (!mbio) exit_with_failure("BIO_new failed", 1);
    BIO_write(mbio, cert, cert_len);

    crt = PEM_read_bio_X509(mbio, NULL, NULL, NULL);
    if (!crt) exit_with_failure("PEM_read_bio_X509 failed", 1);

    // Extract and verify the rsa key
    pub_rsa_key_serv = X509_get_pubkey(crt);
    
    ctx = X509_STORE_CTX_new();
    if (!ctx) exit_with_failure("X509_STORE_CTX_new failed", 1);
    ret = X509_STORE_CTX_init(ctx, ca_store, crt, NULL);
    if (ret != 1) exit_with_failure("X509_STORE_CTX_init failed", 1);
    ret = X509_verify_cert(ctx);
    if (ret != 1) exit_with_failure("X509_verify_cert failed", 1);

    //BIO_free(mbio);
    X509_free(crt);
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

void operation_denied(int sock, char* reason, char* req_denied, unsigned char* key1, unsigned char* key2, unsigned int* nonce)
{
    int ret;

    int msg_len;
    int encr_len;
    unsigned char* ciphertext; 

    int msg_to_hash_len;
    unsigned int digest_len;
    unsigned char* msg_to_hash;
    unsigned char* digest;

    unsigned char* buffer;
    unsigned char* iv;
    char* temp;

    // Seed for the IV
    iv = (unsigned char*) malloc(sizeof(unsigned char)*IV_LEN);
    if (!iv) exit_with_failure("Malloc iv failed", 1);
    ret = RAND_poll(); // Seed OpenSSL PRNG
    if (ret != 1) exit_with_failure("RAND_poll failed\n", 0);
    ret = RAND_bytes((unsigned char*)&iv[0], IV_LEN);
    if (ret != 1) exit_with_failure("RAND_bytes failed\n", 0);

    // Encrypt the reason
    encrypt_AES_128_CBC(&ciphertext, &encr_len, (unsigned char*) reason, strlen(reason), iv, key1);

    // Calculate the hash
    temp = (char*) malloc(LEN_SIZE*sizeof(char));
    if (!temp) exit_with_failure("Malloc temp failed", 0);

    sprintf(temp, "%u", *nonce);
    msg_to_hash_len = build_msg_4(&msg_to_hash, req_denied, strlen(req_denied),\
                                                ciphertext, encr_len,\
                                                iv, IV_LEN,\
                                                temp, LEN_SIZE);
    if (msg_to_hash_len == -1) exit_with_failure("Something bad happened building the hash...", 0);

    digest = hmac_sha256(key2, 16, msg_to_hash, msg_to_hash_len, &digest_len);   

    // Compose and send the message
    sprintf(temp, "%d", encr_len);    
    msg_len = build_msg_5(&buffer, req_denied, strlen(req_denied),\
                                   temp, LEN_SIZE,\
                                   ciphertext, encr_len,\
                                   digest, HASH_LEN,\
                                   iv, IV_LEN);
    if (msg_len == -1) exit_with_failure("Something bad happened building the message...", 0);

    ret = send(sock, buffer, BUF_LEN, 0);
    
    free_6(iv, ciphertext, msg_to_hash, temp, digest, buffer);
    
    if (ret == -1) exit_with_failure("Send failed", 0);
    
    *nonce += 1;
}

void operation_succeed(int sock, char* req_accepted, unsigned char* key2, unsigned int* nonce)
{
    int ret;
    int msg_len;

    int msg_to_hash_len;
    unsigned int digest_len;
    unsigned char* msg_to_hash;
    unsigned char* digest;

    unsigned char* buffer;
    unsigned char* iv;
    char* temp;

    // Seed for the IV
    iv = (unsigned char*) malloc(sizeof(unsigned char)*IV_LEN);
    if (!iv) exit_with_failure("Malloc iv failed", 1);
    ret = RAND_poll(); // Seed OpenSSL PRNG
    if (ret != 1) exit_with_failure("RAND_poll failed\n", 0);
    ret = RAND_bytes((unsigned char*)&iv[0], IV_LEN);
    if (ret != 1) exit_with_failure("RAND_bytes failed\n", 0);

    // Calculate the hash
    temp = (char*) malloc(LEN_SIZE*sizeof(char));
    if (!temp) exit_with_failure("Malloc temp failed", 0);

    sprintf(temp, "%u", *nonce);
    msg_to_hash_len = build_msg_3(&msg_to_hash, req_accepted, strlen(req_accepted),\
                                                iv, IV_LEN,\
                                                temp, LEN_SIZE);
    if (msg_to_hash_len == -1) exit_with_failure("Something bad happened building the hash...", 0);

    digest = hmac_sha256(key2, 16, msg_to_hash, msg_to_hash_len, &digest_len);

    // Compose the message
    msg_len = build_msg_3(&buffer, req_accepted, strlen(req_accepted), \
                                   digest, HASH_LEN, \
                                   iv, IV_LEN);
    if (msg_len == -1) exit_with_failure("Something bad happened building the message...", 0); 

    ret = send(sock, buffer, BUF_LEN, 0);
    
    free_5(iv, buffer, msg_to_hash, digest, temp);

    if (ret == -1) exit_with_failure("Send failed", 1);
    
    *nonce += 1;
}



int check_reqden_msg (char* req_denied, unsigned char* msg, unsigned int nonce, unsigned char* session_key1, unsigned char* session_key2)
{
    unsigned char* bufferSupp2;
    unsigned char* bufferSupp3;

    unsigned char* msg_to_hash;
    int msg_to_hash_len;

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
    offset = strlen(req_denied)+BLANK_SPACE;
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
    sprintf(temp, "%u", nonce);
    msg_to_hash_len = build_msg_4(&msg_to_hash, req_denied, strlen(req_denied),\
                                                bufferSupp3, encr_len,\
                                                iv, IV_LEN,\
                                                temp, LEN_SIZE);
    if (msg_to_hash_len == -1) exit_with_failure("Something bad happened building the hash...", 0);

    digest = hmac_sha256(session_key2, 16, msg_to_hash, msg_to_hash_len, &digest_len);    

    ret = CRYPTO_memcmp(digest, bufferSupp2, HASH_LEN);
    if (ret != 0)
    {
        printf("Wrong hash\n");
        ret = -1;
    }
    else
    {
        // Decrypt the reason (bufferSupp3)
        decrypt_AES_128_CBC(&plaintext, &plain_len, bufferSupp3, encr_len, iv, session_key1);
        reason = (char*) malloc((plain_len+1)*sizeof(char));
        if (!reason) exit_with_failure("Malloc reason failed", 1);
        memcpy(reason, plaintext, plain_len);
        memcpy(&*(reason+plain_len), "\0", 1);

        printf("The request has been denied: %s\n", reason);
            
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

int check_reqacc_msg(char* req_accepted, unsigned char* msg, unsigned int nonce, unsigned char* key)
{
    unsigned char* bufferSupp2;

    unsigned char* msg_to_hash;
    int msg_to_hash_len;

    unsigned char* digest;
    unsigned int digest_len;

    char* temp;

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
    
    sprintf(temp, "%u", nonce);
    msg_to_hash_len = build_msg_3(&msg_to_hash, req_accepted, strlen(req_accepted),\
                                                iv, IV_LEN,\
                                                temp, LEN_SIZE);
    if (msg_to_hash_len == -1) exit_with_failure("Something bad happened building the hash...", 0);

    digest = hmac_sha256(key, 16, msg_to_hash, msg_to_hash_len, &digest_len);   

    ret = CRYPTO_memcmp(digest, bufferSupp2, HASH_LEN);
    if (ret != 0)
    {
        printf("Wrong hash\n");
        ret = -1;
    }
    else
    {
        printf("The request has been accepted!\n");
        ret = 1;
    }

    free(iv);
    free(digest);
    free(temp);
    free(msg_to_hash);
    free(bufferSupp2);

    return ret;
}

int build_msg_2(unsigned char** buffer, void* param1, unsigned int param1_len, void* param2, unsigned int param2_len)
{
    int buff_len;

    buff_len = param1_len+param2_len+BLANK_SPACE;
    *buffer = (unsigned char*) malloc(BUF_LEN*sizeof(unsigned char));
    if(!(*buffer))
    {
        printf("Malloc buffer failed.\n");
        return -1;
    }

    memcpy(*buffer, param1, param1_len);
    memcpy(&*(*buffer+param1_len), " ", BLANK_SPACE);
    memcpy(&*(*buffer+param1_len+BLANK_SPACE), param2, param2_len);

    return buff_len;
}

int build_msg_3(unsigned char** buffer, void* param1, unsigned int param1_len, void* param2, unsigned int param2_len, void* param3, unsigned int param3_len)
{
    int buff_len;

    buff_len = param1_len+param2_len+param3_len+(BLANK_SPACE*2);
    *buffer = (unsigned char*) malloc(BUF_LEN*sizeof(unsigned char));
    if(!(*buffer))
    {
        printf("Malloc buffer failed.\n");
        return -1;
    }

    memcpy(*buffer, param1, param1_len);
    memcpy(&*(*buffer+param1_len), " ", BLANK_SPACE);
    memcpy(&*(*buffer+param1_len+BLANK_SPACE), param2, param2_len);
    memcpy(&*(*buffer+param1_len+BLANK_SPACE+param2_len), " ", BLANK_SPACE);
    memcpy(&*(*buffer+param1_len+BLANK_SPACE+param2_len+BLANK_SPACE), param3, param3_len);

    return buff_len;
}

int build_msg_4(unsigned char** buffer, void* param1, unsigned int param1_len, void* param2, unsigned int param2_len, void* param3, unsigned int param3_len, void* param4, unsigned int param4_len)
{
    int buff_len;

    buff_len = param1_len+param2_len+param3_len+param4_len+(BLANK_SPACE*3);
    *buffer = (unsigned char*) malloc(BUF_LEN*sizeof(unsigned char));
    if(!(*buffer))
    {
        printf("Malloc buffer failed.\n");
        return -1;
    }

    memcpy(*buffer, param1, param1_len);
    memcpy(&*(*buffer+param1_len), " ", BLANK_SPACE);
    memcpy(&*(*buffer+param1_len+BLANK_SPACE), param2, param2_len);
    memcpy(&*(*buffer+param1_len+BLANK_SPACE+param2_len), " ", BLANK_SPACE);
    memcpy(&*(*buffer+param1_len+BLANK_SPACE+param2_len+BLANK_SPACE), param3, param3_len);
    memcpy(&*(*buffer+param1_len+BLANK_SPACE+param2_len+BLANK_SPACE+param3_len), " ", BLANK_SPACE);
    memcpy(&*(*buffer+param1_len+BLANK_SPACE+param2_len+BLANK_SPACE+param3_len+BLANK_SPACE), param4, param4_len);

    return buff_len;
}

int build_msg_5(unsigned char** buffer, void* param1, unsigned int param1_len, void* param2, unsigned int param2_len, void* param3, unsigned int param3_len, void* param4, unsigned int param4_len, void* param5, unsigned int param5_len)
{
    int buff_len;

    buff_len = param1_len+param2_len+param3_len+param4_len+param5_len+(BLANK_SPACE*4);
    *buffer = (unsigned char*) malloc(BUF_LEN*sizeof(unsigned char));
    if(!(*buffer))
    {
        printf("Malloc buffer failed.\n");
        return -1;
    }

    memcpy(*buffer, param1, param1_len);
    memcpy(&*(*buffer+param1_len), " ", BLANK_SPACE);
    memcpy(&*(*buffer+param1_len+BLANK_SPACE), param2, param2_len);
    memcpy(&*(*buffer+param1_len+BLANK_SPACE+param2_len), " ", BLANK_SPACE);
    memcpy(&*(*buffer+param1_len+BLANK_SPACE+param2_len+BLANK_SPACE), param3, param3_len);
    memcpy(&*(*buffer+param1_len+BLANK_SPACE+param2_len+BLANK_SPACE+param3_len), " ", BLANK_SPACE);
    memcpy(&*(*buffer+param1_len+BLANK_SPACE+param2_len+BLANK_SPACE+param3_len+BLANK_SPACE), param4, param4_len);
    memcpy(&*(*buffer+param1_len+BLANK_SPACE+param2_len+BLANK_SPACE+param3_len+BLANK_SPACE+param4_len), " ", BLANK_SPACE);
    memcpy(&*(*buffer+param1_len+BLANK_SPACE+param2_len+BLANK_SPACE+param3_len+BLANK_SPACE+param4_len+BLANK_SPACE), param5, param5_len);

    return buff_len;
}

int build_msg_6(unsigned char** buffer, void* param1, unsigned int param1_len, void* param2, unsigned int param2_len, void* param3, unsigned int param3_len, void* param4, unsigned int param4_len, void* param5, unsigned int param5_len, void* param6, unsigned int param6_len)
{
    int buff_len;

    buff_len = param1_len+param2_len+param3_len+param4_len+param5_len+param6_len+(BLANK_SPACE*5);
    *buffer = (unsigned char*) malloc(BUF_LEN*sizeof(unsigned char));
    if(!(*buffer))
    {
        printf("Malloc buffer failed.\n");
        return -1;
    }

    memcpy(*buffer, param1, param1_len);
    memcpy(&*(*buffer+param1_len), " ", BLANK_SPACE);
    memcpy(&*(*buffer+param1_len+BLANK_SPACE), param2, param2_len);
    memcpy(&*(*buffer+param1_len+BLANK_SPACE+param2_len), " ", BLANK_SPACE);
    memcpy(&*(*buffer+param1_len+BLANK_SPACE+param2_len+BLANK_SPACE), param3, param3_len);
    memcpy(&*(*buffer+param1_len+BLANK_SPACE+param2_len+BLANK_SPACE+param3_len), " ", BLANK_SPACE);
    memcpy(&*(*buffer+param1_len+BLANK_SPACE+param2_len+BLANK_SPACE+param3_len+BLANK_SPACE), param4, param4_len);
    memcpy(&*(*buffer+param1_len+BLANK_SPACE+param2_len+BLANK_SPACE+param3_len+BLANK_SPACE+param4_len), " ", BLANK_SPACE);
    memcpy(&*(*buffer+param1_len+BLANK_SPACE+param2_len+BLANK_SPACE+param3_len+BLANK_SPACE+param4_len+BLANK_SPACE), param5, param5_len);
    memcpy(&*(*buffer+param1_len+BLANK_SPACE+param2_len+BLANK_SPACE+param3_len+BLANK_SPACE+param4_len+BLANK_SPACE+param5_len), " ", BLANK_SPACE);
    memcpy(&*(*buffer+param1_len+BLANK_SPACE+param2_len+BLANK_SPACE+param3_len+BLANK_SPACE+param4_len+BLANK_SPACE+param5_len+BLANK_SPACE), param6, param6_len);
    
    return buff_len;
}

/* The format of the message is:
 *  Type | Len. payload | Payload | Hash | IV
 * 
 * where the Len and Payload fields can be NULL, wheras the others are always not NULL.
 * 
 * This functions takes as argument a buffer in which store the msg, and all the
 * message fields with the corresponding length.
 * 
 * It returns the buffer length or -1 in case of some errors.
 */
int build_msg(unsigned char** buffer, char* type, unsigned int len_payload, unsigned char* payload, unsigned char* hash, unsigned char* iv)
{
    int buff_len;
    char n_buff[LEN_SIZE];
    unsigned char* p;

    if (len_payload == 0)
        buff_len = strlen(type)+HASH_LEN+IV_LEN+(BLANK_SPACE*2);
    else
        buff_len = strlen(type)+LEN_SIZE+len_payload+HASH_LEN+IV_LEN+(BLANK_SPACE*4);

    *buffer = (unsigned char*) malloc(buff_len*sizeof(unsigned char));
    if(!(*buffer))
    {
        printf("Malloc buffer failed.\n");
        return -1;
    }

    p = *buffer;
    memcpy(p, type, strlen(type));
    p += strlen(type);
    memcpy(p, " ", BLANK_SPACE);
    p += BLANK_SPACE;

    if (len_payload != 0) 
    {
        memset(n_buff, 0, LEN_SIZE);
        sprintf(n_buff, "%d", len_payload); // len payload
        memcpy(p, n_buff, LEN_SIZE);
        p += LEN_SIZE;
        memcpy(p, " ", BLANK_SPACE);
        p += BLANK_SPACE;
        memcpy(p, payload, len_payload); // payload
        p += len_payload;
        memcpy(p, " ", BLANK_SPACE);
        p += BLANK_SPACE;
    }

    memcpy(p, hash, HASH_LEN);
    p += HASH_LEN;
    memcpy(p, " ", BLANK_SPACE);
    p += BLANK_SPACE;
    memcpy(p, iv, IV_LEN);
    
    return buff_len;
}

/* The format of the message is:
 *  Type | Len. payload | Payload | Hash | IV
 * 
 * where the Len and Payload fields can be 0/NULL, wheras the others are always not NULL.
 * 
 * If len_payload is 0 the payload and its length are not parsed.
 * 
 * This functions takes as argument a buffer in which the msg is stored, and all the
 * buffer where the message fields will be saved to. 
 * 
 * Return -1 in case of errors, 0 otherwise
 */
int parse_msg(unsigned char* rec_msg, unsigned int len_msg, char* type, unsigned int* len_payload, unsigned char** payload, unsigned char* hash, unsigned char* iv)
{
    unsigned char* p;
    char len[LEN_SIZE];

    p = rec_msg;
    if(type != NULL) memcpy(type, p, TYPE_LEN);
    p += TYPE_LEN+BLANK_SPACE;

    if ((*len_payload) != 0)
    {
        memcpy(len, p, LEN_SIZE);
        p += LEN_SIZE+BLANK_SPACE;
        (*len_payload) = atoi(len);

        if ((*len_payload) > (len_msg-TYPE_LEN-LEN_SIZE-HASH_LEN-IV_LEN))
        {
            printf("Wrong payload len.\n");
            return -1;
        }

        *payload = (unsigned char*) malloc(((*len_payload)+1)*sizeof(unsigned char));
        if (!(*payload))
        {
            printf("Malloc payload failed.\n");
            return -1;
        }
        memcpy(*payload, p, *len_payload);
        p += (*len_payload)+BLANK_SPACE;
        memcpy((*payload)+(*len_payload), "\0", 1);
    }

    if(hash != NULL) memcpy(hash, p, HASH_LEN);
    p += HASH_LEN+BLANK_SPACE;

    if(iv != NULL) memcpy(iv, p, IV_LEN);

    return 0;
}

int concat_5(unsigned char** buffer, void* param1, unsigned int param1_len, void* param2, unsigned int param2_len, void* param3, unsigned int param3_len, void* param4, unsigned int param4_len, void* param5, unsigned int param5_len)
{
    int buff_len = 0;
    unsigned char* temp_buff;
    unsigned char* p;

    temp_buff = (unsigned char*) malloc(BUF_LEN*sizeof(unsigned char));
    if (!temp_buff) 
    {
        printf("Malloc temp_buff failed.\n");
        return -1;
    } 
    p = temp_buff;

    if (param1 != NULL)
    {
        memcpy(p, param1, param1_len);
        buff_len += param1_len;
        p += param1_len;
    }
    if (param2 != NULL)
    {
        memcpy(p, " ", BLANK_SPACE);
        p += BLANK_SPACE;
        memcpy(p, param2, param2_len);
        p += param2_len;
        buff_len += BLANK_SPACE+param2_len;
    }
    if (param3 != NULL)
    {
        memcpy(p, " ", BLANK_SPACE);
        p += BLANK_SPACE;
        memcpy(p, param3, param3_len);
        p += param3_len;
        buff_len += BLANK_SPACE+param3_len;
    }
    if (param4 != NULL)
    {
        memcpy(p, " ", BLANK_SPACE);
        p += BLANK_SPACE;
        memcpy(p, param4, param4_len);
        p += param4_len;
        buff_len += BLANK_SPACE+param4_len;
    }
    if (param5 != NULL)
    {
        memcpy(p, " ", BLANK_SPACE);
        p += BLANK_SPACE;
        memcpy(p, param5, param5_len);
        p += param5_len;
        buff_len += BLANK_SPACE+param5_len;
    }
    
    *buffer = (unsigned char*) malloc((buff_len+1)*sizeof(unsigned char));
    if (!(*buffer))
    {
        printf("Malloc buffer failed.\n");
        return -1;
    }
    memcpy(*buffer, temp_buff, buff_len);
    memcpy((*buffer)+buff_len, "\0", 1);
    free(temp_buff);

    return buff_len;
}

/* This functions takes n arguments (unsigned char*) and freed them */
void free_n(int n,...)
{
    va_list ap;
    unsigned char* f;

    va_start(ap, n);
    for (int i = 0; i < n; i++)
    {
        f = va_arg(ap, unsigned char*);
        free(f);
    }
    va_end(ap);
}

/* This functions takes n arguments (unsigned char*) and calls n times 
 * chdir on these strings 
 * 
 * Return -1 in case of errors, 0 otherwise
 * */
int chdir_n(int n, ...)
{
    va_list ap;
    char* d;

    va_start(ap, n);
    for(int i = 0; i < n; i++)
    {
        d = va_arg(ap, char*);
        if(chdir(d) == -1)
        {
            printf("Problem moving to %s.\n", d);
            return -1;
        }
    }
    va_end(ap);

    return 0;
}

void print_debug(unsigned char* buff, unsigned int len) 
{
    if (DEBUG == 1)
    {
        printf(GRN"***----------------------------------------------------***\n");
        for(unsigned int i = 0; i < len; i++) printf("%c", *(buff+i));
        printf("***----------------------------------------------------***\n\n"RESET);
    }
}




void free_2(void* param1, void* param2)
{
    free(param1);
    free(param2);
}

void free_3(void* param1, void* param2, void* param3)
{
    free(param1);
    free(param2);
    free(param3);
}

void free_4(void* param1, void* param2, void* param3, void* param4)
{
    free(param1);
    free(param2);
    free(param3);
    free(param4);
}

void free_5(void* param1, void* param2, void* param3, void* param4, void* param5)
{
    free(param1);
    free(param2);
    free(param3);
    free(param4);
    free(param5);
}

void free_6(void* param1, void* param2, void* param3, void* param4, void* param5, void* param6)
{
    free(param1);
    free(param2);
    free(param3);
    free(param4);
    free(param5);
    free(param6);
}




int build_file_list(DIR* d, unsigned int* tot_num_file, unsigned char* buffer)
{
    struct dirent *files;
    unsigned int len_filename, offset = 0, n_file = 0;

    // If this is the second list of filenames, reset the pointer to the prev. position
    for (int i = 0; i < *tot_num_file; i++) files = readdir(d);

    while((files = readdir(d)) != NULL)
    {
        len_filename = strlen(files->d_name);
        // The filename fits the list length
        if ((offset+len_filename+BLANK_SPACE) <= CHUNK_SIZE)
        { 
            memcpy(buffer+offset, files->d_name, len_filename);
            offset += len_filename;
            memcpy(buffer+offset, " ", BLANK_SPACE);
            offset += BLANK_SPACE;
            n_file += 1;
        }
    }

    if (offset == 0)
    {
        memcpy(buffer, "empty", strlen("empty"));
        offset += strlen("empty");
    }
    memcpy(buffer+offset, "\0", 1);

    *tot_num_file += n_file;
    return n_file;
}




int rcv_port(int sd, unsigned char* session_key1, unsigned char* session_key2, char* username)
{
    unsigned char* buffer, *h_buff, *iv_buff, *payload, *digest;
    char* path_temp;
    unsigned int len;
    int ret, msg_len, port_client;
    FILE* fd;
    char p_buff[PORT_SIZE];

    buffer = (unsigned char*) malloc(BUF_LEN*sizeof(unsigned char));
    if (!buffer) 
    {
       printf("Malloc buffer failed.\n");
       return -1; 
    } 

    ret = recv(sd, buffer, BUF_LEN, 0);
    if (ret == -1)
    {
        free(buffer);
        printf("Receive failed...\n");
        return -1;
    }
    else printf("#4 Port received by the client.\n");


    // Parse the message
    h_buff = (unsigned char*) malloc(HASH_LEN*sizeof(unsigned char));
    if (!h_buff) exit_with_failure("Malloc h_buff failed", 1);
    iv_buff = (unsigned char*) malloc(IV_LEN*sizeof(unsigned char));
    if (!iv_buff) exit_with_failure("Malloc iv_buff failed", 1);
    len = 1;
    
    ret = parse_msg(buffer, (unsigned int)ret, NULL, &len, &payload, h_buff, iv_buff);
    
    free(buffer);
    if (ret == -1)
    {
        free_n(2, h_buff, iv_buff);
        return -1;
    }


    // Check the hash
    msg_len = concat_5(&buffer, payload, len,\
                                iv_buff, IV_LEN, NULL, 0, NULL, 0, NULL, 0);
    if (msg_len == -1)
    {
        free_n(3, h_buff, iv_buff, payload);
        return -1;
    }

    digest = hmac_sha256(session_key2, 16, buffer, msg_len, NULL); 
    ret = CRYPTO_memcmp(digest, h_buff, HASH_LEN);
    
    free_n(3, h_buff, digest, buffer);
    if (ret != 0)
    {
        free_n(2, iv_buff, payload);
        printf("Checking hash failed.\n");
        return -1;
    }


    // Decrypt the message and save the port
    decrypt_AES_128_CBC(&buffer, &len, payload, len, iv_buff, session_key1); 
    port_client = atoi((char*) buffer);
    free_n(3, iv_buff, buffer, payload);


    // Serialize session_key1, session_key2 and port
    ret = chdir_n(2, "..", "info");
    if (ret == -1) return -1;

    path_temp = (char*) malloc((strlen(username)+4+1)*sizeof(char));
    if (!path_temp)
    {
        printf("Malloc path_temp failed.\n");
        return -1;
    }
    memcpy(path_temp, "\0", 1);
    strncat(path_temp, username, strlen(username));
    strcat(path_temp, ".txt\0");

    fd = fopen(path_temp, "w");
    if (!fd)
    {
        printf("Can't open path_temp...\n");
        free(path_temp);
        return -1;
    }

    // Write port, session_key1 and session_key2 to file
    memset(p_buff, 0, PORT_SIZE);
    sprintf(p_buff, "%d", port_client);
    ret = fwrite(p_buff, sizeof(char), PORT_SIZE, fd);
    if (ret == -1) 
    {
        printf("Fwrite failed.\n");
        free(path_temp);
        return -1;
    }
    ret = fwrite(session_key1, sizeof(unsigned char), 16, fd);
    if (ret == -1) 
    {
        printf("Fwrite failed.\n");
        free(path_temp);
        return -1;
    }
    ret = fwrite(session_key2, sizeof(unsigned char), 16, fd);
    if (ret == -1) 
    {
        printf("Fwrite failed.\n");
        free(path_temp);
        return -1; 
    }

    free(path_temp);
    fclose(fd);

    // Going back to the main directory
    ret = chdir_n(2, "..", username);
    if (ret == -1) return -1; 

    return 0;
}