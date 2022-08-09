#include "intserver.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <sys/sendfile.h>
#include <openssl/x509.h>

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
    char* path_cert_rsa = "../cert.pem";
    char* path_cert_client_rsa = "../cert_client.pem";
    char* path_rsa_key = "../key.pem";
    int ret;
    int msg_len;
    char username [MAX_LEN_USERNAME];
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
    int cipherlen;

    // Hashing
    unsigned char* digest;
    unsigned int digestlen;
    EVP_MD_CTX* ctx_digest;

    // Digital Signature variables
    unsigned char* signature;
    unsigned int signature_len;
    char* password = "password";

    // Diffie-Hellman variables
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
    /*********************
     * END VARIABLES
     ********************/
    
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




    /* ---- Parse the first message ---- */
    printf("Parsing first message.\n");
    memset(bufferSupp1, 0, BUF_LEN);
    memset(bufferSupp2, 0, BUF_LEN);
    memset(bufferSupp3, 0, BUF_LEN);
    memset(bufferSupp4, 0, BUF_LEN);

    offset = str_ssplit(&*((unsigned char*) rec_mex+MAX_LEN_REQUEST+strlen(" ")), delim);
    memcpy(bufferSupp1, &*(rec_mex+MAX_LEN_REQUEST+strlen(" ")), MAX_LEN_USERNAME); // username
    printf("Offset1:%d\n",offset);
    old_offset = offset;

    offset = str_ssplit(&*((unsigned char*) rec_mex+offset), delim);
    memcpy(bufferSupp2, &*(rec_mex+old_offset), offset); // dh pubkey
    printf("Offset2:%d\n",offset);
    old_offset = offset;

    offset = str_ssplit(&*((unsigned char*) rec_mex+offset), delim);
    memcpy(bufferSupp3, &*(rec_mex+old_offset), offset); // iv
    printf("Offset3:%d\n",offset);
    old_offset = offset;

    offset = str_ssplit(&*((unsigned char*) rec_mex+offset), delim);
    memcpy(bufferSupp4, &*(rec_mex+old_offset), offset); // signature
    printf("Offset4:%d\n",offset);

    //printf("Received mex:\n%s\n%s\n%s\n%s\n", bufferSupp1, bufferSupp2, bufferSupp3, bufferSupp4);
    
    // Sanitize and check username
    if (!username_sanitization((char*) bufferSupp1)) exit_with_failure("Username sanitization fails.\n", 0);
    chdir(MAIN_FOLDER_SERVER);
    ret = chdir((char*) bufferSupp1);
    if (ret == -1) exit_with_failure("Error: username doesn't exists...\n", 0);
  
    memset(username, 0, MAX_LEN_USERNAME);
    memcpy(username, bufferSupp1, BUF_LEN);

    // Retrieve the client pubkey
    file_cert_rsa = fopen(path_cert_client_rsa, "r");
    client_cert = PEM_read_X509(file_cert_rsa, NULL, NULL, NULL);
    pub_rsa_client = X509_get_pubkey(client_cert);
    fclose(file_cert_rsa);

    peer_pubkey = pubkey_to_PKEY(bufferSupp2, pubkey_len);

    printf("Debug1\n");

    // Calculate K = g^a^b mod p 
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

    printf("Debug2\n");

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

    printf("Debug3\n");

    // Retrieve the IV
    iv = (unsigned char*)malloc(IV_LEN);
    if (iv == NULL) exit_with_failure("Malloc iv failed", 1);
    memcpy(iv, bufferSupp3, IV_LEN);

    // Verify the digital signature (bufferSupp4)
    ret = verify_signature(bufferSupp3, bufferSupp4, pub_rsa_client);
    if (ret != 1) exit_with_failure("Signature verification failed.\n", 0);




    /* --- Send response (username, dig.sign, DH pubkey, cert) --- */
    printf("Issuing the response.\n");
    pubkey_byte = pubkey_to_byte(dh_pubkey, &pubkey_len);

    // Prepare the digital signature
    msg_len = pubkey_len+strlen(" ")+pubkey_len;
    msg_to_sign = (unsigned char*) malloc(sizeof(unsigned char)*msg_len);
    if (msg_to_sign == NULL) exit_with_failure("Malloc msg_to_sign failed", 1);
    memcpy(msg_to_sign, bufferSupp2, pubkey_len); // peer pubkey is still inside bufferSupp2
    memcpy(&*(msg_to_sign+pubkey_len), " ", strlen(" "));
    memcpy(&*(msg_to_sign+pubkey_len+strlen(" ")), pubkey_byte, pubkey_len);
    
    signature = sign_msg(path_rsa_key, password, msg_to_sign, &signature_len);

    // Encrypt the signature
    ciphertext = (unsigned char*)malloc(sizeof(signature) + BLOCK_SIZE);
    if (ciphertext == NULL) exit_with_failure("Malloc ciphertext failed", 1);
    encrypt_AES_128_CBC(ciphertext, &cipherlen, signature, iv, K_trunc);


    // Serialize the certificate
    file_cert_rsa = fopen(path_cert_rsa, "r");
    if (file_cert_rsa == NULL) exit_with_failure("Fopen failed", 1);
    cert_rsa = PEM_read_X509(file_cert_rsa, NULL, NULL, NULL);
    cert_byte = cert_to_byte(cert_rsa, &cert_len);
    fclose(file_cert_rsa);

    if (cipherlen > 1023 || cert_len > 1023) exit_with_failure("Ciphertext or certificate too long", 0);
    msg_len = MAX_LEN_USERNAME+strlen(" ")+cipherlen+strlen(" ")+pubkey_len+strlen(" ")+cert_len;
    buffer = (unsigned char*) malloc(sizeof(unsigned char)*msg_len);
    if (buffer == NULL) exit_with_failure("Malloc buffer failed", 1);

    // Compose the message
    memcpy(buffer, username, MAX_LEN_USERNAME);
    memcpy(&*(buffer+MAX_LEN_USERNAME), " ", strlen(" "));
    memcpy(&*(buffer+MAX_LEN_USERNAME+strlen(" ")), ciphertext, cipherlen);
    memcpy(&*(buffer+MAX_LEN_USERNAME+strlen(" ")+cipherlen), " ", strlen(" "));
    memcpy(&*(buffer+MAX_LEN_USERNAME+strlen(" ")+cipherlen+strlen(" ")), pubkey_byte, pubkey_len);
    memcpy(&*(buffer+MAX_LEN_USERNAME+strlen(" ")+cipherlen+strlen(" ")+pubkey_len), " ", strlen(" "));
    memcpy(&*(buffer+MAX_LEN_USERNAME+strlen(" ")+cipherlen+strlen(" ")+pubkey_len+strlen(" ")), cert_byte, cert_len);

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
    if (buffer == NULL) exit_with_failure("Malloc buffer failed", 1);
    ret = recv(sd, buffer, 2*BUF_LEN, 0);
    if (ret == -1) exit_with_failure("Receive failed: ", 1);

    memset(bufferSupp1, 0, BUF_LEN);
    memset(bufferSupp2, 0, BUF_LEN);
    memcpy(bufferSupp1, buffer, MAX_LEN_USERNAME);

    old_offset = MAX_LEN_USERNAME+strlen(" ");
    offset = str_ssplit(&*(buffer+old_offset), delim);
    memcpy(bufferSupp2, &*(buffer+old_offset), offset); // signature

    if (strcmp(username, (char*) bufferSupp1) != 0) exit_with_failure("Wrong username.\n", 0);

    // Decrypt and verify signature
    signature = malloc(EVP_PKEY_size(pub_rsa_client));
    decrypt_AES_128_CBC(signature, &signature_len, bufferSupp2, iv, K_trunc);

    ret = verify_signature(msg_to_sign, signature, pub_rsa_client);
    if (ret != 1) exit_with_failure("Signature verification failed.\n", 0);

    free(msg_to_sign);
    free(signature);
    free(buffer);

    return 1;
}
