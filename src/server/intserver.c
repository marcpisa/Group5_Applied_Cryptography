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
    unsigned char* buffer;
    unsigned char* msg_to_sign;
    char* temp;
    unsigned char bufferSupp1[BUF_LEN];
    unsigned char bufferSupp2[BUF_LEN];
    unsigned char bufferSupp3[BUF_LEN];
    unsigned char bufferSupp4[BUF_LEN];
    char* path_pubkey = "../dh_server_pubkey.pem";
    char* path_cert_rsa = "cert.pem";
    char* path_cert_client_rsa = "cert_teo.pem";
    char* path_rsa_key = "key.pem";
    int ret;
    int msg_len;
    char username [MAX_LEN_USERNAME];
    int offset, old_offset;

    // Certificate
    BIO* bio_cert;
    X509* cert_rsa = NULL;
    FILE* file_cert_rsa;
    unsigned char* cert_byte;
    int cert_len = 0;

    X509* client_cert;
    EVP_PKEY* pub_rsa_client;

    // Symmetric encryption
    unsigned char* ciphertext;
    unsigned char* iv;
    unsigned int iv_len;
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
    unsigned int pubkey_len_rec;
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
    temp = (char*) malloc(sizeof(char)*LEN_SIZE);
    if (temp == NULL) exit_with_failure("Malloc temp failed", 1);

    offset = str_ssplit((unsigned char*) rec_mex, DELIM);
    old_offset = offset+strlen(" ");

    offset = str_ssplit(&*((unsigned char*) rec_mex+old_offset), DELIM);
    memcpy(bufferSupp1, &*(rec_mex+old_offset), offset); // username
    old_offset += offset+strlen(" ");

    memcpy(temp, &*(rec_mex+old_offset), LEN_SIZE); // len pubkey
    old_offset += LEN_SIZE+strlen(" ");
    pubkey_len_rec = atoi(temp);

    memcpy(bufferSupp2, &*(rec_mex+old_offset), pubkey_len_rec); // dh pubkey
    old_offset += pubkey_len_rec+strlen(" ");

    memcpy(temp, &*(rec_mex+old_offset), LEN_SIZE); // len iv
    old_offset += LEN_SIZE+strlen(" ");
    iv_len = atoi(temp);

    memcpy(bufferSupp3, &*(rec_mex+old_offset), iv_len); // iv
    old_offset += iv_len+strlen(" ");

    memcpy(temp, &*(rec_mex+old_offset), LEN_SIZE); // len dig sig
    old_offset += LEN_SIZE+strlen(" ");
    signature_len = atoi(temp);

    memcpy(bufferSupp4, &*(rec_mex+old_offset), signature_len); // signature

    free(temp);

    //printf("%d %d %d\n", pubkey_len_rec, iv_len, signature_len);
    /* for(int i = 0; i < 1218; i++) { printf("%c", *(rec_mex+i)); }
    printf("\n\n"); 
    */

    // Sanitize and check username
    if (!username_sanitization((char*) bufferSupp1)) exit_with_failure("Username sanitization fails.\n", 0);
    
    ret = chdir(MAIN_FOLDER_SERVER);
    if (ret == -1) exit_with_failure("No such directory.\n", 0);
    ret = chdir((char*) bufferSupp1);
    if (ret == -1) exit_with_failure("Error: username doesn't exists...\n", 0);
  
    memset(username, 0, MAX_LEN_USERNAME);
    memcpy(username, bufferSupp1, BUF_LEN);

    // Retrieve the client pubkey
    file_cert_rsa = fopen(path_cert_client_rsa, "r");
    if (file_cert_rsa == NULL) exit_with_failure("Fopen failed", 1);
    client_cert = PEM_read_X509(file_cert_rsa, NULL, NULL, NULL);
    if (client_cert == NULL) exit_with_failure("PEM_read_X509 failed", 1);
    pub_rsa_client = X509_get_pubkey(client_cert);
    if (pub_rsa_client == NULL) exit_with_failure("X509_get_pubkey failed", 1);
    fclose(file_cert_rsa);

    peer_pubkey = pubkey_to_PKEY(bufferSupp2, pubkey_len);

    // Calculate K = g^a^b mod p 
    K = key_derivation(my_prvkey, peer_pubkey);
    
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
    
    free(digest);

    // TEST ---- K from 1024 to 128 bit for symm. encr.
    K_trunc = (unsigned char*) malloc(sizeof(unsigned char) * 16); 
    if (K_trunc ==  NULL) exit_with_failure("Malloc K_trunc failed", 1);
    memcpy(K_trunc, K, EVP_CIPHER_key_length(EVP_aes_128_cbc()));
    free(K);

    // Retrieve the IV
    iv = (unsigned char*)malloc(iv_len);
    if (iv == NULL) exit_with_failure("Malloc iv failed", 1);
    memcpy(iv, bufferSupp3, iv_len);


    // Verify the digital signature (bufferSupp4)
    ret = verify_signature(bufferSupp3, bufferSupp4, pub_rsa_client);
    // TO DECOMMENT if (ret != 1) exit_with_failure("Signature verification failed.\n", 0);




    /* --- Send response (username, dig.sign, DH pubkey, cert) --- */
    pubkey_byte = pubkey_to_byte(dh_pubkey, &pubkey_len);

    // Prepare the digital signature
    msg_len = pubkey_len+strlen(" ")+pubkey_len;
    msg_to_sign = (unsigned char*) malloc(sizeof(unsigned char)*msg_len);
    if (msg_to_sign == NULL) exit_with_failure("Malloc msg_to_sign failed", 1);
    memcpy(msg_to_sign, bufferSupp2, pubkey_len); // peer pubkey is still inside bufferSupp2
    memcpy(&*(msg_to_sign+pubkey_len), " ", strlen(" "));
    memcpy(&*(msg_to_sign+pubkey_len+strlen(" ")), pubkey_byte, pubkey_len);
    
    ret = chdir("../../src");
    if (ret == -1) exit_with_failure("No such directory.\n", 0);
    signature = sign_msg(path_rsa_key, password, msg_to_sign, &signature_len);
    
    // Encrypt the signature
    ciphertext = (unsigned char*)malloc(sizeof(signature) + BLOCK_SIZE);
    if (ciphertext == NULL) exit_with_failure("Malloc ciphertext failed", 1);
    encrypt_AES_128_CBC(ciphertext, &cipherlen, signature, iv, K_trunc);

    // Serialize the certificate
    bio_cert = BIO_new(BIO_s_mem());
    BIO_read_filename(bio_cert, path_cert_rsa); // reading certificate to bio
    cert_rsa = PEM_read_bio_X509_AUX(bio_cert, NULL, 0, NULL);  //converting to x509  
    cert_len = i2d_X509(cert_rsa, &cert_byte);  // converting to unsigned char*
    //cert_byte = cert_to_byte(cert_rsa, &cert_len);
    X509_free(cert_rsa);
    BIO_free_all(bio_cert);

    // Come back to the user directory
    ret = chdir("../database/");
    if (ret == -1) exit_with_failure("No such directory.\n", 0);
    ret = chdir(username);
    if (ret == -1) exit_with_failure("No such directory.\n", 0);

    if (cipherlen > 1023) exit_with_failure("Ciphertext too long", 0);
    if (cert_len > 1023) exit_with_failure("Certificate too long", 0);
    msg_len = strlen(username)+strlen(" ")+LEN_SIZE+strlen(" ")+cipherlen+strlen(" ")+LEN_SIZE+strlen(" ")+ \
    pubkey_len+strlen(" ")+LEN_SIZE+strlen(" ")+cert_len;
    buffer = (unsigned char*) malloc(sizeof(unsigned char)*msg_len);
    if (buffer == NULL) exit_with_failure("Malloc buffer failed", 1);
    temp = (char*) malloc(sizeof(char)*LEN_SIZE);
    if (temp == NULL) exit_with_failure("Malloc temp failed", 1);

    // Compose the message
    memcpy(buffer, username, strlen(username)); // username
    memcpy(&*(buffer+strlen(username)), " ", strlen(" "));

    sprintf(temp, "%d", cipherlen);
    memcpy(&*(buffer+strlen(username)+strlen(" ")), temp, LEN_SIZE); // len dig. sig.

    memcpy(&*(buffer+strlen(username)+strlen(" ")+LEN_SIZE), " ", strlen(" "));
    memcpy(&*(buffer+strlen(username)+strlen(" ")+LEN_SIZE+strlen(" ")), ciphertext, cipherlen); // dig. sig.
    memcpy(&*(buffer+strlen(username)+strlen(" ")+LEN_SIZE+strlen(" ")+cipherlen), " ", strlen(" "));

    sprintf(temp, "%d", pubkey_len);
    memcpy(&*(buffer+strlen(username)+strlen(" ")+LEN_SIZE+strlen(" ")+cipherlen+strlen(" ")) \
    , temp, LEN_SIZE); // len pubkey

    memcpy(&*(buffer+strlen(username)+strlen(" ")+LEN_SIZE+strlen(" ")+cipherlen+strlen(" ")+ \
    LEN_SIZE), " ", strlen(" "));
    memcpy(&*(buffer+strlen(username)+strlen(" ")+LEN_SIZE+strlen(" ")+cipherlen+strlen(" ")+ \
    LEN_SIZE+strlen(" ")), pubkey_byte, pubkey_len); // pubkey
    memcpy(&*(buffer+strlen(username)+strlen(" ")+LEN_SIZE+strlen(" ")+cipherlen+strlen(" ")+ \
    LEN_SIZE+strlen(" ")+pubkey_len), " ", strlen(" "));

    sprintf(temp, "%d", cert_len);
    memcpy(&*(buffer+strlen(username)+strlen(" ")+LEN_SIZE+strlen(" ")+cipherlen+strlen(" ")+ \
    LEN_SIZE+strlen(" ")+pubkey_len+strlen(" ")), temp, LEN_SIZE); // len cert    

    memcpy(&*(buffer+strlen(username)+strlen(" ")+LEN_SIZE+strlen(" ")+cipherlen+strlen(" ")+ \
    LEN_SIZE+strlen(" ")+pubkey_len+strlen(" ")+LEN_SIZE), " ", strlen(" "));
    memcpy(&*(buffer+strlen(username)+strlen(" ")+LEN_SIZE+strlen(" ")+cipherlen+strlen(" ")+ \
    LEN_SIZE+strlen(" ")+pubkey_len+strlen(" ")+LEN_SIZE+strlen(" ")), cert_byte, cert_len); // cert.

    //printf("%s\n", buffer);
    printf("I'm sending to the client the response.\n");
    ret = send(sd, buffer, msg_len, 0); 
    if (ret == -1) exit_with_failure("Send failed: ", 1);

    free(temp);
    free(buffer);
    free(pubkey_byte);
    free(cert_byte);
    free(ciphertext);
    free(signature);



    
    /* Parse the client message and verify the fields */
    printf("Debug1\n");
    buffer = (unsigned char*) malloc(sizeof(unsigned char)*(2*BUF_LEN));
    if (buffer == NULL) exit_with_failure("Malloc buffer failed", 1);
    ret = recv(sd, buffer, 2*BUF_LEN, 0);
    if (ret == -1) exit_with_failure("Receive failed: ", 1);
    temp = (char*) malloc(sizeof(char)*LEN_SIZE);
    if (temp == NULL) exit_with_failure("Malloc temp failed", 1);

    printf("Debug1\n");

    memset(bufferSupp1, 0, BUF_LEN);
    memset(bufferSupp2, 0, BUF_LEN);
    
    offset = str_ssplit(buffer, DELIM);
    memcpy(bufferSupp1, buffer, offset); // username
    offset += strlen(" ");

    memcpy(temp, &*(buffer+offset), LEN_SIZE); // len dig.sig.
    offset += LEN_SIZE+strlen(" ");
    signature_len = atoi(temp);
    
    memcpy(bufferSupp2, &*(buffer+offset), signature_len); // signature

    printf("Debug1\n");
    if (strcmp(username, (char*) bufferSupp1) != 0) exit_with_failure("Wrong username.\n", 0);

    // Decrypt and verify signature
    signature = malloc(EVP_PKEY_size(pub_rsa_client));
    decrypt_AES_128_CBC(signature, &signature_len, bufferSupp2, iv, K_trunc);

    printf("Debug1\n");
    ret = verify_signature(msg_to_sign, signature, pub_rsa_client);
    if (ret != 1) exit_with_failure("Signature verification failed.\n", 0);

    printf("Debug1\n");

    free(msg_to_sign);
    free(signature);
    free(buffer);
    free(temp);

    return 1;
}
