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

int loginServer(int sd, char* rec_mex)
{   
    unsigned char* buffer;
    unsigned char* msg_to_sign;
    unsigned char bufferSupp1[BUF_LEN];
    unsigned char bufferSupp2[BUF_LEN];
    unsigned char bufferSupp3[BUF_LEN];
    unsigned char bufferSupp4[BUF_LEN];
    int ret;
    char* path_pubkey = "../dh_server_pubkey.pem";
    char* path_peer_pubkey = "../dh_peer1_pubkey.pem";
    char* path_cert_rsa = "../cert.pem";
    char* path_rsa_key = "../key.pem";
    int msg_len;

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
    BIO* bio;

    // REMEMBER TO SANITIZE PROPERLY THE BUFFER (VERY IMPORTANT)

    bio = BIO_new_socket(sd, BIO_NOCLOSE);

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
    
    // sign and encrypt

    
    // Serialize the certificate


    msg_len = MAX_SIZE_USERNAME+strlen(" ")+...+strlen(" ")+pubkey_len
    buffer = (unsigned char*) malloc(sizeof(unsigned char)*msg_len);


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
    free(msg_to_sign);


    // Calculating digital signature

    /**/



    /* Sending certificate ....
    // Send pubkey file size
    ret = send(sock, file_sz, sizeof(file_sz), 0);
    if (ret < 0)
    {
        printf("Send file size gone bad\n");
        exit(1);
    }

    file_pubkey_pem = fopen(path_pubkey, "r");
    if (file_pubkey_pem == NULL) 
    { 
        printf("Error reading PEM file.\n");
        // Change this later to manage properly the session
        exit(1);
    } 

    // Sending file data
    offset = 0;
    remain_data = file_sz;
    while (((sent_bytes = sendfile(sock, file_pubkey_pem, &offset, BUF_LEN)) > 0) && (remain_data > 0))
    {
            fprintf(stdout, "1. Client sent %d bytes from file's data, offset is now : %d and remaining data = %d\n", sent_bytes, offset, remain_data);
            remain_data -= sent_bytes;
            fprintf(stdout, "2. Client sent %d bytes from file's data, offset is now : %d and remaining data = %d\n", sent_bytes, offset, remain_data);
    }

*/
































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
}
