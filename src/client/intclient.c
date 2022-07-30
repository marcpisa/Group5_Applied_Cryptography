#include "intclient.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include <sys/sendfile.h>

#define MAX_SIZE_USERNAME 25
#define MAX_SIZE_REQUEST 15
#define MAX_SIZE_PUBKEY 1024

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
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
    {
        printf("\n Socket creation error \n");
        return -1;
    }
    return sock;
}

int loginClient(char* session_key1, char* session_key2, char* username, struct sockaddr_in srv_addr) {
    EVP_MD_CTX* ctx_digest;
    unsigned char* digest;
    char key[1028]; // TO check if the size is 1028 byte, not sure, but it is fixed
    int digestlen;
    char* path_pubkey = "../dh_client1_pubkey.pem";
    int pubkey_len = 0;
    int msg_len;

    // Diffie-Hellman variables
    EVP_PKEY* dh_params;
    EVP_PKEY_CTX* ctx_dh;
    EVP_PKEY* my_prvkey = NULL;
    EVP_PKEY* peer_pubkey;
    unsigned char* K;
    EVP_PKEY_CTX* ctx_drv;
    size_t secretlen;
    FILE* file_pubkey_pem;
    EVP_PKEY* dh_pubkey;

    // Certificate
    X509* server_cert;
    FILE* cert_fp;

    int sock, ret;
    unsigned char* buffer;
    unsigned char bufferSupp1[BUF_LEN];
    unsigned char bufferSupp2[BUF_LEN];
    unsigned char bufferSupp3[BUF_LEN];
    unsigned char bufferSupp4[BUF_LEN];
    
    sock = createSocket();
    if (connect(sock, (struct sockaddr*)&srv_addr, sizeof(srv_addr)) < 0) 
    {
        printf("\nConnection Failed \n");
        exit(1);
    }

    /* ---- Generate DH asymmetric key(s) ---- */
    dh_params = EVP_PKEY_new();
    EVP_PKEY_set1_DH(dh_params, DH_get_1024_160());

    ctx_dh = EVP_PKEY_CTX_new(dh_params, NULL);
    EVP_PKEY_keygen_init(ctx_dh);
    EVP_PKEY_keygen(ctx_dh, &my_prvkey);

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
    
    free(ctx_dh);
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
        exit(-1);
    }
    
    
    /* ---- Send login request message + DH pubkey ---- */
    unsigned char* pubkey_byte = pubkey_to_byte(dh_pubkey, &pubkey_len);
    if (pubkey_len > MAX_SIZE_PUBKEY) 
    {
        printf("Pubkey too long.\n");
        exit(-1);
    }
    msg_len = MAX_SIZE_REQUEST+strlen(" ")+MAX_SIZE_USERNAME+strlen(" ")+MAX_SIZE_PUBKEY;
    buffer = (unsigned char*) malloc(sizeof(unsigned char)*msg_len);

    memcpy(buffer, LOGIN_REQUEST, MAX_SIZE_REQUEST);
    memcpy(&*(buffer+MAX_SIZE_REQUEST), " ", strlen(" "));
    memcpy(&*(buffer+MAX_SIZE_REQUEST+strlen(" ")), username, MAX_SIZE_USERNAME);
    memcpy(&*(buffer+MAX_SIZE_REQUEST+strlen(" ")+MAX_SIZE_USERNAME), " ", strlen(" "));
    memcpy(&*(buffer+MAX_SIZE_REQUEST+strlen(" ")+MAX_SIZE_USERNAME+strlen(" ")), pubkey_byte, MAX_SIZE_PUBKEY);
    //printf("%s\n", buffer);
    printf("I'm sending to the server the mex %s\n\n", buffer);
    ret = send(sock, buffer, msg_len, 0); 
    if (ret == -1)
    {
        printf("Send operation gone bad\n");
        // Change this later to manage properly the session
        exit(1);
    }

    free(buffer);
    free(pubkey_byte);
    exit(1);









    /* ---- Obtain response server (DH pubkey, signature and cert.) ----*/
    memset(buffer, 0, strlen(buffer));
    printf("Login request message sent\n");
    ret = recv(sock, buffer, BUF_LEN,0);
    if (ret == -1)
    {
        printf("Receive operation gone bad\n");
        // Change this later to manage properly the session
        exit(1);
    }

    // Parse the server response
    // username, g^b, encrypted dig.sign., cert. server
    memset(bufferSupp1, 0, strlen(bufferSupp1));
    memset(bufferSupp2, 0, strlen(bufferSupp2));
    memset(bufferSupp3, 0, strlen(bufferSupp3));
    memset(bufferSupp4, 0, strlen(bufferSupp4));
    sscanf(buffer, "%s %s %s %s", bufferSupp1, bufferSupp2, bufferSupp3, bufferSupp4);

    // SANITIZATION

    if (strcmp(username, bufferSupp1) != 0) 
    {
        printf("Wrong username\n");
        // Change this later to manage properly the session
        exit(1);
    }


    peer_pubkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);

    //cert_fp = fopen(cert, r);

    //server_cert = PEM_read_X509(cert_fp, NULL, NULL, NULL);




    // Calculate K = g^a^b mod p 
    //peer_pubkey = bufferSupp2;

    ctx_drv = EVP_PKEY_CTX_new(my_prvkey, NULL);
    EVP_PKEY_derive_init(ctx_drv);
    EVP_PKEY_derive_set_peer(ctx_drv, peer_pubkey);
    
    /* Retrieving shared secret’s length */
    EVP_PKEY_derive(ctx_drv, NULL, &secretlen);

    /* Deriving shared secret */
    K = (unsigned char*)malloc(secretlen);
    EVP_PKEY_derive(ctx_drv, K, &secretlen);


    // Decrypt the server's message (bufferSupp3)
    printf("%lu\n", secretlen);
    return -1;


    /*
    // Verify the signature of the server
    // DO SOMETHING WITH CERTIFICATE (bufferSupp4)
    
    
    
    // Check that all the contents are correct like the fresh quantities and the username received back
    


    // If everything good

    // Concatenate g^a (dh_pubkey) and g^b, signed it with the private key and encrypt it with K
    // result=....
    
    
    memset(buffer, 0, strlen(buffer));
    sprintf(buffer, "%s %s", username, result); // or %d?
    printf("I'm sending to the server the mex %s\n\n", buffer);

    ret = send(sock, buffer, strlen(buffer), 0); // in clear
    if (ret == -1)
    {
        printf("Send operation gone bad\n");
        // Change this later to manage properly the session
        exit(1);
    }

    memset(buffer, 0, strlen(buffer));
    printf("Login last message sent\n");
    ret = recv(sock, buffer, BUF_LEN,0);
    if (ret == -1)
    {
        printf("Receive operation gone bad\n");
        // Change this later to manage properly the session
        exit(1);
    }

    sscanf(buffer, "%s %s", bufferSupp1, bufferSupp2); // The two values are the message type and eventually the reason why the request went bad
    
    // SANITIZE THE BUFFER

    if (strcmp(bufferSupp1, LOGIN_DENIED) == 0)
    {
        printf("The login request has been denied: %s\n\n", bufferSupp2);
        return -1;
    }
    else if (strcmp(bufferSupp1, LOGIN_ACCEPTED) == 0)
    {
        printf("The login request has been accepted!\n\n");
    }
    else
    {
        printf("We don't know what the server said...\n\n");
        return -1;
    }


    // After establishing the session key, there is the
    // generation of the two session keys (for symm. encr. and MAC) 
    digest = (unsigned char*)malloc(EVP_MD_size(EVP_sha256())); // check malloc return value
    ctx_digest = EVP_MD_CTX_new();


    // Hashing
    EVP_DigestInit(ctx_digest, EVP_sha256());
    
    // We need more than one update....
    EVP_DigestUpdate(ctx_digest, (unsigned char*)key, sizeof(key));
    EVP_DigestFinal(ctx_digest, digest, &digestlen);

    EVP_MD_CTX_free(ctx_digest);

    // Split the digest in half to obtain the two keys
    if(len(session_key1) != (16+1) || len(session_key2) != (16+1)) { //16byte=128bits + null final char
        print("Invalid length of session keys");
        return -1;
    }
    if(digestlen != 256) {
        print("Invalid length of digest");
        return -1;
    }

    for(int i = 0; i < 16; i++) {
        session_key1[i] = digest[i];
    }
    session_key1[16] = '\0';

    for(int i = 0; i < 16; i++) {
        session_key2[i] = digest[15+i];
    }
    session_key2[16] = '\0';

    //DH_free(dh_client);

    //return
    */
    BIO_free(bio);
}