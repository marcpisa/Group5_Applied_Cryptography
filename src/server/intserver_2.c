#include "intserver.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <sys/sendfile.h>
#include <openssl/x509.h>
#include <openssl/rand.h>

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

int loginServer(int sd, char* rec_mex, unsigned char* session_key1, unsigned char* session_key2)
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
    char* path_rsa_key = "rsa_prvkey.pem";
    char* path_cert_client_rsa = "cert_teo.pem";
    int ret;
    int msg_len;
    char username [MAX_LEN_USERNAME];
    int offset, old_offset;
    size_t K_len;

    // Certificate
    unsigned char* cert_byte;
    int cert_len = 0;
    EVP_PKEY* pub_rsa_client;

    // Symmetric encryption
    unsigned char* ciphertext;
    unsigned char* iv;
    unsigned int iv_len;
    int cipherlen;

    // Digital Signature variables
    unsigned char* signature;
    unsigned int signature_len;
    char* password = "password";
    int msg_to_sign_len;

    // Diffie-Hellman variables
    EVP_PKEY* dh_pubkey = NULL;
    EVP_PKEY* my_prvkey = NULL;
    EVP_PKEY* peer_pubkey;
    
    unsigned char* pubkey_byte = NULL;
    unsigned char* K;
    unsigned char* K_trunc;
    
    int pubkey_len = 0;
    unsigned int pubkey_len_rec;
    
    /*********************
     * END VARIABLES
     ********************/
    
    /* Generate private and certificate for public key
     * Private key
     *      openssl genrsa -aes128 -out rsa_prvkey.pem 2048
     * Public key
     *      openssl rsa -pubout -in rsa_prvkey.pem -out rsa_pubkey.pem
     * Certificate
     *      openssl req -new -x509 -key rsa_prvkey.pem -out cert.pem -days 360
     */
    
    // Generate DH asymmetric key(s)
    pubkey_byte = gen_dh_keys(path_pubkey, &my_prvkey, &dh_pubkey, &pubkey_len);

    
    /* ---- Parse the first message ---- */
    /*
    memset(bufferSupp1, 0, BUF_LEN);
    memset(bufferSupp2, 0, BUF_LEN);
    memset(bufferSupp3, 0, BUF_LEN);
    memset(bufferSupp4, 0, BUF_LEN);
    temp = (char*) malloc(sizeof(char)*LEN_SIZE);
    if (!temp) exit_with_failure("Malloc temp failed", 1);

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

    
    //printf("%d %d %d\n", pubkey_len_rec, iv_len, signature_len);
    //for(int i = 0; i < 1218; i++) { printf("%c", *(rec_mex+i)); }
    //printf("\n\n"); 

    // Sanitize and check username
    if (!username_sanitization((char*) bufferSupp1)) exit_with_failure("Username sanitization fails.\n", 0);
    
    ret = chdir(MAIN_FOLDER_SERVER);
    if (ret == -1) exit_with_failure("No such directory.\n", 0);
    ret = chdir((char*) bufferSupp1);
    if (ret == -1) exit_with_failure("Error: username doesn't exists...\n", 0);
  
    memset(username, 0, MAX_LEN_USERNAME);
    memcpy(username, bufferSupp1, BUF_LEN);

    // Retrieve the client pubkey (from the client cert., already owned by the server)
    pub_rsa_client = get_client_pubkey(path_cert_client_rsa);
    
    // Calculate K = g^a^b mod p, established key
    peer_pubkey = pubkey_to_PKEY(bufferSupp2, pubkey_len);
    K = key_derivation(my_prvkey, peer_pubkey, &K_len);
    
    EVP_PKEY_free(peer_pubkey);

    // Obtain the two session keys from the established key
    issue_session_keys(K, K_len, &session_key1, &session_key2);
    
    // TEST ---- K from 1024 to 128 bit for symm. encr.
    K_trunc = (unsigned char*) malloc(sizeof(unsigned char) * 16); 
    if (!K_trunc) exit_with_failure("Malloc K_trunc failed", 1);
    memcpy(K_trunc, K, EVP_CIPHER_key_length(EVP_aes_128_cbc()));
    
    // Retrieve the IV
    iv = (unsigned char*) malloc(iv_len);
    if (!iv) exit_with_failure("Malloc iv failed", 1);
    memcpy(iv, bufferSupp3, iv_len);

    // Verify the digital signature (bufferSupp4) of the iv
    ret = verify_signature(bufferSupp3, iv_len, bufferSupp4, signature_len, pub_rsa_client);
    if (ret != 1) exit_with_failure("Signature verification failed.\n", 0);

    printf("First message is correct. Preparing the response...\n");

    free(temp);
    free(K);
    */

    // Generate the IV
    iv = (unsigned char*) malloc(IV_LEN);
    if (!iv) exit_with_failure("Malloc iv failed", 1);
    RAND_poll(); // Seed OpenSSL PRNG
    ret = RAND_bytes((unsigned char*)&iv[0], IV_LEN);
    if (ret != 1) exit_with_failure("RAND_bytes failed\n", 0);

    K_trunc = (unsigned char*) malloc(sizeof(unsigned char) * 16);
    if(!K_trunc) exit_with_failure("K_trunc malloc failed", 1);
    memcpy(username, "teo", 3);
    memcpy(K_trunc, "teo1234567891234", 16);

    /* --- Send response (username, dig.sign, DH pubkey, cert) --- */
    /*
    pubkey_byte = pubkey_to_byte(dh_pubkey, &pubkey_len);

    // Prepare the digital signature
    //if ((int)pubkey_len_rec != pubkey_len) exit_with_failure("Pubkey length wrong.\n", 0);
    msg_to_sign_len = pubkey_len+strlen(" ")+pubkey_len;
    msg_to_sign = (unsigned char*) malloc(sizeof(unsigned char)*msg_to_sign_len);
    if (!msg_to_sign) exit_with_failure("Malloc msg_to_sign failed", 1);
    
    memcpy(msg_to_sign, pubkey_byte, pubkey_len); // peer pubkey is still inside bufferSupp2
    memcpy(&*(msg_to_sign+pubkey_len), " ", strlen(" "));
    memcpy(&*(msg_to_sign+pubkey_len+strlen(" ")), pubkey_byte, pubkey_len);
    */
    msg_to_sign = (unsigned char*) malloc(5*sizeof(unsigned char));
    memcpy(msg_to_sign, "teo12", 5);
    ret = chdir("../../src");
    if (ret == -1) exit_with_failure("No such directory.\n", 0);
    //signature = sign_msg(path_rsa_key, password, msg_to_sign, &signature_len);

    // Encrypt the signature
    ciphertext = (unsigned char*)malloc(sizeof(signature) + BLOCK_SIZE);
    if (!ciphertext) exit_with_failure("Malloc ciphertext failed", 1);
    encrypt_AES_128_CBC(&ciphertext, &cipherlen, msg_to_sign, iv, K_trunc);
    

    // Serialize the certificate
    cert_byte = read_cert(path_cert_rsa, &cert_len);

    // Come back to the user directory
    /*
    ret = chdir("../database/");
    if (ret == -1) exit_with_failure("No such directory.\n", 0);
    ret = chdir(username);
    if (ret == -1) exit_with_failure("No such directory.\n", 0);

    // Calculating message length and allocate memory for it
    msg_len = strlen(username)+strlen(" ")+LEN_SIZE+strlen(" ")+cipherlen+strlen(" ")+LEN_SIZE+strlen(" ")+ \
    pubkey_len+strlen(" ")+LEN_SIZE+strlen(" ")+cert_len;
    
    printf("%d %d %d\n", cipherlen, cert_len, msg_len);
    if (cipherlen > 1023) exit_with_failure("Ciphertext too long", 0);
    if (cert_len > 1023) exit_with_failure("Certificate too long", 0);
    
    buffer = (unsigned char*) malloc(sizeof(unsigned char)*msg_len);
    if (!buffer) exit_with_failure("Malloc buffer failed", 1);
    temp = (char*) malloc(sizeof(char)*LEN_SIZE);
    if (!temp) exit_with_failure("Malloc temp failed", 1);
    */
    /* Compose the message (username len_digsig signature len_pubkey pubkey len_cert cert) */
    /*
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
    
    EVP_PKEY_free(dh_pubkey);
    */


    
    /* Parse the client message and verify the fields */
    /*
    msg_len = 2*BUF_LEN;
    buffer = (unsigned char*) malloc(sizeof(unsigned char)*msg_len);
    if (!buffer) exit_with_failure("Malloc buffer failed", 1);
    temp = (char*) malloc(sizeof(char)*LEN_SIZE);
    if (!temp) exit_with_failure("Malloc temp failed", 1);

    ret = recv(sd, buffer, msg_len, 0);
    if (ret == -1) exit_with_failure("Receive failed: ", 1);
    
    memset(bufferSupp1, 0, BUF_LEN);
    memset(bufferSupp2, 0, BUF_LEN);
    
    offset = str_ssplit(buffer, DELIM);
    memcpy(bufferSupp1, buffer, offset); // username
    offset += strlen(" ");

    memcpy(temp, &*(buffer+offset), LEN_SIZE); // len dig.sig.
    offset += LEN_SIZE+strlen(" ");
    signature_len = atoi(temp);
    
    memcpy(bufferSupp2, &*(buffer+offset), signature_len); // signature

    // Check correctness of username
    if (strcmp(username, (char*) bufferSupp1) != 0) exit_with_failure("Wrong username.\n", 0);

    // Decrypt and verify signature
    signature = malloc(EVP_PKEY_size(pub_rsa_client));
    decrypt_AES_128_CBC(&signature, &signature_len, bufferSupp2, iv, K_trunc);

    ret = verify_signature(msg_to_sign, msg_to_sign_len, signature, signature_len, pub_rsa_client);
    if (ret != 1) exit_with_failure("Signature verification failed.\n", 0);

    
    free(signature);
    free(buffer);
    free(temp);
    free(msg_to_sign);

    free(iv);
    free(K_trunc);

    EVP_PKEY_free(pub_rsa_client);
    */

    printf("Done.\n");

    return 1;
}
