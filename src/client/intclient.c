#include "intclient.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include <openssl/rand.h>

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

int loginClient(unsigned char* session_key1, unsigned char* session_key2, char* username, struct sockaddr_in srv_addr, X509_STORE* ca_store) {
    /*********************
     * VARIABLES
     ********************/
    char* path_pubkey;
    char* path_rsa_key;
    unsigned int msg_len;
    size_t offset;
    size_t K_len;

    // Encryption/Decryption (AES-128-CBC)
    unsigned char* iv;
    unsigned char* ciphertext;
    unsigned char* msg_to_ver;
    
    int iv_len;
    int cipherlen;

    // Digital signature
    unsigned char* exp_digsig;
    unsigned char* signature;
    
    int expected_len;
    unsigned int signature_len;

    // Diffie-Hellman
    EVP_PKEY* my_prvkey = NULL;
    EVP_PKEY* dh_pubkey = NULL;
    EVP_PKEY* peer_pubkey;

    unsigned char* K;
    unsigned char* pubkey_byte = NULL;
    
    int pubkey_len = 0;
    int rcv_pubkey_len;
    
    // Certificate
    X509* serv_cert = NULL;
    EVP_PKEY* pub_rsa_key_serv;
    int cert_len;

    int sock, ret;
    char* temp;
    unsigned char* buffer;
    unsigned char* cert_buffer;
    unsigned char bufferSupp1[BUF_LEN];
    unsigned char bufferSupp2[BUF_LEN];
    unsigned char bufferSupp3[BUF_LEN];
    unsigned char bufferSupp4[BUF_LEN];
    /*********************
     * END VARIABLES
     ********************/

    // Creation of socket
    sock = createSocket();
    if (connect(sock, (struct sockaddr*)&srv_addr, sizeof(srv_addr)) < 0) exit_with_failure("Connect failed", 1);

    // Compose the path for the current user
    path_pubkey = (char*) malloc(sizeof(char)*(15+strlen(username)+14+1));
    memcpy(path_pubkey, "../../database/", 15);
    memcpy(&*(path_pubkey+15), username, strlen(username));
    memcpy(&*(path_pubkey+15+strlen(username)), "/dh_pubkey.pem\0", 14+1);
    
    path_rsa_key = (char*) malloc(sizeof(char)*(15+strlen(username)+8+1));
    memcpy(path_rsa_key, "../../database/", 15);
    memcpy(&*(path_rsa_key+15), username, strlen(username));
    memcpy(&*(path_rsa_key+15+strlen(username)), "/rsa.pem\0", 8+1);

    // Generate DH asymmetric key(s)
    pubkey_byte = gen_dh_keys(path_pubkey, &my_prvkey, &dh_pubkey, &pubkey_len);
    

    /* ---- 1st message: login request message + username + DH pubkey + IV + dig.sig.(IV) ---- */
    // Generate the IV
    iv = (unsigned char*) malloc(sizeof(unsigned char)*IV_LEN);
    if (!iv) exit_with_failure("Malloc iv failed", 1);
    RAND_poll(); // Seed OpenSSL PRNG
    ret = RAND_bytes((unsigned char*)&iv[0], IV_LEN);
    if (ret != 1) exit_with_failure("RAND_bytes failed\n", 0);
    iv_len = IV_LEN;

    // IV digital signature
    signature = sign_msg(path_rsa_key, iv, iv_len, &signature_len);  

    // Calculate the message length and allocate the memory
    msg_len = strlen(LOGIN_REQUEST)+strlen(" ")+strlen(username)+strlen(" ")+LEN_SIZE+ \
    strlen(" ")+pubkey_len+strlen(" ")+LEN_SIZE+strlen(" ")+iv_len+strlen(" ")+ \
    LEN_SIZE+strlen(" ")+signature_len+1;
    buffer = (unsigned char*) malloc(sizeof(unsigned char)*(msg_len+1));
    if (!buffer) exit_with_failure("Malloc buffer failed", 1);
    temp = (char*) malloc(sizeof(char)*LEN_SIZE);
    if (!temp) exit_with_failure("Malloc temp failed", 1);

    /* Compose the message and send it to the server (login_request username len_pubkey pubkey 
    len_iv iv len_digsig signature_iv) */
    memcpy(buffer, LOGIN_REQUEST, strlen(LOGIN_REQUEST));  // login req
    memcpy(&*(buffer+strlen(LOGIN_REQUEST)), " ", strlen(" "));
    memcpy(&*(buffer+strlen(LOGIN_REQUEST)+strlen(" ")), username, strlen(username)); // username
    memcpy(&*(buffer+strlen(LOGIN_REQUEST)+strlen(" ")+strlen(username)), " ", strlen(" "));
    
    sprintf(temp, "%d", pubkey_len);
    memcpy(&*(buffer+strlen(LOGIN_REQUEST)+strlen(" ")+strlen(username)+strlen(" ")), temp, \
    LEN_SIZE); // len pubkey
    
    memcpy(&*(buffer+strlen(LOGIN_REQUEST)+strlen(" ")+strlen(username)+strlen(" ")+LEN_SIZE), \
    " ", strlen(" "));
    memcpy(&*(buffer+strlen(LOGIN_REQUEST)+strlen(" ")+strlen(username)+strlen(" ")+LEN_SIZE+ \
    strlen(" ")), pubkey_byte, pubkey_len); // dh pubkey
    memcpy(&*(buffer+strlen(LOGIN_REQUEST)+strlen(" ")+strlen(username)+strlen(" ")+LEN_SIZE+ \
    strlen(" ")+pubkey_len), " ", strlen(" ")); 
    
    sprintf(temp, "%d", iv_len);
    memcpy(&*(buffer+strlen(LOGIN_REQUEST)+strlen(" ")+strlen(username)+strlen(" ")+LEN_SIZE+ \
    strlen(" ")+pubkey_len+strlen(" ")), temp, LEN_SIZE); // len iv
    
    memcpy(&*(buffer+strlen(LOGIN_REQUEST)+strlen(" ")+strlen(username)+strlen(" ")+LEN_SIZE+ \
    strlen(" ")+pubkey_len+strlen(" ")+LEN_SIZE), " ", strlen(" "));
    memcpy(&*(buffer+strlen(LOGIN_REQUEST)+strlen(" ")+strlen(username)+strlen(" ")+LEN_SIZE+ \
    strlen(" ")+pubkey_len+strlen(" ")+LEN_SIZE+strlen(" ")), iv, iv_len); // iv
    memcpy(&*(buffer+strlen(LOGIN_REQUEST)+strlen(" ")+strlen(username)+strlen(" ")+LEN_SIZE+ \
    strlen(" ")+pubkey_len+strlen(" ")+LEN_SIZE+strlen(" ")+iv_len), " ", strlen(" "));
    
    sprintf(temp, "%d", signature_len);
    memcpy(&*(buffer+strlen(LOGIN_REQUEST)+strlen(" ")+strlen(username)+strlen(" ")+LEN_SIZE+ \
    strlen(" ")+pubkey_len+strlen(" ")+LEN_SIZE+strlen(" ")+iv_len+strlen(" ")), \
    temp, LEN_SIZE); // len dig. sig.
    
    memcpy(&*(buffer+strlen(LOGIN_REQUEST)+strlen(" ")+strlen(username)+strlen(" ")+LEN_SIZE+ \
    strlen(" ")+pubkey_len+strlen(" ")+LEN_SIZE+strlen(" ")+iv_len+strlen(" ")+ \
    LEN_SIZE), " ", strlen(" "));
    memcpy(&*(buffer+strlen(LOGIN_REQUEST)+strlen(" ")+strlen(username)+strlen(" ")+LEN_SIZE+ \
    strlen(" ")+pubkey_len+strlen(" ")+LEN_SIZE+strlen(" ")+iv_len+strlen(" ")+ \
    LEN_SIZE+strlen(" ")), signature, signature_len); // iv dig. sig.

    memcpy(&*(buffer+msg_len-1), "\0", 1);
    /* 
    for(int i = 0; i < msg_len; i++) { printf("%c", *(buffer+i)); }
    printf("\n\n");    
    */
    //printf("%d\n%d\n%d\n", pubkey_len, iv_len, signature_len);
    printf("I'm sending to the server the first message.\n");
    ret = send(sock, buffer, msg_len, 0);
    if (ret == -1) exit_with_failure("Send failed", 1);

    free(buffer);
    free(signature);
    free(temp);




    /* ---- Obtain and parse response server (username, DH pubkey, signature and cert.) ----*/
    msg_len = 4*BUF_LEN;
    buffer = (unsigned char*) malloc(sizeof(unsigned char)*msg_len);
    if (!buffer) exit_with_failure("Malloc buffer failed", 1);
    ret = recv(sock, buffer, msg_len, 0);
    if (ret == -1) exit_with_failure("Receive failed", 1);
    printf("Received the response of the server.\n");
    temp = (char*) malloc(sizeof(char)*LEN_SIZE);
    if (!temp) exit_with_failure("Malloc temp failed", 1);

    // Parse the server response
    memset(bufferSupp1, 0, BUF_LEN);
    memset(bufferSupp2, 0, BUF_LEN);
    memset(bufferSupp3, 0, BUF_LEN);

    offset = str_ssplit(buffer, DELIM);
    memcpy(bufferSupp1, buffer, strlen(username)); // username
    offset += strlen(" ");

    memcpy(temp, &*(buffer+offset), LEN_SIZE); // len dig.sig
    offset += LEN_SIZE+strlen(" ");
    signature_len = atoi(temp);

    memcpy(bufferSupp2, &*(buffer+offset), signature_len); // dig.sig.
    offset += signature_len+strlen(" ");

    memcpy(temp, &*(buffer+offset), LEN_SIZE); // len pubkey
    offset += LEN_SIZE+strlen(" ");
    rcv_pubkey_len = atoi(temp);
    if(rcv_pubkey_len != pubkey_len) exit_with_failure("Wrong pubkey len", 0);

    memcpy(bufferSupp3, &*(buffer+offset), rcv_pubkey_len); // g^b
    offset += rcv_pubkey_len+strlen(" ");

    memcpy(temp, &*(buffer+offset), LEN_SIZE); // len cert
    offset += LEN_SIZE+strlen(" ");
    cert_len = atoi(temp);

    // The certificate is greater than 1024
    cert_buffer = (unsigned char*) malloc((cert_len+1)*sizeof(unsigned char));
    if (!cert_buffer) exit_with_failure("cert_buffer malloc failed", 1);
    memcpy(cert_buffer, &*(buffer+offset), cert_len); // cert
    
    free(temp);
    free(buffer);

    // Sanitization username and check validity
    if (!username_sanitization((char*) bufferSupp1)) exit_with_failure("Username sanitization fails\n", 0);    
    if (strcmp(username, (char*) bufferSupp1) != 0) exit_with_failure("Wrong username\n", 0);

    // Obtain the public key, derive the established key
    peer_pubkey = pubkey_to_PKEY(bufferSupp3, pubkey_len);
    K = key_derivation(my_prvkey, peer_pubkey, &K_len);

    // Obtain the two session keys from the established key
    issue_session_keys(K, K_len, &session_key1, &session_key2);
    
    // Decrypt the message (digital signature) (bufferSupp2)
    msg_to_ver = (unsigned char*) malloc(sizeof(unsigned char) * BUF_LEN);
    if (!msg_to_ver) exit_with_failure("Malloc msg_to_ver failed", 1);
    decrypt_AES_128_CBC(&msg_to_ver, &msg_len, bufferSupp2, signature_len, iv, K);
   
    // Obtain the RSA public key and verify the certificate of the server
    serv_cert = cert_to_X509(cert_buffer, cert_len);
    if (!serv_cert) exit_with_failure("cert_to_X509 failed", 1);
    pub_rsa_key_serv = get_ver_server_pubkey(serv_cert, ca_store);
    X509_free(serv_cert);
    free(cert_buffer);

    // Generate the digital signature expected
    expected_len = pubkey_len+strlen(" ")+pubkey_len;
    exp_digsig = (unsigned char*) malloc(sizeof(unsigned char)*expected_len);
    if (!exp_digsig) exit_with_failure("Malloc exp_digsig failed", 1);
    
    memcpy(exp_digsig, pubkey_byte, pubkey_len);
    memcpy(&*(exp_digsig+pubkey_len), " ", strlen(" "));
    memcpy(&*(exp_digsig+pubkey_len+strlen(" ")), bufferSupp3, pubkey_len); // peer pubkey is still inside bufferSupp3
    
    // Verify the digital signature received (decrypted in the previous step)
    ret = verify_signature(exp_digsig, expected_len, msg_to_ver, msg_len, pub_rsa_key_serv);
    if (ret != 1) exit_with_failure("Signature verification failed.\n", 0);
    
    free(pubkey_byte);
    free(msg_to_ver);
    EVP_PKEY_free(pub_rsa_key_serv);
    EVP_PKEY_free(my_prvkey);




    /* Generate last message for the server (username + digital signature) */
    // Sign exp_digsig with private key of client and encrypt the signature with K
    signature = sign_msg(path_rsa_key, exp_digsig, expected_len, &signature_len);
    ciphertext = (unsigned char*) malloc(signature_len + BLOCK_SIZE);
    if (!ciphertext) exit_with_failure("Malloc ciphertext failed", 1);
    encrypt_AES_128_CBC(&ciphertext, &cipherlen, signature, signature_len, iv, K);
    
    msg_len = strlen(username) + strlen(" ") + LEN_SIZE + strlen(" ") + cipherlen;
    buffer = (unsigned char*) malloc(sizeof(unsigned char)*msg_len);
    if (!buffer) exit_with_failure("Malloc buffer failed", 1);
    temp = (char*) malloc(sizeof(char)*LEN_SIZE);
    if (!temp) exit_with_failure("Malloc temp failed", 1);

    // Compose the message (username len_digsig signature)
    memcpy(buffer, username, strlen(username)); // username
    memcpy(&*(buffer+strlen(username)), " ", strlen(" "));

    sprintf(temp, "%d", cipherlen);
    memcpy(&*(buffer+strlen(username)+strlen(" ")), temp, LEN_SIZE); // len dig. sig.

    memcpy(&*(buffer+strlen(username)+strlen(" ")+LEN_SIZE), " ", strlen(" "));
    memcpy(&*(buffer+strlen(username)+strlen(" ")+LEN_SIZE+strlen(" ")), ciphertext, \
    cipherlen); // signature
    
    //printf("%s\n", buffer);
    printf("I'm sending to the server the last message.\n");
    ret = send(sock, buffer, msg_len, 0); 
    if (ret == -1) exit_with_failure("Send failed", 1);

    free(path_pubkey);
    free(path_rsa_key);

    free(temp);
    free(buffer);
    free(ciphertext);
    free(signature);
    free(exp_digsig);
    free(iv);
    free(K);



    /*CHECK IF ALL IS CORRECT WITH THE LAST MESSAGE OF THE SERVER */
    
    return 1;
}