#include "intclient.h"
#include <openssl/evp.h>
#include <openssl/pem.h>

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

int loginClient(char* session_key1, char* session_key2, char* username, struct sockaddr_in srv_addr)
{
    EVP_MD_CTX* ctx_digest;
    unsigned char* digest;
    char key[1028]; // TO check if the size is 1028 byte, not sure, but it is fixed
    int digestlen;
    
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

    int sock, ret;
    char buffer[BUF_LEN];
    char bufferSupp1[BUF_LEN];
    char bufferSupp2[BUF_LEN];
    char bufferSupp3[BUF_LEN];
    char bufferSupp4[BUF_LEN];
    sock = createSocket();

    if (connect(sock, (struct sockaddr*)&srv_addr, sizeof(srv_addr)) < 0) 
    {
        printf("\nConnection Failed \n");
        exit(1);
    }


    /* Generate a (private key of the client) and the 
       related public key, and saves the public key */
    dh_params = EVP_PKEY_new();
    EVP_PKEY_set1_DH(dh_params, DH_get_1024_160());

    ctx_dh = EVP_PKEY_CTX_new(dh_params, NULL);
    EVP_PKEY_keygen_init(ctx_dh);
    EVP_PKEY_keygen(ctx_dh, &my_prvkey);

    // Save public key
    file_pubkey_pem = fopen("../dh_client1_pubkey.pem", "w"); // to fix path
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
    // free ...

    // Retrieve the saved public key
    file_pubkey_pem = fopen("../dh_client1_pubkey.pem", "r"); // to fix path
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
    

    /* Send FIRST MESSAGE to server: login request message */
    memset(buffer, 0, strlen(buffer));
    sprintf(buffer, "%s %s %s", LOGIN_REQUEST, username, dh_pubkey); // or %d?
    printf("I'm sending to the server the mex %s\n\n", buffer);

    ret = send(sock, buffer, strlen(buffer), 0); // in clear
    if (ret == -1)
    {
        printf("Send operation gone bad\n");
        // Change this later to manage properly the session
        exit(1);
    }

    memset(buffer, 0, strlen(buffer));
    memset(bufferSupp1, 0, strlen(bufferSupp1));
    memset(bufferSupp2, 0, strlen(bufferSupp2));
    memset(bufferSupp3, 0, strlen(bufferSupp3));
    memset(bufferSupp4, 0, strlen(bufferSupp4));
    printf("Login request message sent\n");
    ret = recv(sock, buffer, BUF_LEN,0);
    if (ret == -1)
    {
        printf("Receive operation gone bad\n");
        // Change this later to manage properly the session
        exit(1);
    }

    /* Parse the server response, calculate K and do the checks*/
    // username, g^b, encrypted dig.sign., cert. server
    sscanf(buffer, "%s %s %s %s", bufferSupp1, bufferSupp2, bufferSupp3, bufferSupp4);

    // SANITIZATION

    if (strcmp(username, bufferSupp1) != 0) 
    {
        printf("Wrong username\n");
        // Change this later to manage properly the session
        exit(1);
    }

    // Calculate K = g^a^b mod p 
    peer_pubkey = bufferSupp2;

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
    exit(1);


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
}

int logoutClient()
{

}

int listClient(char* username, struct sockaddr_in srv_addr)
{
    
    int sock, ret;
    char buffer[BUF_LEN];
    sock = createSocket();

    if (connect(sock, (struct sockaddr*)&srv_addr, sizeof(srv_addr)) < 0) 
    {
        printf("\nConnection Failed \n");
        exit(1);
    }

    
    // SET LIST REQUEST BUFFER
    memset(buffer, 0, BUF_LEN);
    sprintf(buffer, "%s %s", LIST_REQUEST, username);
    buffer[BUF_LEN-1] = '\0';

    // HERE ADD CRYPTOGRAPHIC FUNCTION TO SET PROPERLY THE BUFFER
    printf("I'm sending %s\n", buffer);
    ret = send(sock, buffer, BUF_LEN, 0);
    if (ret == -1)
    {
        printf("Send operation gone bad\n");
        // Change this later to manage properly the session
        exit(1);
    }
    memset(buffer, 0, strlen(buffer));
    printf("List request message sent\n");
    ret = recv(sock, buffer, BUF_LEN,0);
    if (ret == -1)
    {
        printf("Receive operation gone bad\n");
        // Change this later to manage properly the session
        exit(1);
    }

    // HERE USE DECRYPTION TO UNDERSTAND WHAT YOU RECEIVE

    // END COMMUNICATION

    printf("%s\n", buffer);
    return 1;
}

int renameClient(char* username,char* filename, char* new_filename, struct sockaddr_in srv_addr)
{
    int sock, ret;
    char buffer[BUF_LEN];
    char bufferSupp1[BUF_LEN];
    char bufferSupp2[BUF_LEN];
    sock = createSocket();

    if (connect(sock, (struct sockaddr*)&srv_addr, sizeof(srv_addr)) < 0) 
    {
        printf("\nConnection Failed \n");
        exit(1);
    }


    //Add: show message when filename is to long to user --> check server side though. 

    // SANITIZE FILENAME AND NEW_FILENAME (VERY IMPORTANT)

    // SET RENAME REQUEST BUFFER
    memset(buffer, 0, strlen(buffer));
    printf("The new filename is %s\n\n", new_filename);
    sprintf(buffer, "%s %s %s %s", RENAME_REQUEST, username, filename, new_filename);
    printf("I'm sending to the server the mex %s\n\n", buffer);

    // HERE ADD CRYPTOGRAPHIC FUNCTION TO SET PROPERLY THE BUFFER

    ret = send(sock, buffer, strlen(buffer), 0);
    if (ret == -1)
    {
        printf("Send operation gone bad\n");
        // Change this later to manage properly the session
        exit(1);
    }
    memset(buffer, 0, strlen(buffer));
    printf("Rename request message sent\n");
    ret = recv(sock, buffer, BUF_LEN,0);
    if (ret == -1)
    {
        printf("Receive operation gone bad\n");
        // Change this later to manage properly the session
        exit(1);
    }

    // DECRYPT BUFFER TO UNDERSTAND WHAT IT IS WRITTEN

    sscanf(buffer, "%s %s", bufferSupp1, bufferSupp2); // The two values are the message type and eventually the reason why the request went bad
    
    // SANITIZE THE BUFFER

    if (strcmp(bufferSupp1, RENAME_DENIED) == 0)
    {
        printf("The rename request has been denied: %s\n\n", bufferSupp2);
        return 1;
    }
    else 
        if (strcmp(bufferSupp1, RENAME_ACCEPTED) == 0)
        {
           printf("The rename request has been accepted!\n\n");
           return 1;
        }
        else
        {
            printf("We don't know what the server said...\n\n");
            return -1;
        }
}



int deleteClient(char* username, char* filename, struct sockaddr_in srv_addr)
{        
    int sock, ret;
    char buffer[BUF_LEN];
    sock = createSocket();

    if (connect(sock, (struct sockaddr*)&srv_addr, sizeof(srv_addr)) < 0) 
    {
        printf("\nConnection Failed \n");
        exit(1);
    }

    
    // SET DELETE REQUEST BUFFER
    memset(buffer, 0, BUF_LEN);
    sprintf(buffer, "%s %s %s", DELETE_REQUEST, username, filename);
    buffer[BUF_LEN-1] = '\0';

    // HERE ADD CRYPTOGRAPHIC FUNCTION TO SET PROPERLY THE BUFFER
    ret = send(sock, buffer, BUF_LEN, 0);
    if (ret == -1)
    {
        printf("Send operation gone bad\n");
        // Change this later to manage properly the session
        exit(1);
    }
    printf("Delete request message sent\n");
    memset(buffer, 0, strlen(buffer));
    ret = recv(sock, buffer, BUF_LEN,0);
    if (ret == -1)
    {
        printf("Receive operation gone bad\n");
        // Change this later to manage properly the session
        exit(1);
    }

    // HERE USE DECRYPTION TO UNDERSTAND WHAT YOU RECEIVE

    // END COMMUNICATION

    printf("%s\n", buffer);
    return 1;
}

int downloadClient(char* username, char* filename, struct sockaddr_in srv_addr)
{
    int sock, ret, nchunk, i, j;
    char buffer[BUF_LEN];
    FILE* f1;
    char bufferSupp1[BUF_LEN];
    char bufferSupp2[BUF_LEN];
    char bufferSupp3[BUF_LEN];

    int position;

    sock = createSocket();

    if (chdir(MAIN_FOLDER_CLIENT) == -1)
	{
		printf("I'm having some problem with the change directory to the main folder of the software...\n\n");
	}
    f1 = fopen(filename, "r");
    if (f1 == NULL) printf("Starting the download...\n\n");
    else
    {
        fclose(f1);
        printf("Filename already exists. Download request over...\n\n");
        return -1;
    }

    if (connect(sock, (struct sockaddr*)&srv_addr, sizeof(srv_addr)) < 0) 
    {
        printf("\nConnection Failed \n");
        exit(1);
    }

    // SANITIZE FILENAME(VERY IMPORTANT)

    // SET DOWNLOAD REQUEST BUFFER
    memset(buffer, 0, strlen(buffer));
    sprintf(buffer, "%s %s %s", DOWNLOAD_REQUEST, username, filename);
    printf("I'm sending %s\n\n", buffer);

    // HERE ADD CRYPTOGRAPHIC FUNCTION TO SET PROPERLY THE BUFFER

    ret = send(sock, buffer, strlen(buffer), 0);
    if (ret == -1)
    {
        printf("Send operation gone bad\n");
        // Change this later to manage properly the session
        exit(1);
    }
    memset(buffer, 0, strlen(buffer));

    // I'm going to receive a messsage with this format: download_accepted username number_of_chunk

    ret = recv(sock, buffer, BUF_LEN, 0);
    if (ret == -1)
    {
        printf("Receive operation gone bad\n");
        // Change this later to manage properly the session
        exit(1);
    }
    printf("I'm receiving %s", buffer);
    sscanf(buffer, "%s %s", bufferSupp1, bufferSupp2); // bufferSupp3 = number_of_chunk
    nchunk = atoi(bufferSupp2);
    if (nchunk == 0)
    {
        printf("The number of chunk is 0, this means that the file is empty. Download refused!\n\n");
        return 1;
    }

    f1 = fopen(filename, "w");
    for (i; i < nchunk; i++)
    {
        printf("We are receiving the chunk number %i...\n\n", i);
        memset(buffer, 0, strlen(buffer));
        // I'm receveing a message with this format: download_chunk n_chunk payload
        ret = recv(sock, buffer, BUF_LEN, 0);
        if (ret == -1)
        {
            printf("Receive operation gone bad\n");
            // Change this later to manage properly the session
            exit(1);
        }
        //sscanf(buffer, "%s %s %s", bufferSupp1, bufferSupp2, bufferSupp3); // we receive: donwload_chunk filename payload
        memset(bufferSupp1, 0, strlen(bufferSupp1));
        memset(bufferSupp2, 0, strlen(bufferSupp2));
        memset(bufferSupp3, 0, strlen(bufferSupp3));
        sscanf(buffer, "%s %s", bufferSupp1, bufferSupp2);
        position = strlen(bufferSupp1) + strlen(bufferSupp2) + 2;
        for (j = 0; j < CHUNK_SIZE; j++)
        {
            bufferSupp3[j] = buffer[position+j];
        }
        bufferSupp3[j] = '\0';

        printf("The payload received is %s\n\n", bufferSupp3);
        
        
        // Now take the bufferSupp3 and append it to the file. When the loop is over we close the file and we got what we neededs
        printf("Now we append %s to the file...\n\n", bufferSupp3);
        fprintf(f1, "%s", bufferSupp3);
        //fwrite(bufferSupp3, 1, strlen(bufferSupp3), f1); //I append the payload to the file
        memset(bufferSupp1, 0, strlen(bufferSupp1));
        memset(bufferSupp2, 0, strlen(bufferSupp2));
        memset(bufferSupp3, 0, strlen(bufferSupp3));
    }
    fclose(f1);
    memset(buffer, 0, strlen(buffer));
    sprintf(buffer, "%s %s %s", DOWNLOAD_FINISHED, username, filename);
    printf("I'm sending %s\n\n", buffer);
    ret = send(sock, buffer, BUF_LEN, 0);
    if (ret == -1)
    {
        printf("Send operation gone bad\n");
        // Change this later to manage properly the session
        exit(1);
    }
    printf("Download completed!\n\n");
    return 1;
}

int uploadClient(char* username, char* filename, struct sockaddr_in srv_addr)
{
    // We received a message with this format: download_request username filenameù
    char buffer[BUF_LEN];
    char bufferSupp1[BUF_LEN];
    char bufferSupp2[BUF_LEN];
    char bufferSupp3[BUF_LEN];
    char payload[CHUNK_SIZE+1];
    struct stat st;
    int i, sock, nchunk, ret;
    FILE* fd;

    sock = createSocket();

    // SANIFICATION FILENAME
    if (chdir(MAIN_FOLDER_CLIENT) == -1)
    {
        printf("Main folder of the client unaccessible...\n\n");
        return -1;
    }
    if ((fd = fopen(filename, "r")) == NULL)
    {
        printf("The file doesn't exist\n\n");
        return -1;
    }
    else
    {
        if (connect(sock, (struct sockaddr*)&srv_addr, sizeof(srv_addr)) < 0) 
        {
            printf("\nConnection Failed \n");
            exit(1);
        }

        stat(filename, &st);
        nchunk = (st.st_size/CHUNK_SIZE)+1;

        memset(buffer, 0, strlen(buffer));
        memset(bufferSupp1, 0, strlen(bufferSupp1));
        memset(bufferSupp2, 0, strlen(bufferSupp2));
        sprintf(buffer, "%s %s %s %i", UPLOAD_REQUEST, username, filename, nchunk);

        // ENCRYPT THE BUFFER
        printf("I'm sending %s\n\n", buffer);
        ret = send(sock, buffer, strlen(buffer), 0);
        if (ret == -1)
        {
            printf("Send operation gone bad!\n\n");
            exit(1);
        }

        memset(buffer, 0, strlen(buffer));
        memset(bufferSupp1, 0, strlen(bufferSupp1));
        memset(bufferSupp2, 0, strlen(bufferSupp2));
        memset(bufferSupp3, 0, strlen(bufferSupp3));
        ret = recv(sock, buffer, BUF_LEN, 0);
        if (ret == -1)
        {
            printf("Receive operation gone bad!\n\n");
            exit(1);
        }
        printf("I received %s from the server\n\n", buffer);

        // DECRYPT THE BUFFER

        sscanf(buffer, "%s %s %s", bufferSupp1, bufferSupp2, bufferSupp3);
        if (strcmp(bufferSupp1, UPLOAD_ACCEPTED) != 0)
        {
            printf("Upload operation denied by the server!\n\n");
            return -1;
        }
    }
    fd = fopen(filename, "r");
    printf("I'm starting the upload operation...\n\n");
    // We should add another check about the fact that the file exists or not
    for (i = 0; i < nchunk; i++)
    {
        memset(buffer, 0, strlen(buffer));
        memset(bufferSupp1, 0, strlen(bufferSupp1));
        memset(bufferSupp2, 0, strlen(bufferSupp2));
        memset(bufferSupp3, 0, strlen(bufferSupp3));
        memset(payload, 0, strlen(payload));

        ret = fread(payload, CHUNK_SIZE, 1, fd);
        if (ret == -1)
        {
            printf("Problem during the reading of the file to upload... \n\n");
            return -1;
        }
        sprintf(buffer, "%s %s %s", UPLOAD_CHUNK, filename, payload); //Format of the message sent is: type_mex n_chunk
        printf("I'm sending %s\n\n", buffer);
        // ENCRYPT BUFFER

        ret = send(sock, buffer, strlen(buffer), 0);
        if (ret == -1)
        {
            printf("Problem during the send operation... \n\n");
            return -1;
        }
    }
    printf("Upload operation over... Waiting end communication from the server... \n\n");
    memset(buffer, 0, strlen(buffer));
    memset(bufferSupp1, 0, strlen(bufferSupp1));
    memset(bufferSupp2, 0, strlen(bufferSupp2));
    memset(bufferSupp3, 0, strlen(bufferSupp3));

    ret = recv(sock, buffer, BUF_LEN,0);
    if (ret == -1)
    {
        printf("Problem during the send operation... \n\n");
        return -1;
    }
    
    sscanf(buffer, "%s %s %s", bufferSupp1, bufferSupp2, bufferSupp3);
    if (!(strcmp(bufferSupp1, UPLOAD_FINISHED)==0) || !(strcmp(bufferSupp2, username)==0) || !(strcmp(bufferSupp3, filename)==0))
    {
        printf("Error in the last message sent: message of end upload\n\n");
        return -1;
    }
    printf("We have completed successfully the upload operation!\n\n");
    return 1;
}



int shareClient(char* username, char* filename, char* peername, struct sockaddr_in srv_addr)
{
    char buffer[BUF_LEN];
    char bufferSupp1[BUF_LEN];
    char bufferSupp2[BUF_LEN];
    char bufferSupp3[BUF_LEN];
    int sock, ret;

    sock = createSocket();

    memset(buffer, 0, strlen(buffer));
    memset(bufferSupp1, 0, strlen(bufferSupp1));
    memset(bufferSupp2, 0, strlen(bufferSupp2));
    memset(bufferSupp3, 0, strlen(bufferSupp3));

    if (connect(sock, (struct sockaddr*)&srv_addr, sizeof(srv_addr)) < 0) 
    {
        printf("\nConnection Failed \n");
        exit(1);
    }

    sprintf(buffer, "%s %s %s %s", SHARE_REQUEST, username, peername, filename);
    printf("I'm sending %s to the server\n\n", buffer);

    // ENCRYPT THE BUFFER

    ret = send(sock, buffer, strlen(buffer), 0);
    if (ret == -1)
    {
        printf("Error during send operation!\n\n");
        return -1;
    }

    memset(buffer, 0, strlen(buffer));
    memset(bufferSupp1, 0, strlen(bufferSupp1));
    memset(bufferSupp2, 0, strlen(bufferSupp2));
    memset(bufferSupp3, 0, strlen(bufferSupp3));
    ret = recv(sock, buffer, BUF_LEN,0);
    if (ret == -1)
    {
        printf("Error during receive operation!\n\n");
        return -1;
    }

    // DECRYPT THE BUFFER

    sscanf(buffer, "%s %s %s", bufferSupp1, bufferSupp2, bufferSupp3);
    if (strcmp(bufferSupp1, SHARE_ACCEPTED) == 0)
    {
        printf("Share operation accepted by the server!\n\n");
        return 1;
    }
    else printf("Share operation denied by the server!\n\n");
    return -1;
}


int shareReceivedClient(int sd, char* rec_mex)
{
    int ret, i;
    char* p;
    char buffer[BUF_LEN];
    char bufferSupp1[BUF_LEN];
    char bufferSupp2[BUF_LEN];
    char bufferSupp3[BUF_LEN];
    char filename[MAX_LEN_FILENAME];
    char sharername[MAX_LEN_USR];

    //DECRYPT REC_MEX, SANITIZE THE INPUT

    sscanf(rec_mex, "%s %s %s", bufferSupp1, sharername, filename);
    if (strcmp(bufferSupp1, SHARE_PERMISSION) != 0)
    {
        //printf("The mex type is incorrect!\n\n");
        return -1;
    }
    printf("We received a share request: the filename is %s from peer %s.\n Do you accept the share operation? [Y/N]\n\n", filename, sharername);
    //sscanf(buffer, "%s", stdin); // REMEMBER TO CHANGE PROPERLY THIS COMMAND
    while((strcmp(buffer, "Y")!=0) && (strcmp(buffer, "N")!=0))
    {
        if (fgets(buffer, BUF_LEN, stdin) == NULL)
        {
            printf("Some problem during the get function...\n\n");
            return -1;
        }
        p = strchr(buffer, '\n');
        if(p) {*p = '\0';}

        printf("Given in input %s", buffer);
        printf("\n"); 
        if(strcmp(buffer, "Y") == 0)
        {
            memset(buffer, 0, strlen(buffer));
            memset(bufferSupp1, 0, strlen(bufferSupp1));
            memset(bufferSupp2, 0, strlen(bufferSupp2));
            memset(bufferSupp2, 0, strlen(bufferSupp3));
            sprintf(buffer, "%s %s %s", SHARE_ACCEPTED, sharername, filename);
            ret = send(sd, buffer, strlen(buffer), 0);
            if (ret == -1)
            {
                printf("Send operation gone bad.\n\n");
                return -1;
            }
            return 1;
        }
        else if (strcmp(buffer, "N") == 0)
        {
            //test comment remove later not important just to test if git works for francesco
            memset(buffer, 0, strlen(buffer));
            memset(bufferSupp1, 0, strlen(bufferSupp1));
            memset(bufferSupp2, 0, strlen(bufferSupp2));
            memset(bufferSupp2, 0, strlen(bufferSupp3));
            sprintf(buffer, "%s %s %s", SHARE_DENIED, sharername, filename);
            ret = send(sd, buffer, strlen(buffer), 0);
            if (ret == -1)
            {
                printf("Send operation gone bad.\n\n");
                return -1;
            }
            return 1;
        }
        else printf("Given a bad input. Retry!\n\n");
        fflush(stdin);
    }
}