#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int askCertClient() {
    printf("Please provide the location Security Certificate in order to Login:\n");
    
    char fileLocation[300];
    scanf("%s", fileLocation);
    
    FILE* ptr;
    char str[500];
    ptr = fopen(fileLocation, "a+");

    if (NULL == ptr) {
        printf("file can't be opened \n");
    }
 
    fgets(str, 501, ptr);

    if(strlen(str) != 130) {
        printf("This is the wrong file / File is corrupted.\nPlease try again. \n");
        askCertClient();
    } else {
        printf("Trying to Log you in. \n");
    }
 
    fclose(ptr);
    return 0;

}