#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int askCertClient() {
    
    /* Terminal asks for the File Location of the Certificate File.
        User then provides it using the scanf
        

        to:do prevent overflows, e.g. when file location is > 300
        */
    printf("Please provide the location Security Certificate in order to Login:\n");
    char fileLocation[300];
    scanf("%s", fileLocation);
    
    /*Opens file

    to do: prevent overflows
        */

    FILE* ptr;
    char str[500];
    ptr = fopen(fileLocation, "a+");
    if (NULL == ptr) {
        printf("file can't be opened \n");
    }

    /* reads the content of the file
        todo: prevent overlows
        */

    fgets(str, 501, ptr);

    /* verifies that legth of str is 128. I do not know why I need to make != 130 then but ok. 

        If the str is not 128 chars longs, a error message is given to the Client. The entire method then repeats by calling it again (I do not know if you should call this way, we need to figure out)

        */

    if(strlen(str) != 130) {
        printf("This is the wrong file / File is corrupted.\nPlease try again. \n");
        askCertClient();
    } else {
        printf("Trying to Log you in. \n");
    }
 
    fclose(ptr);
    return 0;

}