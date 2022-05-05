#include "../include/input.h"

int enterKey(){
    char message[BUF_SIZE];
    int ret;
    printf("\n");
    while(1){
        puts("Input message(go or Go) to send message.");
        puts("Input message(q or Q) to quit.");
        fgets(message,BUF_SIZE,stdin);
        if(!strcmp(message, "q\n") || !strcmp(message, "Q\n")){
            ret = 0;
            break;
        }
        else if(!strcmp(message,"go\n") || !strcmp(message, "Go\n")){
            ret=1;
            break;
        }
        puts("Wrong Input. Try again.");
    }
    printf("\n");
    return ret;
}