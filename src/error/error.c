#include "../include/error.h"

void errorHandler(int errorType){
    switch (errorType){
        case ARGUMENT:
            printf("Incorrect Argument\n");
            break;
        case SOCKET:
            printf("socket() error\n");
            break;
        case BIND:
            printf("bind() error\n");
            break;
        case LISTEN:
            printf("listen() error\n");
            break;
        case ACCEPT:
            printf("accept() error\n");
            break;
        case CONNECT:
            printf("connect() error\n");
            break;
        case READ:
            printf("read() error\n");
            break;
        default:
            break;
    }
    exit(0);
}