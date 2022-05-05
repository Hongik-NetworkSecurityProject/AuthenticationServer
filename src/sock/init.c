#include "../include/init.h"
#include "../include/error.h"

int initServer(int *servSock,const char* argv){
    struct sockaddr_in servAddr;
    struct sigaction act;
    int state;

    act.sa_handler= readChildProcess;
    sigemptyset(&act.sa_mask);
    act.sa_flags=0;
    state=sigaction(SIGCHLD,&act,0);

    *servSock = socket(PF_INET, SOCK_STREAM, 0);
    if(*servSock == -1)
        errorHandling(SOCKET);
    
    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servAddr.sin_port = htons(atoi(argv));

    if(bind(*servSock, (struct sockaddr*)&servAddr, sizeof(servAddr))==-1)
        errorHandling(BIND);
    
    if(listen(*servSock, 5)==-1)
        errorHandling(LISTEN);

    return 1;
}

void readChildProcess(int sig){
    pid_t pid;
    int status;
    pid=waitpid(-1,&status,WNOHANG);
}

