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
        errorHandler(SOCKET);
    
    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servAddr.sin_port = htons(atoi(argv));

    if(bind(*servSock, (struct sockaddr*)&servAddr, sizeof(servAddr))==-1)
        errorHandler(BIND);
    
    if(listen(*servSock, CLIENT_NUM) ==-1)
        errorHandler(LISTEN);

    return TRUE;
}

int initUserInfo(USER* user){

    FILE* fpUserId = NULL;
    FILE* fpUserPassword = NULL;

    if(chdir("./db")==-1){
        puts("Phase 0 :: Cannot open directory \"db\".");
        return FALSE;
    }

    if((fpUserId = fopen("userID.txt", "r"))==NULL){
        printf("Phase 0 :: Cannot open file \"userID.txt\".\n");
        return FALSE;
    }

    if((fpUserPassword = fopen("userPassword.txt", "r"))==NULL){
        printf("Phase 0 :: Cannot open file \"userPassword.txt\".\n");
        return FALSE;
    }

    for(int i=0; i< USER_NUM; i++){
        fgets(user[i].id,ID_SIZE,fpUserId);        
        fgets(user[i].passwordHash, HASH_SIZE, fpUserPassword);
        SHA256(user[i].passwordHash, strlen(user[i].passwordHash), user[i].passwordHash);
    }
    fclose(fpUserId);
    fclose(fpUserPassword);
    chdir("..");
    return TRUE;
}

void readChildProcess(int sig){
    pid_t pid;
    int status;
    pid=waitpid(-1,&status,WNOHANG);
}

