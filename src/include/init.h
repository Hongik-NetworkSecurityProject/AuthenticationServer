#include <arpa/inet.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include "macro.h"

typedef struct __user_info{
    uint8_t id[ID_SIZE];
    uint8_t passwordHash[HASH_SIZE];
}USER;

int initServer(int *servSock,const char* argv);
int initUserInfo(USER* user);
void readChildProcess(int sig);