#ifndef __PHASE__
#define __PHASE__

#include <arpa/inet.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "security.h"
#include "crypto.h"
#include "error.h"
#include "init.h"
#include "input.h"
#include "macro.h"
#include "printText.h"

void phase0PreparationServer(int* fileSocket, uint8_t* symmetricKeyAuthenticationServerFileServer, int* serverSocket, RSA* rsaKeyAuthenticationServer);
void phase1SendChallenge(int* clientSock,uint8_t *challenge, CERTIFICATE **certificate, RSA* rsaKeyAuthenticationServer, RSA* rsaKeyCertificateAuthority);
void phase2VerifyUserAndMessage(int *clientSock, uint8_t *symmetricKey1, uint8_t * initialVector, uint8_t *challenge, uint8_t *id, USER **user ,RSA* rsaKeyAuthenticationServer);
void phase3SendToken(int* clientSock, uint8_t* initialVector, uint8_t* id, uint8_t* symmetricKey1, uint8_t* symmetricKeyAuthenticationServerFileServer, CERTIFICATE* certificate);

#endif