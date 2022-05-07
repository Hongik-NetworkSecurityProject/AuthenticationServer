#include "src/include/init.h"
#include "src/include/macro.h"
#include "src/include/error.h"
#include "src/include/openssl.h"
#include "src/include/phase.h"
#include "src/include/printText.h"

int main(int argc, const char *argv[])
{
    int servSock, fileSock ,clntSock;
    struct sockaddr_in clntAddr;
    socklen_t clntAddrSize;
    pid_t pid;

    uint8_t challenge[CHALLENGE_SIZE];
    uint8_t id[ID_SIZE];
    uint8_t initialVector[AES_BLOCK_SIZE];
    uint8_t symmetricKey1[SYM_KEY_SIZE];
    uint8_t symmetricKeyAuthenticationServerFileServer[SYM_KEY_SIZE];

    CERTIFICATE *certificate = NULL;

    BIO *outAuthenticationServer = NULL, *outCertificateAuthority = NULL;
    RSA *rsaKeyAuthenticationServer = NULL, *rsaKeyCertificateAuthority = NULL;
    EVP_PKEY *pkeyAuthenticationServer = NULL, *pkeyCertificateAuthority = NULL;

    if(argc !=2){
        printf("Usage: %s <authentication server port>\n", argv[0]);
        errorHandler(ARGUMENT);
    }

    // generage rsa key for AS and CA
    if(!generateRSAKey(&rsaKeyAuthenticationServer, &outAuthenticationServer, &pkeyAuthenticationServer))
	{
		printf("generate RSA key error.\n");
		exit(1);
	}

    if(!generateRSAKey(&rsaKeyCertificateAuthority, &outCertificateAuthority, &pkeyCertificateAuthority)){
        printf("generate RSA key error.\n");
		exit(1);
    }

    certificate = (CERTIFICATE*)malloc(sizeof(CERTIFICATE));
    USER *user = (USER*)malloc(sizeof(USER) * USER_NUM);
    
    initServer(&servSock,argv[1]);
    if(!initUserInfo(user)){
        printf("user info loaded error.\n");
        exit(1);
    }

    phase0PreparationServer(&fileSock,symmetricKeyAuthenticationServerFileServer, &servSock, rsaKeyAuthenticationServer);
    
    while(1){
        clntAddrSize = sizeof(clntAddr);
        clntSock = accept(servSock, (struct sockaddr*)&clntAddr, &clntAddrSize);
        if(clntSock == -1) continue;
        else printClientConnection();

        pid = fork();
        if(pid==-1) {
            printClientDisconnection();
            close(clntSock);
        }
        if(pid==0){
            close(servSock);

            phase1SendChallenge(&clntSock, challenge, &certificate, rsaKeyAuthenticationServer , rsaKeyCertificateAuthority);
            phase2VerifyUserAndMessage(&clntSock, symmetricKey1, initialVector, challenge,id, &user, rsaKeyAuthenticationServer);
            phase3SendToken(&clntSock, initialVector, id, symmetricKey1, symmetricKeyAuthenticationServerFileServer, certificate);
            printClientDisconnection();
            close(clntSock);
            return 0;
        }
        else{
            close(clntSock);
        }
    }
    close(servSock);
    free(certificate);
    return 0;
}