#include "../include/phase.h"

void phase0PreparationServer(int* fileSocket, uint8_t* symmetricKeyAuthenticationServerFileServer, int* serverSocket){
    struct sockaddr_in fsAddr;
    socklen_t fsAddrSize = sizeof(fsAddr);

    *fileSocket = accept(*serverSocket, (struct sockaddr*)&fsAddr, &fsAddrSize);

    if(*fileSocket == -1) errorHandler(ACCEPT);

    printFileServerConnection();

    puts("Phase 0 :: Send AS_public key to file server.");
    uint8_t *asPublic = publicKeyToString(rsaKeyAuthenticationServer);
    int asPublicSize = strlen(asPublic);

    uint8_t symmetricKeyAuthenticationServerFileServerEncrypted[RSA_ENC_SIZE];

    write(*fileSocket, &asPublicSize, sizeof(int));
    write(*fileSocket, asPublic, asPublicSize);

    printf("public key : %s\n", asPublic);

    read(*fileSocket, symmetricKeyAuthenticationServerFileServerEncrypted, RSA_ENC_SIZE);
     
    puts("Phase 0 :: Encrypted symmetric key received.");
    printEncryptedSymmetricKey(symmetricKeyAuthenticationServerFileServerEncrypted);

    puts("Phase 0 :: Decrypt encrypted symmetric key.");
    rsaPrivateDecrypt(RSA_ENC_SIZE, symmetricKeyAuthenticationServerFileServerEncrypted, symmetricKeyAuthenticationServerFileServer, rsaKeyAuthenticationServer, RSA_PKCS1_PADDING);
    printSymmetricKey(symmetricKeyAuthenticationServerFileServer);

    close(*fileSocket);
    printFileServerDisconnection();
}

void phase1SendChallenge(int* clientSock,uint8_t *challenge, CERTIFICATE **certificate){
    uint8_t encryptedTokenMessage[BUF_SIZE];
    read(*clientSock, encryptedTokenMessage, sizeof(NEED_TOKEN_MSG));
    
    if(strcmp(encryptedTokenMessage, NEED_TOKEN_MSG) != 0){
        puts("Phase 1 :: It's not a reqeust encryptedTokenMessage.");
        printClientDisconnection();
        exit(0);
    }
    puts("Phase 1 :: Request encryptedTokenMessage received.");

    puts("Phase 1 :: Make Challenge.");
    makeChallenge(challenge);
    printChallenge(challenge);

    puts("Phase 1 :: Make Certificate.");
    makeCertificate(certificate,rsaKeyAuthenticationServer, rsaKeyCertificateAuthority);
    printCertificate(*certificate);

    if(enterKey()==0) {
        printClientDisconnection();
        exit(0);
    }
    
    uint8_t *caPublic = publicKeyToString(rsaKeyCertificateAuthority);
    int caPublicSize = strlen(caPublic);
    
    write(*clientSock, &caPublicSize, sizeof(int));
    write(*clientSock, caPublic, caPublicSize);
    write(*clientSock,challenge,CHALLENGE_SIZE);
    puts("Phase 1 :: Challenge sended.");

    if(send(*clientSock, *certificate, sizeof(CERTIFICATE), 0) == -1){
        puts("send() error");
        printClientDisconnection();
        exit(0);
    }
    puts("phase 1 :: Certificate sended.");
    
    free(caPublic);
    puts("==================================================");

}

void phase2VerifyUserAndMessage(int *clientSock, uint8_t *symmetricKey1, uint8_t * initialVector, uint8_t *challenge, uint8_t *id, USER **user){
    uint8_t symmetricKey1Encrypted[RSA_ENC_SIZE];
    uint8_t authenticationMessageCipher[AUTH_MSG_SIZE];
    uint8_t authenticationMessagePlainText[AUTH_MSG_SIZE];
    uint8_t passwordHash[HASH_SIZE];
    uint8_t receiveChallenge[CHALLENGE_SIZE];
    uint8_t initialVectorUse[AES_BLOCK_SIZE];

    read(*clientSock, initialVector, AES_BLOCK_SIZE);
    puts("Phase 2 :: IV received.");
    printInitialVector(initialVector);
    memcpy(initialVectorUse,initialVector,AES_BLOCK_SIZE);

    read(*clientSock, symmetricKey1Encrypted, RSA_ENC_SIZE);
    puts("Phase 2 :: Encrypted symmetric key received.");
    printEncryptedSymmetricKey(symmetricKey1Encrypted);

    // decrypt encrypted symmetric key .
    puts("Phase 2 :: Decrypt encrypted symmetric key.");
    rsaPrivateDecrypt(RSA_ENC_SIZE, symmetricKey1Encrypted, symmetricKey1, rsaKeyAuthenticationServer, RSA_PKCS1_PADDING);
    printSymmetricKey(symmetricKey1);

    read(*clientSock, authenticationMessageCipher, AUTH_MSG_SIZE);
    puts("Phase 2 :: Authentication encryptedTokenMessage received.");
    printAuthenticationMessage(authenticationMessageCipher,CIPHER);

    // decrypt Authentication encryptedTokenMessage.
    puts("Phase 2 :: Decrypt authentication encryptedTokenMessage.");
    decryptSymmetricKey(authenticationMessageCipher, authenticationMessagePlainText, AUTH_MSG_SIZE, symmetricKey1, initialVectorUse);
    printAuthenticationMessage(authenticationMessagePlainText,PLAINTEXT);

    getInformation(authenticationMessagePlainText, id, passwordHash, receiveChallenge);

    puts("Phase 2 :: Verify challenge.");
    if(verifyAuthenticationMessage(receiveChallenge, challenge)==0){
        puts("Verification failed.");
        printClientDisconnection();
        exit(0);
    }

    puts("Phase 2 :: Verification success.");
    puts("Phase 2 :: User authentication start.");

    if(authenticateUser(id,passwordHash,*user)==0){
        puts("User authentication failed.");
        printClientDisconnection();
        exit(0);
    }
    puts("Phase 2 :: User authentication success.");
    puts("==================================================");
}

void phase3SendToken(int* clientSock, uint8_t* initialVector, uint8_t* id, uint8_t* symmetricKey1, uint8_t* symmetricKeyAuthenticationServerFileServer, CERTIFICATE* certificate){
    uint8_t symmetricKey2[SYM_KEY_SIZE];
    uint8_t token[TOKEN_SIZE];
    uint8_t encryptedTokenMessage[MSG_SIZE];
    uint8_t certificateHash[HASH_SIZE];
    uint8_t initialVectorUse[AES_BLOCK_SIZE];

    puts("Phase 3 :: Make symmetric key.");
    if(!generateSymmetricKey(symmetricKey2)){
        printf("generate Symmetric key error.\n");
		exit(1);
    }
    printSymmetricKey(symmetricKey2);

    puts("Phase 3 :: Make Token.");
    memcpy(initialVectorUse, initialVector, AES_BLOCK_SIZE);
    makeToken(id, initialVectorUse, symmetricKey2, symmetricKeyAuthenticationServerFileServer, token);
    printToken(token, CIPHER);

    puts("Phase 3 :: Hash certificate.");
    SHA256((const uint8_t*)certificate,sizeof(CERTIFICATE),certificateHash);
    printCertificateHash(certificateHash);

    puts("Phase 3 :: Encrypt token message.");
    memcpy(initialVectorUse,initialVector,AES_BLOCK_SIZE);
    encryptTokenMessage(encryptedTokenMessage, symmetricKey1,initialVectorUse, token, symmetricKey2, certificateHash);
    
    printEncryptedTokenMessage(encryptedTokenMessage);

    if(enterKey()==0) {
        printClientDisconnection();
        exit(0);
    }

    write(*clientSock, encryptedTokenMessage, MSG_SIZE);
    puts("Phase 3 :: Encrypted token message sended.");
}