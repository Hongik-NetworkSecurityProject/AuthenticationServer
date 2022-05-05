#include "../include/printText.h"

void printAuthenticationMessage(uint8_t* authenticationMessage, int flag){
    int i,j;
    if(flag==PLAINTEXT)printf("\nAuthentication Cipher message : \n\t");
    if(flag==CIPHER)printf("\nAuthentication Plaintext message : \n\t");
    for(i=0, j=0; i<AUTH_MSG_SIZE;i++,j++, j%=PRINT_LINE_SIZE){
        printf("%02x", authenticationMessage[i]);
        if(j==PRINT_LINE_SIZE-1) printf("\n\t");
    }
    printf("\n");
}

void printCertificate(CERTIFICATE* certificate){
    int i,j;
    
    printf("\nCertificate : \n");
    printf("\tname : %s\n", certificate->name);
    printf("\tpublic key : \n%s\n", certificate -> publicKey);
    printf("\tsign : \t");
    for(i=0, j=0; i<sizeof(certificate->signature);i++,j++, j%=PRINT_LINE_SIZE){
        printf("%02x", certificate->signature[i]);
        if(j==PRINT_LINE_SIZE-1) printf("\n\t\t");
    }
    printf("\n");
}


void printCertificateHash(uint8_t* certificateHash){
    int i;
    printf("\nCertificate_hashed : ");
    for(i=0;i<HASH_SIZE; i++){
        printf("%02x", certificateHash[i]);
    }
    printf("\n\n");
}

void printChallenge(uint8_t* challenge){
    int i;
    printf("\nChallenge : ");
    for(i=0;i<CHALLENGE_SIZE;i++){
        printf("%02x", challenge[i]);
    }
    printf("\n\n");
}

void printClientConnection(){
    puts("==================================================");
    puts("\tConnected to New Client\t");
    puts("==================================================");
}

void printClientDisonnection(){
    puts("==================================================");
    puts("\tDisconnected to Client\t");
    puts("==================================================");
}

void printEncryptedSymmetricKey(uint8_t* symmetricKey1Encrypted){
    int i,j;
    printf("\nEncrypted symmetric key : \n\t");
    for(i=0, j=0;i<RSA_ENC_SIZE; i++,j++,j%=PRINT_LINE_SIZE){
        printf("%02x", symmetricKey1Encrypted[i]);
        if(j==PRINT_LINE_SIZE-1) printf("\n\t");
    }
    printf("\n");
}

void printEncryptedTokenMessage(uint8_t* tokenMessage){
    int i,j;
    printf("\nEncrypted Token Message : \n\t");
    for(i=0, j=0;i<MSG_SIZE; i++,j++,j%=PRINT_LINE_SIZE){
        printf("%02x", tokenMessage[i]);
        if(j==PRINT_LINE_SIZE-1) printf("\n\t");
    }
    printf("\n");
}

void printFileServerConnection(){
    puts("================================================");
    puts("\tConnected to File server\t");
    puts("================================================");
}

void printFileServerDisconnection(){
    puts("==================================================");
    puts("\tDisconnected to File Server\t");
    puts("==================================================");
}

void printInitialVector(uint8_t* initialVector){
    int i;
    printf("\nIV : ");
    for(i=0; i<AES_BLOCK_SIZE;i++){
        printf("%02x", initialVector[i]);
    }
    printf("\n\n");
}

void printSymmetricKey(uint8_t* symmetricKey1){
    int i;
    printf("\nSymmetric key : ");
    for(i=0; i<SYM_KEY_SIZE;i++){
        printf("%02x", symmetricKey1[i]);
    }
    printf("\n\n");
}

void printTimestamp(uint8_t* timestamp){
    int i;
    printf("\nTimestamp : ");
    for(i=0;i<TIMESTAMP_SIZE;i++){
        printf("%02x", timestamp[i]);
    }
    printf("\n\n");
}

void printToken(uint8_t* token, int flag){
    int i,j;
    if(flag==PLAINTEXT)printf("\nToken PlainText : \n\t");
    if(flag==CIPHER)printf("\nToken Cipher : \n\t");
    for(i=0, j=0;i<TOKEN_SIZE; i++,j++,j%=PRINT_LINE_SIZE){
        printf("%02x", token[i]);
        if(j==PRINT_LINE_SIZE-1) printf("\n\t");
    }
    printf("\n");
}
