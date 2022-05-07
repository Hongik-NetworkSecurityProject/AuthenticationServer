#include "../include/security.h"

int authenticateUser(uint8_t* id,uint8_t* passwordHash,USER* user){
    for(int i=0;i<USER_NUM;i++){
        if(!strcmp(user[i].id, id)){
            for(int j=0; j<HASH_SIZE; j++){
                if(user[i].passwordHash[j] != passwordHash[j]){
                    printf("Phase 2 :: password incorret.\n");
                    return FALSE;
                }
            }
        }
    }
    printf("Phase 2 :: cannot find user.\n");
    return 0;
}
void encryptTokenMessage(uint8_t* encrypedTokenMessage, uint8_t* symmetricKey1, uint8_t* initialVectorUse, uint8_t* token, 
                uint8_t* symmetricKey2, uint8_t* certificateHash){
    
    uint8_t tokenMessage[MSG_SIZE];

    for(int i=0;i<TOKEN_SIZE;i++)
        tokenMessage[i]=token[i];

    for(int i=TOKEN_SIZE,j=0;i<TOKEN_SIZE+SYM_KEY_SIZE;i++,j++)
        tokenMessage[i]=symmetricKey2[j];

    for(int i=TOKEN_SIZE+SYM_KEY_SIZE,j=0;i<MSG_SIZE;i++,j++)
        tokenMessage[i]=certificateHash[j];

    encryptSymmetricKey(tokenMessage, encryptTokenMessage, MSG_SIZE, symmetricKey1, initialVectorUse);
}

void getInformation(uint8_t* authenticationMessagePlainText, uint8_t* id, uint8_t* passwordHash, uint8_t* receiveChallenge){

    for(int i=0; i<ID_SIZE;++i){
        id[i] = authenticationMessagePlainText[i];
    }
    int paddingLength = id[ID_SIZE-1];
    for(int i=ID_SIZE-paddingLength-1;i<ID_SIZE;i++){
        id[i]='\0';
    }

    for(int i=ID_SIZE, j=0; i<ID_SIZE+HASH_SIZE;++i,++j){
        passwordHash[j] = authenticationMessagePlainText[i];
    }
    for(int i=ID_SIZE+HASH_SIZE, j=0; i<AUTH_MSG_SIZE;++i,++j){
        receiveChallenge[j] = authenticationMessagePlainText[i];
    }

}

void makeChallenge(uint8_t *challenge){
    uint8_t randomChallenge[CHALLENGE_SIZE];
    RAND_bytes(randomChallenge, sizeof(randomChallenge));
    rc4(randomChallenge, challenge, SIZE_16);
}

void makeCertificate(CERTIFICATE **certificate, RSA *rsaKeyAuthenticationServer, RSA *rsaKeyCertificateAuthority)
{   
    uint8_t signature[RSA_ENC_SIZE];
    uint8_t info[BUF_SIZE];

    uint8_t *publicKey = publicKeyToString(rsaKeyAuthenticationServer);
    
    strcpy((*certificate)->name, "Auth Server");
    for(int i=0; i<RSA_PUB_KEY_SIZE;++i)
        (*certificate) -> publicKey[i] = publicKey[i];
    
    int name_size = strlen((*certificate) -> name);
    int public_key_size = strlen((*certificate) -> publicKey);

    strcat(info, (*certificate) -> name);
    strcat(info, (*certificate) -> publicKey); // "Auth server" || pu(as)
    
    uint8_t infoHash[HASH_SIZE];
    SHA256(info, strlen(info), infoHash); // h("Auth server" || pu(as))
    
    int signatureLength = RSA_private_encrypt(sizeof(infoHash), infoHash, signature, rsaKeyCertificateAuthority, RSA_PKCS1_PADDING);
    for(int i=0; i < signatureLength; ++i)
        (*certificate) -> signature[i] = signature[i];
}

void makeTimestamp(uint8_t* timestamp){
    time_t t;
    struct tm *localTime;

    time(&t);
    localTime = localtime(&t);
    timestamp[0]=localTime->tm_year;
    timestamp[1]=localTime->tm_mon;
    timestamp[2]=localTime->tm_mday;
    timestamp[3]=localTime->tm_hour;
    timestamp[4]=localTime->tm_min;

    for(int i=5;i<TIMESTAMP_SIZE;i++)
        timestamp[i]='\0';
}

void makeToken(uint8_t* id, uint8_t* initialVectorUse, uint8_t* symmetricKey2, uint8_t* symmetricKeyAuthenticationServerFileServer, uint8_t* token){
    uint8_t timestamp[CHALLENGE_SIZE];
    uint8_t plaintext[TOKEN_SIZE];

    makeTimestamp(timestamp);

    for(int i=0;i<ID_SIZE;i++)
        plaintext[i]=id[i];
    
    for(int i=ID_SIZE,j=0;i<ID_SIZE+TIMESTAMP_SIZE;i++,j++)
        plaintext[i]=timestamp[j];
    
    for(int i=ID_SIZE+CHALLENGE_SIZE,j=0;i<TOKEN_SIZE;i++,j++)
        plaintext[i]=symmetricKey2[j];
    
    printToken(plaintext,PLAINTEXT);
    encryptSymmetricKey(plaintext, token, TOKEN_SIZE, symmetricKeyAuthenticationServerFileServer, initialVectorUse);
}


int verifyAuthenticationMessage(uint8_t *receiveChallenge, uint8_t *challenge){
    for(int i=0; i<CHALLENGE_SIZE; ++i){
        if(receiveChallenge[i] != challenge[i])
            return FALSE;
    }
    return TRUE;
}