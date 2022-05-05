#include "macro.h"
#include "openssl.h"


typedef enum _textType{
    PLAINTEXT,
    CIPHER
}TEXTTYPE;

typedef enum _keyType{
    SIZE_16,
    SIZE_32
}KEYTYPE;

BIO *outAuthenticationServer = NULL, *outCertificateAuthority = NULL;
RSA *rsaKeyAuthenticationServer = NULL, *rsaKeyCertificateAuthority = NULL;
EVP_PKEY *pkeyAuthenticationServer = NULL, *pkeyCertificateAuthority = NULL;

int generateRSAKey(RSA **rsaKey, BIO **out, EVP_PKEY **pKey);
int generateSymmetricKey(uint8_t *symmetric_key);

void encryptSymmetricKey(uint8_t* plainText, uint8_t* cipher, int SIZE, uint8_t* symmetricKey, uint8_t* initialVector);
void decryptSymmetricKey(uint8_t* cipher, uint8_t* plainText, int SIZE, uint8_t* symmetricKey, uint8_t* initialVector);

uint8_t* publicKeyToString(RSA *rsaPublicKey);
void rc4(uint8_t *inputKey,uint8_t *outputKey,int keyType);
