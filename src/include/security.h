#ifndef __SECURITY__
#define __SECURITY__

#include "crypto.h"
#include "init.h"
#include "macro.h"
#include "time.h"
#include "printText.h"

int authenticateUser(uint8_t* id,uint8_t* passwordHash, USER* user);
void encryptTokenMessage(uint8_t* encrypedTokenMessage, uint8_t* symmetricKey1, uint8_t* initialVectorUse, uint8_t* token, 
                uint8_t* symmetricKey2, uint8_t* certificateHash);
void getInformation(uint8_t* authenticationMessagePlainText, uint8_t* id, uint8_t* passwordHash, uint8_t* receiveChallenge);

void makeChallenge(uint8_t *challenge);
void makeCertificate(CERTIFICATE **certificate, RSA *rsaKeyAuthenticationServer, RSA *rsaKeyCertificateAuthority);
void makeTimestamp(uint8_t* timestamp);
void makeToken(uint8_t* id, uint8_t* initialVectorUse, uint8_t* symmetricKey2, uint8_t* symmetricKeyAuthenticationServerFileServer, uint8_t* token);

int verifyAuthenticationMessage(uint8_t *receiveChallenge, uint8_t *challenge);

#endif