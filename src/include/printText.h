#ifndef __PRINTTEXT__
#define __PRINTTEXT__

#include <stdio.h>
#include <stdint.h>

#include "crypto.h"
#include "openssl.h"
#include "macro.h"


void printAuthenticationMessage(uint8_t* authenticationMessage, int flag);

void printCertificate(CERTIFICATE* cert);
void printCertificateHash(uint8_t* certificateHash);

void printChallenge(uint8_t* challenge);
void printClientConnection();
void printClientDisconnection();
void printEncryptedSymmetricKey(uint8_t* symmetricKey1Encrypted);
void printEncryptedTokenMessage(uint8_t* tokenMessage);

void printFileServerConnection();
void printFileServerDisconnection();

void printInitialVector(uint8_t* initialVector);


void printSymmetricKey(uint8_t* symmetricKey1);
void printTimestamp(uint8_t* timestamp);
void printToken(uint8_t* token, int flag);

#endif