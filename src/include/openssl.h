#include "macro.h"

#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rc4.h>
#include <openssl/rand.h>

typedef struct _certificate{
    uint8_t name[NAME_SIZE];
    uint8_t publicKey[RSA_PUB_KEY_SIZE];
    uint8_t signature[RSA_ENC_SIZE];
}CERTIFICATE;

typedef enum _keyType{
    SIZE_16,
    SIZE_32
}KEYTYPE;