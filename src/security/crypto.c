#include "../include/crypto.h"

int generateRSAKey(RSA **rsaKey, BIO **out, EVP_PKEY **pKey){

    BIGNUM *bne=NULL;

	bne=BN_new();
	if(BN_set_word(bne, RSA_F4)!=1)
		return 0;

	*rsaKey=RSA_new();
	if(RSA_generate_key_ex(*rsaKey, RSA_LENGTH, bne, NULL)!=1)
	{
		BN_free(bne);
        printf("generateRsaKey error.\n");
		return FALSE;
	}

    // Print RSA key pair.
	*out=BIO_new_fp(stdout, BIO_CLOSE);  // allocate BIO for 'stdout'.
	*pKey=EVP_PKEY_new();
	EVP_PKEY_set1_RSA(*pKey, *rsaKey); // convert RSA structure to EVP_PKEY structure for printing key data.
    return TRUE;
}

int generateSymmetricKey(uint8_t *symmetricKey){
    uint8_t randomKey[SYM_KEY_SIZE];
    RAND_bytes(randomKey, sizeof(randomKey));
    rc4(randomKey, symmetricKey, SIZE_32);
    return TRUE;
}

void encryptSymmetricKey(uint8_t* plainText, uint8_t* cipher, int SIZE, uint8_t* symmetricKey, uint8_t* initialVector){
    AES_KEY key;
    AES_set_decrypt_key(symmetricKey, SYM_KEY_BIT, &key);
    AES_cbc_encrypt(plainText, cipher, SIZE, &key, initialVector, AES_ENCRYPT);
}

void decryptSymmetricKey(uint8_t* cipher, uint8_t* plainText, int SIZE, uint8_t* symmetricKey, uint8_t* initialVector){
    AES_KEY key;
    AES_set_decrypt_key(symmetricKey, SYM_KEY_BIT, &key);
    AES_cbc_encrypt(cipher, plainText, SIZE, &key, initialVector, AES_DECRYPT);
}


uint8_t* publicKeyToString(RSA *rsaPublicKey){
    BIO *public = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(public,rsaPublicKey);
   
    size_t publicLength = BIO_pending(public);
    char *publicKeyString = malloc(publicLength + 1);

    BIO_read(public, publicKeyString, (int)publicLength);
    publicKeyString[publicLength] = '\0';

    return publicKeyString;
}

void rc4(unsigned char *inputKey,unsigned char *outputKey,int keyType){
    RC4_KEY *rc4Key = (RC4_KEY*)malloc(sizeof(RC4_KEY));
    switch(keyType){
        case SIZE_16:
            RC4_set_key(rc4Key, CHALLENGE_SIZE, inputKey);
            RC4(rc4Key, CHALLENGE_SIZE, inputKey, outputKey);
            break;
        case SIZE_32:
            RC4_set_key(rc4Key, SYM_KEY_SIZE, inputKey);
            RC4(rc4Key, SYM_KEY_SIZE, inputKey, outputKey);
            break;
    }
    free(rc4Key);
}

