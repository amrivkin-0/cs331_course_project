#include "stdint.h"

#define flake_size 1024
#define flakes_per_nug 256
#define PASSWORD "Master Secret Password" // Not how this should be done, but doesn't matter for performance
#define KEY_LEN crypto_box_SEEDBYTES

#define BYTES_FLAKE_TAG_OUT         16U // crypto_onetimeauth_poly1305_BYTES
#define BYTES_TJ_HASH_OUT           16U // crypto_onetimeauth_poly1305_BYTES
#define BYTES_FLAKE_TAG_KEY         32U // crypto_onetimeauth_poly1305_KEYBYTES; <= BLFS_CRYPTO_BYTES_KDF_OUT

void resetStore();

void seqReads();

void seqWrites();

void randReads();

void randWrites();

unsigned long roundUpNugget(unsigned long numToRound);

unsigned long roundDownFlake(unsigned long numToRound);

unsigned long roundUpFlake(unsigned long numToRound);

void rekey(int nugget_num);

void genKeyNugget(unsigned char* key, int nugget_index);

void printHelp();

void writeDisk(unsigned long startAddr, uint8_t *data, unsigned int length);

void writeDiskLen(unsigned long startAddr, unsigned int length);

void readDisk(unsigned long startAddr, unsigned long endAddr);

void readDiskDecrypt(unsigned long startAddr, unsigned long endAddr);

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext);
            
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext);

void writeDiskEncrypt(unsigned long startAddr, uint8_t *data, unsigned int length);

void writeDiskLenEncrypt(unsigned long startAddr, unsigned int length);

void init();