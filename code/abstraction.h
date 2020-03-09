#include "stdint.h"

#define flake_size 1024
#define flakes_per_nug 256
#define PASSWORD "Master Secret Password"
#define KEY_LEN crypto_box_SEEDBYTES

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