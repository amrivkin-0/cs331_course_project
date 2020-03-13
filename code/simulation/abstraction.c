#include <abstraction.h>
#include <stdio.h>
#include <stdio.h> 
#include <stdlib.h> 
#include <time.h>
#include "stdbool.h"
#include "string.h"
#include <sodium.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
// #include "merkle.h"

FILE *disk_sim;
FILE *backing_store;
int nugs_per_mem;
int keycount_length; // in bytes
int transaction_length; // in bytes
int mem_size;

const EVP_CIPHER *cipher;
bool encryption;
bool randomize;

void init(){
    if (sodium_init() < 0) {
        printf("Could not init libsodium\n");
    }
    cipher = EVP_chacha20(); // EVP_aes_256_ctr, EVP_aes_256_ofb, EVP_aes_256_xts
    // unsigned char* key = calloc(1, KEY_LEN);
    // password_to_secret(key, 0);
    // printf("Key: %s\n", key);
    // free(key);
    srand(time(0));
    disk_sim = fopen("disk_sim.bin", "rb+");
    backing_store = fopen("backing_store.bin", "rb+");
    fseek(disk_sim, 0L, SEEK_END);
    mem_size = ftell(disk_sim);
    printf("Memory size: %i\n", mem_size);
    nugs_per_mem = (int) mem_size / (flake_size * flakes_per_nug);
    printf("Nuggets in memory: %i\n", nugs_per_mem);
    fseek(backing_store, 0L, SEEK_END);
    int backing_store_size = ftell(backing_store);
    printf("Backing store size: %i\n", backing_store_size);
    keycount_length = 8 * nugs_per_mem;
    transaction_length = (int) flakes_per_nug * nugs_per_mem / 8;
    encryption = true;
    randomize = false;
    return;
}


void resetStore(){
    int flake_start_num = 0;
    int flake_end_num = flakes_per_nug * nugs_per_mem;
    for(int flake_num = flake_start_num; flake_num < flake_end_num; flake_num++){
        fseek(backing_store, keycount_length + flake_num, SEEK_SET);
        fputc('0', backing_store);
    }
}

void printHelp(){
    printf("Commands:\n");
    printf("    help - Prints the program\'s commands\n");
    printf("    read startAddr endAddr - Reads the data stored in the file between startAddr and endAddr\n");
    printf("    readBox startAddr endAddr - Decrypts eads the data stored in the file between startAddr and endAddr\n");
    printf("    write startAddr data - Writes data to the file starting from startAddr\n");
    printf("    writeRand startAddr length - Writes random bytes to the file starting from startAddr\n");
    printf("    writeBox startAddr data - Encrypts and writes data to the file starting from startAddr\n");
    printf("    writeRandBox startAddr length - Encrypts and writes random bytes to the file starting from startAddr\n");
    printf("    runTests - runs all performance tests and prints the results\n");
    printf("    switchChaCha - Use the ChaCha20 cipher\n");
    printf("    switchXTS - Use AES-XTS\n");
    printf("    switchCTR - Use AES-CTR\n");
    printf("    switchOFB - Use AES-OFB\n");
    printf("    switchUnencrypted - Turn off encryption\n");
    printf("    resetStore - resets the backing store transaction journal\n");
    printf("    tinyRandReads - 4k random reads\n");
    printf("    tinyRandWrites - 4k random writes\n");
    printf("    smallRandReads - 512k random reads\n");
    printf("    smallRandWrites - 512k random writes\n");
    printf("    mediumRandReads - 4m random reads\n");
    printf("    mediumRandWrites - 4m random writes\n");
    printf("    largeRandReads - 40m random reads\n");
    printf("    largeRandWrites - 40m random writes\n");
    printf("    tinySeqReads - 4k sequential reads\n");
    printf("    tinySeqWrites - 4k sequential writes\n");
    printf("    smallSeqReads - 512k sequential reads\n");
    printf("    smallSeqWrites - 512k sequential writes\n");
    printf("    mediumSeqReads - 4m sequential reads\n");
    printf("    mediumSeqWrites - 4m sequential writes\n");
    printf("    largeSeqReads - 40m sequential reads\n");
    printf("    largeSeqWrites - 40m sequential writes\n");
}



void seqReads(unsigned long size){
    clock_t t; 
    t = clock(); 
    unsigned long startAddr = 0;
    unsigned long endAddr = size;
    for(int i = 0; i < 30; i++){
        readDiskDecrypt(startAddr, endAddr);
        startAddr += size;
        endAddr += size;
    }
    t = clock() - t; 
    double time_taken = ((double)t)/CLOCKS_PER_SEC; // in seconds 
    printf("%lu SeqReads took %f seconds to execute \n", size, time_taken); 
}

void seqWrites(unsigned long size){
    clock_t t; 
    t = clock();
    unsigned long startAddr = 0;
    unsigned int length = size;
    for(int i = 0; i < 30; i++){
        writeDiskLenEncrypt(startAddr, length);
        startAddr += size;
    }
    t = clock() - t; 
    double time_taken = ((double)t)/CLOCKS_PER_SEC; // in seconds 
    printf("%lu SeqWrites took %f seconds to execute \n", size, time_taken); 
}


void randReads(unsigned long size){
    clock_t t; 
    t = clock();
    unsigned long startAddr;
    unsigned long endAddr;
    for(int i = 0; i < 30; i++){
        startAddr = rand() % (mem_size - size);
        endAddr = startAddr + size;
        readDiskDecrypt(startAddr, endAddr);
    }
    t = clock() - t; 
    double time_taken = ((double)t)/CLOCKS_PER_SEC; // in seconds 
    printf("%lu RandReads took %f seconds to execute \n", size, time_taken); 
}

void randWrites(unsigned long size){
    clock_t t; 
    t = clock();
    unsigned long startAddr;
    unsigned int length = size;
    for(int i = 0; i < 30; i++){
        startAddr = rand() % (mem_size - size);
        writeDiskLenEncrypt(startAddr, length);
    }
    t = clock() - t; 
    double time_taken = ((double)t)/CLOCKS_PER_SEC; // in seconds 
    printf("%lu RandWrites took %f seconds to execute \n", size, time_taken); 
}

uint64_t rand_uint64(void) {
  uint64_t r = 0;
  for (int i=0; i<64; i += 30) {
    r = r*((uint64_t)RAND_MAX + 1) + rand();
  }
  return r;
}


void genKeyNugget(unsigned char* key, int nugget_index)
{
    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char tmpkey[KEY_LEN];
    char nuggetString[5];
    sprintf(nuggetString, "%d", nugget_index);
    char tmpPass[64];
    strcpy(tmpPass, PASSWORD);
    strcat(tmpPass, nuggetString);
    // printf("TmpPass: %s\n", tmpPass);
    if(crypto_pwhash(tmpkey, sizeof tmpkey, tmpPass, strlen(tmpPass), salt,
                     crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_DEFAULT) != 0)
    {
        printf("Problem\n");
    }
    // printf("TmpKey: %s\n", tmpkey);
    strcpy(key, tmpkey);
    // return key;
}


unsigned long roundUpNugget(unsigned long numToRound)
{
    unsigned long remainder = numToRound % 262144;
    if (remainder == 0)
        return numToRound;
    return numToRound + 262144 - remainder;
}

unsigned long roundUpFlake(unsigned long numToRound)
{
    unsigned long remainder = numToRound % 1024;
    if (remainder == 0)
        return numToRound;
    return numToRound + 1024 - remainder;
}

unsigned long roundDownFlake(unsigned long numToRound)
{
    unsigned long remainder = numToRound % 1024;
    if (remainder == 0)
        return numToRound;
    return numToRound - remainder;
}


void readDiskDecrypt(unsigned long startAddr, unsigned long endAddr){
    unsigned int length = (unsigned int) endAddr - startAddr;
    if(length <= 0){
        return;
    }
    int nugget_num_start = (int) startAddr / (flake_size * flakes_per_nug);
    int nugget_num_end = (int) startAddr / (flake_size * flakes_per_nug);
    // int flake_num = (int)((startAddr % (flake_size * flakes_per_nug)) / flake_size);
    // int nugget_index = ;
    
    for(int nugget_num = nugget_num_start; nugget_num <= nugget_num_end; nugget_num++){
        unsigned long single_start = 0;
        unsigned long single_length = 0;
        if(nugget_num_end == nugget_num_start){
            single_start = roundDownFlake(startAddr);
            single_length = length + (roundUpFlake(endAddr) - endAddr);
        } else if(nugget_num == nugget_num_start){
            single_start = roundDownFlake(startAddr);
            single_length = roundUpNugget(startAddr) - startAddr;
        } else if(nugget_num == nugget_num_end){
            single_start = roundUpNugget(startAddr) + ((nugget_num - nugget_num_start - 1) * 262144);
            single_length = roundUpFlake(endAddr) - single_start;
        } else {
            single_start = roundUpNugget(startAddr) + ((nugget_num - nugget_num_start - 1) * 262144);
            single_length = 262144;
        }
        fseek(backing_store, nugget_num * 8, SEEK_SET);
        unsigned char *nonce = calloc(1, 8);
        fread(nonce, 8, 1, backing_store);
        
        // printf("Nonce: %s\n", nonce);
        // for(unsigned int i = 0; i < 8; i++) {
            // printf("%02X", *(nonce + i));
        // }
        // printf("\n");
        
        fseek(disk_sim, single_start, SEEK_SET);
        unsigned char *buffer = calloc(single_length, sizeof(unsigned char));
        fread(buffer, single_length, 1, disk_sim);
        unsigned char* key = calloc(1, KEY_LEN);
        
        genKeyNugget(key, nugget_num);
        // printf("Key: %s\n", key);
        
        for(int flake_num = 0; flake_num < (int)(single_length / flake_size); flake_num++){
            uint8_t flake_key[BYTES_FLAKE_TAG_KEY];
            uint8_t tag[BYTES_FLAKE_TAG_OUT];
            
            memcpy(flake_key, key, BYTES_FLAKE_TAG_KEY);
        
            uint64_t * nk8bytes = (uint64_t *) flake_key;
            nk8bytes[0] += ((uint64_t) flake_num);
            
            crypto_onetimeauth(tag, buffer + (flake_num * flake_size), flake_size, flake_key);
        }
        
        unsigned char* decryptedtext = calloc(single_length, sizeof(unsigned char));
        
        if(!encryption){
            memcpy(decryptedtext, buffer, single_length);
        } else {
            int decryptedtext_len = decrypt(buffer, single_length, key, nonce,
                                        decryptedtext);
        }
        /* Add a NULL terminator. We are expecting printable text */
        // decryptedtext[decryptedtext_len] = '\0';
    
        /* Show the decrypted text */
        // printf("Decrypted text is:\n");
        // printf("%s\n", decryptedtext);
        
        // free(key);
        // free(buffer);
        // free(nonce);
        // free(decryptedtext);
    }
    return;
}


int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    
    int len;

    int plaintext_len = 0;
    
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        printf("Decrypt errors 1\n");
    
    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv))
        printf("Decrypt errors 2\n");
    
    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        printf("Decrypt errors 3\n");
    plaintext_len = len;
    
    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        printf("Decrypt errors 4\n");
    plaintext_len += len;
    
    /* Clean up */
    // EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}


void readDisk(unsigned long startAddr, unsigned long endAddr){
    unsigned int length = (unsigned int) endAddr - startAddr;
    if(length <= 0){
        return;
    }
    fseek(disk_sim, startAddr, SEEK_SET);
    unsigned char *buffer = calloc(length, sizeof(unsigned char));
    char hexval[5];
    // printf("Made it so far\n");
    fread(buffer, length, 1, disk_sim);
    // fgets(buff, 255, disk_sim);
    // printf("%s\n", buffer);
    for(unsigned int i = 0; i < length; i++) {
        if(i != 0 && i % 4 == 0){
            printf(" ");
            if(i % 32 == 0){
                printf("\n");
            }
        }
        printf("%02X", *(buffer + i));
    }
    printf("\n");
    // free(buffer);
    return;
}


void writeDiskLen(unsigned long startAddr, unsigned int length){
    uint8_t *data = calloc(length, sizeof(uint8_t));
    for(unsigned int i; i < length; i++){
        *(data + i) = (uint8_t) rand();
    }
    writeDisk(startAddr, data, length);
    // free(data);
}


void writeDiskLenEncrypt(unsigned long startAddr, unsigned int length){
    uint8_t *data = calloc(length, sizeof(uint8_t));
    for(unsigned int i; i < length; i++){
        *(data + i) = (uint8_t) rand();
    }
    writeDiskEncrypt(startAddr, data, length);
    // free(data);
}

void writeDisk(unsigned long startAddr, uint8_t *data, unsigned int length){
    fseek(disk_sim, startAddr, SEEK_SET);
    for(int i = 0; i < length; i++){
        fputc(*(data + i), disk_sim);
    }
    printf("Data: %s\n", data);
    printf("Writing\n");
}


void rekey(int nugget_num){
    fseek(backing_store, nugget_num * 8, SEEK_SET);
    unsigned char *nonce = calloc(1, 8);
    fread(nonce, 8, 1, backing_store);
    
    unsigned long single_length = flake_size * flakes_per_nug;
    
    fseek(disk_sim, nugget_num * (single_length), SEEK_SET);
    unsigned char *buffer = calloc(single_length, sizeof(unsigned char));
    fread(buffer, single_length, 1, disk_sim);
    unsigned char* key = calloc(1, KEY_LEN);
    
    genKeyNugget(key, nugget_num);
    // printf("Key: %s\n", key);
    
    for(int flake_num = 0; flake_num < (int)(single_length / flake_size); flake_num++){
        uint8_t flake_key[BYTES_FLAKE_TAG_KEY];
        uint8_t tag[BYTES_FLAKE_TAG_OUT];
        
        memcpy(flake_key, key, BYTES_FLAKE_TAG_KEY);
    
        uint64_t * nk8bytes = (uint64_t *) flake_key;
        nk8bytes[0] += ((uint64_t) flake_num);
        
        crypto_onetimeauth(tag, buffer + (flake_num * flake_size), flake_size, flake_key);
    }
    
    unsigned char* decryptedtext = calloc(single_length, sizeof(unsigned char));
    
    if(!encryption){
        memcpy(decryptedtext, buffer, single_length);
    } else {
        int decryptedtext_len = decrypt(buffer, single_length, key, nonce,
                                    decryptedtext);
    }
    
    if(!randomize){
        *(nonce + 7) += 1;
    } else {
        uint64_t new_nonce = rand_uint64();
        *nonce = (uint8_t *)&new_nonce;
    }
    int length = strlen(nonce);
    fseek(backing_store, nugget_num * 8, SEEK_SET);
    for(int i = 0; i < length; i++){
        fputc(*(nonce + i), backing_store);
    }
    
    unsigned char* encryptedtext = calloc(single_length, sizeof(unsigned char));
    
    if(!encryption){
        memcpy(encryptedtext, decryptedtext, single_length);
    } else {
        int encryptedtext_len = encrypt(decryptedtext, single_length, key, nonce,
                                    encryptedtext);
    }
    
    
    fseek(disk_sim, nugget_num * (single_length), SEEK_SET);
    for(int i = 0; i < single_length; i++){
        fputc(encryptedtext[i], disk_sim);
    }
    int flake_start_num = (int)((nugget_num * (single_length) % (flake_size * flakes_per_nug)) / flake_size);
    int flake_end_num = (int)(((nugget_num * (single_length) + single_length) % (flake_size * flakes_per_nug)) / flake_size);
    for(int flake_num = flake_start_num; flake_num < flake_end_num; flake_num++){
        fseek(backing_store, keycount_length + (flake_num + (nugget_num * flakes_per_nug)), SEEK_SET);
        fputc('1', backing_store);
    }
    
    
    // free(nonce);
}



void writeDiskEncrypt(unsigned long startAddr, uint8_t *data, unsigned int length){
    int nugget_num_start = (int) startAddr / (flake_size * flakes_per_nug);
    int nugget_num_end = (int) (startAddr + length) / (flake_size * flakes_per_nug);
    
    for(int nugget_num = nugget_num_start; nugget_num <= nugget_num_end; nugget_num++){
        unsigned long single_start = 0;
        unsigned long single_length = 0;
        if(nugget_num_end == nugget_num_start){
            single_start = roundDownFlake(startAddr);
            single_length = length + (roundUpFlake(startAddr + length) - (startAddr + length));
        } else if(nugget_num == nugget_num_start){
            single_start = roundDownFlake(startAddr);
            single_length = roundUpNugget(startAddr) - startAddr;
        } else if(nugget_num == nugget_num_end){
            single_start = roundUpNugget(startAddr) + ((nugget_num - nugget_num_start) * 262144);
            single_length = roundUpFlake(startAddr + length) - single_start;
        } else {
            single_start = roundUpNugget(startAddr) + ((nugget_num - nugget_num_start) * 262144);
            single_length = 262144;
        }
        // printf("Single start: %lu\n", single_start);
        bool rekeyed = false;
        int flake_start_num = (int)((single_start % (flake_size * flakes_per_nug)) / flake_size);
        int flake_end_num = (int)(((single_start + single_length) % (flake_size * flakes_per_nug)) / flake_size);
        for(int flake_num = flake_start_num; flake_num < flake_end_num; flake_num++){
            // int flake_num = (int)((startAddr % (flake_size * flakes_per_nug)) / flake_size);
            fseek(backing_store, keycount_length + (flake_num + (nugget_num * flakes_per_nug)), SEEK_SET);
            unsigned char *flag = calloc(1, 1);
            fread(flag, 1, 1, backing_store);
        
            if(strcmp(flag, "1") == 0){ // Change
                // printf("Need to rekey\n");
                rekey(nugget_num);
                rekeyed = true;
            }
            if(rekeyed){
                break;
            }
            // free(flag);
        }
        if(!rekeyed){
            fseek(backing_store, nugget_num * 8, SEEK_SET);
            unsigned char *nonce = calloc(1, 8);
            fread(nonce, 8, 1, backing_store);
            
            // printf("Nonce: %s\n", nonce);
            // for(unsigned int i = 0; i < 8; i++) {
            //     printf("%02X", *(nonce + i));
            // }
            // printf("\n");
            
            unsigned char* key = calloc(1, KEY_LEN);
            genKeyNugget(key, nugget_num);
            // printf("Key: %s\n", key);
            
            
            unsigned char* encryptedtext = calloc(single_length, sizeof(unsigned char));
            
            if(!encryption){
                memcpy(encryptedtext, data, single_length);
            } else {
                int encryptedtext_len = encrypt(data, single_length, key, nonce,
                                            encryptedtext);
            }
            
            
            fseek(disk_sim, single_start, SEEK_SET);
            for(int i = 0; i < single_length; i++){
                fputc(encryptedtext[i], disk_sim);
            }
            int flake_start_num = (int)((single_start % (flake_size * flakes_per_nug)) / flake_size);
            int flake_end_num = (int)(((single_start + single_length) % (flake_size * flakes_per_nug)) / flake_size);
            for(int flake_num = flake_start_num; flake_num < flake_end_num; flake_num++){
                fseek(backing_store, keycount_length + (flake_num + (nugget_num * flakes_per_nug)), SEEK_SET);
                fputc('1', backing_store);
            }
            // free(key);
            // free(nonce);
        }
    }
    return;
}


int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        printf("Encrypt errors 1\n");

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv))
        printf("Encrypt errors 2\n");

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        printf("Encrypt errors 3\n");
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        printf("Encrypt errors 4\n");
    ciphertext_len += len;

    /* Clean up */
    // EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}



int main() {
    init();
    
    bool running = true;
    char input[256];
    char delim[] = " ";
    while(running){
        printf("> ");
        fgets(input, sizeof(input), stdin);
        char *pos;
        if ((pos=strchr(input, '\n')) != NULL)
          *pos = '\0';
        char* token = strtok(input, " ");
        printf("%s\n", token);
        if(strcmp("help", token) == 0){
            printHelp();
        }
        if(strcmp("read", token) == 0){
            token = strtok(NULL, " ");
            char *tmp;
            // printf("Param 1: %s\n", token);
            unsigned long startAddr = strtoul(token, &tmp, 10);
            token = strtok(NULL, " ");
            // printf("Param 2: %s\n", token);
            unsigned long endAddr = strtoul(token, &tmp, 10);
            readDisk(startAddr, endAddr);
        }
        if(strcmp("readBox", token) == 0){
            token = strtok(NULL, " ");
            char *tmp;
            // printf("Param 1: %s\n", token);
            unsigned long startAddr = strtoul(token, &tmp, 10);
            token = strtok(NULL, " ");
            // printf("Param 2: %s\n", token);
            unsigned long endAddr = strtoul(token, &tmp, 10);
            readDiskDecrypt(startAddr, endAddr);
        }
        if(strcmp("writeRand", token) == 0){
            token = strtok(NULL, " ");
            char* tmp;
            unsigned long startAddr = strtoul(token, &tmp, 10);
            token = strtok(NULL, " ");
            unsigned int length = atoi(token);
            writeDiskLen(startAddr, length);
        }
        if(strcmp("write", token) == 0){
            token = strtok(NULL, " ");
            char* tmp;
            unsigned long startAddr = strtoul(token, &tmp, 10);
            token = strtok(NULL, " ");
            unsigned int length = strlen(token);
            uint8_t* data = calloc(length, sizeof(uint8_t));
            for(int i = 0; i < length; i++){
                *(data + i) = *(token + i);
            }
            writeDisk(startAddr, data, length);
            // free(data);
        }
        if(strcmp("writeRandBox", token) == 0){
            token = strtok(NULL, " ");
            char* tmp;
            unsigned long startAddr = strtoul(token, &tmp, 10);
            token = strtok(NULL, " ");
            unsigned int length = atoi(token);
            writeDiskLenEncrypt(startAddr, length);
        }
        if(strcmp("writeBox", token) == 0){
            token = strtok(NULL, " ");
            char* tmp;
            unsigned long startAddr = strtoul(token, &tmp, 10);
            token = strtok(NULL, " ");
            unsigned int length = strlen(token);
            uint8_t* data = calloc(length, sizeof(uint8_t));
            for(int i = 0; i < length; i++){
                *(data + i) = *(token + i);
            }
            writeDiskEncrypt(startAddr, data, length);
            // free(data);
        }
        if(strcmp("tinySeqReads", token) == 0){
            seqReads(4096);
        }
        if(strcmp("tinySeqWrites", token) == 0){
            seqWrites(4096);
        }
        if(strcmp("tinyRandReads", token) == 0){
            randReads(4096);
        }
        if(strcmp("tinyRandWrites", token) == 0){
            randWrites(4096);
        }
        if(strcmp("smallSeqReads", token) == 0){
            seqReads(524288);
        }
        if(strcmp("smallSeqWrites", token) == 0){
            seqWrites(524288);
        }
        if(strcmp("smallRandReads", token) == 0){
            randReads(524288);
        }
        if(strcmp("smallRandWrites", token) == 0){
            randWrites(524288);
        }
        if(strcmp("mediumSeqReads", token) == 0){
            seqReads(5242880);
        }
        if(strcmp("mediumSeqWrites", token) == 0){
            seqWrites(5242880);
        }
        if(strcmp("mediumRandReads", token) == 0){
            randReads(5242880);
        }
        if(strcmp("mediumRandWrites", token) == 0){
            randWrites(5242880);
        }
        if(strcmp("largeSeqReads", token) == 0){
            seqReads(41943040);
        }
        if(strcmp("largeSeqWrites", token) == 0){
            seqWrites(41943040);
        }
        if(strcmp("largeRandReads", token) == 0){
            randReads(41943040);
        }
        if(strcmp("largeRandWrites", token) == 0){
            randWrites(41943040);
        }
        if(strcmp("switchChaCha", token) == 0){
            printf("Switching to ChaCha20\n");
            cipher = EVP_chacha20();
            encryption = true;
            randomize = false;
        }
        if(strcmp("switchXTS", token) == 0){
            printf("Switching to AES-XTS\n");
            cipher = EVP_aes_256_xts();
            encryption = true;
            randomize = false;
        }
        if(strcmp("switchCTR", token) == 0){
            printf("Switching to AES-CTR\n");
            cipher = EVP_aes_256_ctr();
            encryption = true;
            randomize = false;
        }
        if(strcmp("switchOFB", token) == 0){
            printf("Switching to AES-OFB\n");
            cipher = EVP_aes_256_ofb();
            encryption = true;
            randomize = true;
        }
        if(strcmp("switchUnencrypted", token) == 0){
            printf("Switching to unencrypted\n");
            encryption = false;
            randomize = false;
        }
        if(strcmp("resetStore", token) == 0){
            printf("Resetting the transaction journal\n");
            resetStore();
        }
        if(strcmp("quit", token) == 0){
            running = false;
        }
        token = strtok(NULL, " ");
    }
    fclose(disk_sim);
    return(0);
}