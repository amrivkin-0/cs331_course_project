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
// EVP_CIPHER cipher = EVP_chacha20(); // EVP_aes_256_ctr, EVP_aes_256_ofb, EVP_aes_256_xts

void init(){
    if (sodium_init() < 0) {
        printf("Could not init libsodium\n");
    }
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
    return;
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
    printf("    smallRandReads - Small random reads\n");
    printf("    smallRandWrites - Small random writes\n");
    printf("    largeRandReads - Large random reads\n");
    printf("    largeRandWrites - Large random writes\n");
    printf("    smallSeqReads - Small sequential reads\n");
    printf("    smallSeqWrites - Small sequential writes\n");
    printf("    largeSeqReads - Large sequential reads\n");
    printf("    largeSeqWrites - Large sequential writes\n");
}


void smallSeqReads(){
    clock_t t; 
    t = clock(); 
    unsigned long startAddr = 0;
    unsigned long endAddr = 256;
    for(int i = 0; i < 256; i++){
        readDiskDecrypt(startAddr, endAddr);
        startAddr += 256;
        endAddr += 256;
    }
    t = clock() - t; 
    double time_taken = ((double)t)/CLOCKS_PER_SEC; // in seconds 
    printf("smallSeqReads took %f seconds to execute \n", time_taken); 
}


void smallSeqWrites(){
    clock_t t; 
    t = clock();
    unsigned long startAddr = 0;
    unsigned int length = 256;
    for(int i = 0; i < 256; i++){
        writeDiskLenEncrypt(startAddr, length);
        startAddr += 256;
    }
    t = clock() - t; 
    double time_taken = ((double)t)/CLOCKS_PER_SEC; // in seconds 
    printf("smallSeqWrites took %f seconds to execute \n", time_taken); 
}


void largeSeqReads(){
    clock_t t; 
    t = clock(); 
    unsigned long startAddr = 0;
    unsigned long endAddr = 40960;
    for(int i = 0; i < 256; i++){
        readDiskDecrypt(startAddr, endAddr);
        startAddr += 40960;
        endAddr += 40960;
        startAddr = startAddr % mem_size;
        endAddr = endAddr % mem_size;
    }
    t = clock() - t; 
    double time_taken = ((double)t)/CLOCKS_PER_SEC; // in seconds 
    printf("largeSeqReads took %f seconds to execute \n", time_taken); 
}


void largeSeqWrites(){
    clock_t t; 
    t = clock();
    unsigned long startAddr = 0;
    unsigned int length = 40960;
    for(int i = 0; i < 256; i++){
        writeDiskLenEncrypt(startAddr, length);
        startAddr += 40960;
        startAddr = startAddr % mem_size;
    }
    t = clock() - t; 
    double time_taken = ((double)t)/CLOCKS_PER_SEC; // in seconds 
    printf("largeSeqWrites took %f seconds to execute \n", time_taken); 
}


void smallRandReads(){
    clock_t t; 
    t = clock();
    unsigned long startAddr;
    unsigned long endAddr;
    for(int i = 0; i < 256; i++){
        startAddr = rand() % (mem_size - 256);
        endAddr = startAddr + 256;
        readDiskDecrypt(startAddr, endAddr);
    }
    t = clock() - t; 
    double time_taken = ((double)t)/CLOCKS_PER_SEC; // in seconds 
    printf("smallRandReads took %f seconds to execute \n", time_taken); 
}


void smallRandWrites(){
    clock_t t; 
    t = clock();
    unsigned long startAddr;
    unsigned int length = 256;
    for(int i = 0; i < 256; i++){
        startAddr = rand() % (mem_size - 256);
        writeDiskLenEncrypt(startAddr, length);
        startAddr += 256;
    }
    t = clock() - t; 
    double time_taken = ((double)t)/CLOCKS_PER_SEC; // in seconds 
    printf("smallRandWrites took %f seconds to execute \n", time_taken); 
}


void largeRandReads(){
    clock_t t; 
    t = clock();
    unsigned long startAddr;
    unsigned long endAddr;
    for(int i = 0; i < 256; i++){
        startAddr = rand() % (mem_size - 40960);
        endAddr = startAddr + 40960;
        readDiskDecrypt(startAddr, endAddr);
    }
    t = clock() - t; 
    double time_taken = ((double)t)/CLOCKS_PER_SEC; // in seconds 
    printf("smallRandReads took %f seconds to execute \n", time_taken); 
}


void largeRandWrites(){
    clock_t t; 
    t = clock();
    unsigned long startAddr;
    unsigned int length = 40960;
    for(int i = 0; i < 256; i++){
        startAddr = rand() % (mem_size - 40960);
        writeDiskLenEncrypt(startAddr, length);
    }
    t = clock() - t; 
    double time_taken = ((double)t)/CLOCKS_PER_SEC; // in seconds 
    printf("smallRandWrites took %f seconds to execute \n", time_taken); 
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


void readDiskDecrypt(unsigned long startAddr, unsigned long endAddr){
    unsigned int length = (unsigned int) endAddr - startAddr;
    if(length <= 0){
        return;
    }
    int nugget_num = (int) startAddr / (flake_size * flakes_per_nug);
    int flake_num = (int)((startAddr % (flake_size * flakes_per_nug)) / flake_size);
    // int nugget_index = ;
    
    fseek(backing_store, nugget_num * 8, SEEK_SET);
    unsigned char *nonce = calloc(1, 8);
    fread(nonce, 8, 1, backing_store);
    
    // printf("Nonce: %s\n", nonce);
    // for(unsigned int i = 0; i < 8; i++) {
        // printf("%02X", *(nonce + i));
    // }
    // printf("\n");
    
    fseek(disk_sim, startAddr, SEEK_SET);
    unsigned char *buffer = calloc(length, sizeof(unsigned char));
    fread(buffer, length, 1, disk_sim);
    unsigned char* key = calloc(1, KEY_LEN);
    
    genKeyNugget(key, nugget_num);
    // printf("Key: %s\n", key);
    
    unsigned char* decryptedtext = calloc(length, sizeof(unsigned char));
    
    int decryptedtext_len = decrypt(buffer, length, key, nonce,
                                decryptedtext);
                                
    /* Add a NULL terminator. We are expecting printable text */
    // decryptedtext[decryptedtext_len] = '\0';

    /* Show the decrypted text */
    // printf("Decrypted text is:\n");
    // printf("%s\n", decryptedtext);
    
    // free(key);
    // free(buffer);
    // free(nonce);
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
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_xts(), NULL, key, iv))
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
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}


// int decryptCTR(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
//             unsigned char *iv, unsigned char *plaintext)
// {
//     EVP_CIPHER_CTX *ctx;
// 
//     int len;
// 
//     int plaintext_len = 0;
// 
//     /* Create and initialise the context */
//     if(!(ctx = EVP_CIPHER_CTX_new()))
//         printf("Decrypt errors 1\n");
// 
//     /*
//      * Initialise the decryption operation. IMPORTANT - ensure you use a key
//      * and IV size appropriate for your cipher
//      * In this example we are using 256 bit AES (i.e. a 256 bit key). The
//      * IV size for *most* modes is the same as the block size. For AES this
//      * is 128 bits
//      */
//     if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv))
//         printf("Decrypt errors 2\n");
// 
//     /*
//      * Provide the message to be decrypted, and obtain the plaintext output.
//      * EVP_DecryptUpdate can be called multiple times if necessary.
//      */
//     if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
//         printf("Decrypt errors 3\n");
//     plaintext_len = len;
// 
//     /*
//      * Finalise the decryption. Further plaintext bytes may be written at
//      * this stage.
//      */
//     if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
//         printf("Decrypt errors 4\n");
//     plaintext_len += len;
// 
//     /* Clean up */
//     EVP_CIPHER_CTX_free(ctx);
// 
//     return plaintext_len;
// }


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
    free(buffer);
    return;
    // for(int addr = startAddr; addr < endAddr; addr++){
    //     int nugget_num = (int) addr / (flake_size * flakes_per_nug);
    //     int flake_num = (int)((addr % (flake_size * flakes_per_nug)) / flake_size);
    //     flake_t* target_flake = main_memory -> nuggets[nugget_num] -> flakes[flake_num];
    //     int data_num = (addr % (flake_size * flakes_per_nug)) % flake_size;
    //     uint8_t* target = target_flake -> data[data_num];
    //     printf("%x", target);
    //     int offset = addr - startAddr;
    //     if(offset % 8 == 7){
    //         printf(" ");
    //     }
    //     if(offset % 64 == 63){
    //         printf("\n");
    //     }
    // }
    // printf("\n");
}


void writeDiskLen(unsigned long startAddr, unsigned int length){
    uint8_t *data = calloc(length, sizeof(uint8_t));
    for(unsigned int i; i < length; i++){
        *(data + i) = (uint8_t) rand();
    }
    writeDisk(startAddr, data, length);
    free(data);
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
    nonce += 1;
    int length = strlen(nonce);
    for(int i = 0; i < length; i++){
        fputc(*(nonce + i), backing_store);
    }
    // free(nonce);
}



void writeDiskEncrypt(unsigned long startAddr, uint8_t *data, unsigned int length){
    int nugget_num = (int) startAddr / (flake_size * flakes_per_nug);
    int flake_num = (int)((startAddr % (flake_size * flakes_per_nug)) / flake_size);
    
    fseek(backing_store, keycount_length + (flake_num + (nugget_num * flakes_per_nug)), SEEK_SET);
    unsigned char *flag = calloc(1, 1);
    fread(flag, 1, 1, backing_store);
    
    if(strcmp(flag, "1") == 0){
        // printf("Need to rekey\n");
        rekey(nugget_num);
    }
    
    // free(flag);
    
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
    
    unsigned char* encryptedtext = calloc(length, sizeof(unsigned char));
    
    int encryptedtext_len = encrypt(data, length, key, nonce,
                                encryptedtext);
    
    fseek(disk_sim, startAddr, SEEK_SET);
    for(int i = 0; i < length; i++){
        fputc(encryptedtext[i], disk_sim);
    }
    
    fseek(backing_store, keycount_length + (flake_num + (nugget_num * flakes_per_nug)), SEEK_SET);
    fputc('1', backing_store);
    
    // free(key);
    // free(nonce);
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
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_xts(), NULL, key, iv))
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
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}


// int encryptCTR(unsigned char *plaintext, int plaintext_len, unsigned char *key,
//             unsigned char *iv, unsigned char *ciphertext)
// {
//     EVP_CIPHER_CTX *ctx;
// 
//     int len;
// 
//     int ciphertext_len;
// 
//     /* Create and initialise the context */
//     if(!(ctx = EVP_CIPHER_CTX_new()))
//         printf("Encrypt errors 1\n");
// 
//     /*
//      * Initialise the encryption operation. IMPORTANT - ensure you use a key
//      * and IV size appropriate for your cipher
//      * In this example we are using 256 bit AES (i.e. a 256 bit key). The
//      * IV size for *most* modes is the same as the block size. For AES this
//      * is 128 bits
//      */
//     if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv))
//         printf("Encrypt errors 2\n");
// 
//     /*
//      * Provide the message to be encrypted, and obtain the encrypted output.
//      * EVP_EncryptUpdate can be called multiple times if necessary
//      */
//     if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
//         printf("Encrypt errors 3\n");
//     ciphertext_len = len;
// 
//     /*
//      * Finalise the encryption. Further ciphertext bytes may be written at
//      * this stage.
//      */
//     if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
//         printf("Encrypt errors 4\n");
//     ciphertext_len += len;
// 
//     /* Clean up */
//     EVP_CIPHER_CTX_free(ctx);
// 
//     return ciphertext_len;
// }



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
            free(data);
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
            free(data);
        }
        if(strcmp("smallSeqReads", token) == 0){
            smallSeqReads();
        }
        if(strcmp("smallSeqWrites", token) == 0){
            smallSeqWrites();
        }
        if(strcmp("smallRandReads", token) == 0){
            smallRandReads();
        }
        if(strcmp("smallRandWrites", token) == 0){
            smallRandWrites();
        }
        if(strcmp("largeSeqReads", token) == 0){
            largeSeqReads();
        }
        if(strcmp("largeSeqWrites", token) == 0){
            largeSeqWrites();
        }
        if(strcmp("largeRandReads", token) == 0){
            largeRandReads();
        }
        if(strcmp("largeRandWrites", token) == 0){
            largeRandWrites();
        }
        if(strcmp("quit", token) == 0){
            running = false;
        }
        token = strtok(NULL, " ");
    }
    fclose(disk_sim);
    return(0);
}