#include "fss-common.h"
#include <cpuid.h>
#include <stdint.h>

void prf(unsigned char* out, unsigned char* key, unsigned char* in, uint64_t key_size, uint64_t in_size) {

    // check if there is aes-ni instruction
    uint32_t eax, ebx, ecx, edx;

    eax = ebx = ecx = edx = 0;
    __get_cpuid(1, &eax, &ebx, &ecx, &edx);
    
    if ((ecx & bit_AES) > 0) {
        // Do Matyas–Meyer–Oseas one-way compression function using different AES keys to get desired
        // output length

        uint32_t num_keys_required = in_size/16;
        for (int i = 0; i < num_keys_required; i++) {
            aesni_encrypt(key, out + (i*16), &aes_keys[i]);
        }
        for (int i = 0; i < in_size; i++) {
            out[i] = out[i] ^ key[i%16];
        }
    } else {
        unsigned char iv []= {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        unsigned char ecount [] ={0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        int len = 0;
        EVP_CIPHER_CTX ctx;
        EVP_CIPHER_CTX_init(&ctx);
        EVP_EncryptInit_ex(&ctx, EVP_aes_128_ctr(), NULL, key, iv);
        EVP_EncryptUpdate(&ctx, out, &len, in, in_size);
        EVP_EncryptFinal_ex(&ctx, out + len, &len);
    }
}

