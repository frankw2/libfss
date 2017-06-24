#include "fss-common.h"

void prf(unsigned char* out, unsigned char* key, unsigned char* in, uint64_t in_size, AES_KEY* aes_keys) {

    // check if there is aes-ni instruction
    uint32_t eax, ebx, ecx, edx;

    eax = ebx = ecx = edx = 0;
    __get_cpuid(1, &eax, &ebx, &ecx, &edx);
    
    // Do Matyas–Meyer–Oseas one-way compression function using different AES keys to get desired
    // output length
    uint32_t num_keys_required = in_size/16;
    for (int i = 0; i < num_keys_required; i++) {
        if ((ecx & bit_AES) > 0) {
            aesni_encrypt(key, out + (i*16), &aes_keys[i]);
        } else {
            AES_encrypt(key, out + (i*16), &aes_keys[i]);
        }
    }
    for (int i = 0; i < in_size; i++) {
        out[i] = out[i] ^ key[i%16];
    }
}

