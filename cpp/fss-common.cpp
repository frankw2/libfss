#include "fss-common.h"

AES_KEY* prf(unsigned char* out, unsigned char* key, uint64_t in_size, AES_KEY* aes_keys, uint32_t numKeys) {
#ifndef AESNI
    // check if there is aes-ni instruction
    uint32_t eax, ebx, ecx, edx;

    eax = ebx = ecx = edx = 0;
    __get_cpuid(1, &eax, &ebx, &ecx, &edx);
#endif
    
    AES_KEY* temp_keys = aes_keys;
    // Do Matyas–Meyer–Oseas one-way compression function using different AES keys to get desired
    // output length
    uint32_t num_keys_required = in_size/16;
    if (num_keys_required > numKeys) {
        free(temp_keys);
        temp_keys = (AES_KEY*) malloc(sizeof(AES_KEY)*num_keys_required); 
        for (int i = 0; i < num_keys_required; i++) {
            unsigned char rand_bytes[16];
            if (!RAND_bytes(rand_bytes, 16)) {
                printf("Random bytes failed.\n");
            }
#ifndef AESNI
            if ((ecx & bit_AES) > 0) {
                aesni_set_encrypt_key(rand_bytes, 128, &(temp_keys[i]));
            } else {
                AES_set_encrypt_key(rand_bytes, 128, &(temp_keys[i]));
            }
#else
            aesni_set_encrypt_key(rand_bytes, 128, &(temp_keys[i]));
#endif
        }
    }
    for (int i = 0; i < num_keys_required; i++) {
#ifndef AESNI
        if ((ecx & bit_AES) > 0) {
            aesni_encrypt(key, out + (i*16), &temp_keys[i]);
        } else {
            AES_encrypt(key, out + (i*16), &temp_keys[i]);
        }
#else
        aesni_encrypt(key, out + (i*16), &temp_keys[i]);
#endif
    }
    for (int i = 0; i < in_size; i++) {
        out[i] = out[i] ^ key[i%16];
    }
    return temp_keys;
}

