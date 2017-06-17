#ifndef FSS_COMMON_H
#define FSS_COMMON_H


#include "openssl-aes.h"

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string>

inline int getBit(uint64_t n, uint64_t pos) {
    int val = n & (1 << (64 - pos));
    if (val > 0) {
        return 1;
    } else {
        return 0;
    }
}

void prf(unsigned char* out, unsigned char* key, unsigned char* in, uint64_t key_size, uint64_t in_size);

#endif
