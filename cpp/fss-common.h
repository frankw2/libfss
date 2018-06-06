#ifndef FSS_COMMON_H
#define FSS_COMMON_H


#include "openssl-aes.h"

#include <cpuid.h>
#include <gmp.h>
#include <gmpxx.h>
#include <iostream>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <string>

using namespace std;

const int initPRFLen = 4;

struct Fss {
    // store keys in fixedBlocks
    AES_KEY* aes_keys;
    uint32_t numBits; // number of bits in domain 
    mpz_class prime;
    uint32_t numParties; // used only in multiparty. Default is 3
    uint32_t numKeys;
};

struct CWEq {
    unsigned char cs[2][16];
    unsigned char ct[2];
};

struct CWLt {
    unsigned char cs[2][16];
    unsigned char ct[2];
    uint64_t cv[2];
};

struct ServerKeyEq {
    unsigned char s[2][16];
    unsigned char t[2];
    CWEq* cw[2];
    mpz_class w;
};

struct ServerKeyLt {
    unsigned char s[2][16];
    unsigned char t[2];
    uint64_t v[2];
    CWLt* cw[2];
};

struct MPLtKey {
    unsigned char*** s;
    uint32_t** aValue;
    uint32_t** cw;
    uint32_t* wVal;
};

struct MPKey {
    unsigned char** sigma;
    uint32_t** cw;
};

// Assumes integers are 64 bits
inline int getBit(uint64_t n, uint64_t pos) {
    return (n & ( 1 << (64-pos))) >> (64-pos);
}

// Converts byte array into 64-bit integer
inline uint64_t byteArr2Int64(unsigned char* arr)
{
    uint64_t i = ((unsigned long) arr[7] << 56) | ((unsigned long)arr[6] << 48) | ((unsigned long)arr[5] << 40) |
                ((unsigned long) arr[4] << 32) | ((unsigned long) arr[3] << 24) |
                ((unsigned long) arr[2] << 16) | ((unsigned long) arr[1] << 8) | ((unsigned long) arr[0]);
    return i;
}

// Converts byte array into 32-bit integer
inline uint32_t byteArr2Int32(unsigned char* arr)
{
    uint32_t a = uint32_t((unsigned char)(arr[0]) << 24 |
            (unsigned char)(arr[1]) << 16 |
            (unsigned char)(arr[2]) << 8 |
            (unsigned char)(arr[3]));
    return a;
}

AES_KEY* prf(unsigned char* out, unsigned char* key, uint64_t in_size, AES_KEY* aes_keys, uint32_t numKeys);

#endif
