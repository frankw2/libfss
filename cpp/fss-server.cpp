// This is the server side code for FSS which does the evaluation

#include "fss-server.h"

void initializeServer(Fss* f, AES_KEY* aes_keys, uint32_t numBits) {
    f->aes_keys = (AES_KEY*) malloc(sizeof(AES_KEY)*initPRFLen);
    memcpy(f->aes_keys, aes_keys, sizeof(AES_KEY)*initPRFLen);
    f->m = 4;
    f->numBits = numBits;
}

mpz_class evaluateEq(Fss* f, ServerKeyEq *k, uint64_t x) {

    // get num bits to be compared
    uint32_t n = f->numBits;

    // start at the correct LSB
    int xi = getBit(x, (64-n+1));
    unsigned char s[16];
    memcpy(s, k->s[xi], 16);
    unsigned char t = k->t[xi];
    /*unsigned char pt []= {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02};
    */
    unsigned char pt[1];
    unsigned char sArray[32];
    unsigned char temp[2];
    unsigned char out[48];
    for (uint32_t i = 1; i < n+1; i++) {
        xi = getBit(x, (64-n+i+1));
        prf(out, s, pt, 48, f->aes_keys);
        memcpy(sArray, out, 32);
        temp[0] = out[32] % 2;
        temp[1] = out[33] % 2;
        //printf("s: ");
        //printByteArray(s, 16);
        //printf("out: %d %d\n", out[32], out[33]);
        if (i == n) {
            break;
        }
        int xStart = 16 * xi;
        memcpy(s, (unsigned char*) (sArray + xStart), 16);
        for (uint32_t j = 0; j < 16; j++) {
            s[j] = s[j] ^ k->cw[t][i-1].cs[xi][j];
        }
        //printf("After XOR: ");
        //printByteArray(s, 16);
        //printf("%d: t: %d %d, ct: %d, bit: %d\n", i, temp[0], temp[1], k->cw[t][i-1].ct[xi], xi);
        t = temp[xi] ^ k->cw[t][i-1].ct[xi];
    }

    mpz_class ans;
    unsigned char sIntArray[34];
    memcpy(sIntArray, sArray, 32);
    sIntArray[32] = temp[0];
    sIntArray[33] = temp[1];
    mpz_import(ans.get_mpz_t(), 34, 1, sizeof(sIntArray[0]), 0, 0, sIntArray);
    ans = ans * k->w;
    ans = ans % f->prime;
    return ans;
}

uint64_t evaluateLt(Fss* f, ServerKeyLt *k, uint64_t x) {

    uint32_t n = f->numBits;

    int xi = getBit(x, (64-n+1));
    unsigned char s[16];
    memcpy(s, k->s[xi], 16);
    unsigned char t = k->t[xi];
    uint64_t v = k->v[xi];
    unsigned char pt []= {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03};

    unsigned char sArray[32];
    unsigned char temp[2];
    unsigned char out[64];
    uint64_t temp_v;
    for (uint32_t i = 1; i < n; i++) {
        xi = getBit(x, (64-n+i+1));
        prf(out, s, pt, 64, f->aes_keys);
        memcpy(sArray, out, 32);
        temp[0] = out[32] % 2;
        temp[1] = out[33] % 2;

        temp_v = byteArr2Int64((unsigned char*) (out + 40 + (8*xi)));
        int xStart = 16 * xi;
        memcpy(s, (unsigned char*) (sArray + xStart), 16);
        for (uint32_t j = 0; j < 16; j++) {
            s[j] = s[j] ^ k->cw[t][i-1].cs[xi][j];
        }
        //printf("%d: t: %d %d, ct: %d, bit: %d\n", i, temp[0], temp[1], k->cw[t][i-1].ct[xi], xi);
        //printf("temp_v: %lld\n", temp_v);
        v = (v + temp_v);
        v = (v + k->cw[t][i-1].cv[xi]);
        t = temp[xi] ^ k->cw[t][i-1].ct[xi];
    }
    
    return v;
}
