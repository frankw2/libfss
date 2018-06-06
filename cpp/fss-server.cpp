// This is the server side code for FSS which does the evaluation

#include "fss-server.h"

void initializeServer(Fss* fServer, Fss* fClient) {
    fServer->numKeys = fClient->numKeys;
    fServer->aes_keys = (AES_KEY*) malloc(sizeof(AES_KEY)*fClient->numKeys);
    memcpy(fServer->aes_keys, fClient->aes_keys, sizeof(AES_KEY)*fClient->numKeys);
    fServer->numBits = fClient->numBits;
    fServer->numParties = fClient->numParties;
    fServer->prime = fClient->prime;
}

// evaluate whether x satisifies value in function stored in key k

mpz_class evaluateEq(Fss* f, ServerKeyEq *k, uint64_t x) {

    // get num bits to be compared
    uint32_t n = f->numBits;

    // start at the correct LSB
    int xi = getBit(x, (64-n+1));
    unsigned char s[16];
    memcpy(s, k->s[xi], 16);
    unsigned char t = k->t[xi];
    
    unsigned char sArray[32];
    unsigned char temp[2];
    unsigned char out[48];
    for (uint32_t i = 1; i < n+1; i++) {
        if(i!=n) {
            xi = getBit(x, (64-n+i+1));
        } else {
            xi = 0;
        }
        prf(out, s, 48, f->aes_keys, f->numKeys);
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

// Evaluate whether x < value in function stored in key k

uint64_t evaluateLt(Fss* f, ServerKeyLt *k, uint64_t x) {

    uint32_t n = f->numBits;

    int xi = getBit(x, (64-n+1));
    unsigned char s[16];
    memcpy(s, k->s[xi], 16);
    unsigned char t = k->t[xi];
    uint64_t v = k->v[xi];

    unsigned char sArray[32];
    unsigned char temp[2];
    unsigned char out[64];
    uint64_t temp_v;
    for (uint32_t i = 1; i < n; i++) {
        if(i!=n) {
            xi = getBit(x, (64-n+i+1));
        } else {
            xi = 0;
        }
        prf(out, s, 64, f->aes_keys, f->numKeys);
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

// This function is for multi-party (3 or more parties) FSS
// for equality functions
// The API interface is similar to the 2 party version.
// One main difference is the output of the evaluation function
// is XOR homomorphic, so for additive queries like SUM and COUNT,
// the client has to add it locally.

uint32_t evaluateEqMParty(Fss *f, MPKey* key, uint32_t x)
{
    uint32_t m = 4; // Assume messages are 4 bytes long 
    uint64_t n = f->numBits;
    uint32_t p = f->numParties;
    uint32_t p2 = (uint32_t)(pow(2, p-1));
    uint64_t mu = (uint64_t)ceil((pow(2, n/2.0) * pow(2,(p-1)/2.0)));

    // sigma is last n/2 bits
    uint32_t delta = x & ((1 << (n/2)) - 1);
    uint32_t gamma = (x & (((1 << (n+1)/2) - 1) << n/2)) >> n/2;

    unsigned char** sigma = key->sigma;
    uint32_t** cw = key->cw;
    uint32_t m_bytes = m*mu;

    uint32_t* y = (uint32_t*) malloc(m_bytes);
    unsigned char* temp_out = (unsigned char*) malloc(m_bytes);
    memset(y, 0, m_bytes);
    f->numKeys = mu;
    for (int i = 0; i < p2; i++) {
        unsigned char* s = (unsigned char*)sigma[gamma] + i*16;
        bool all_zero_bytes = true;
        for (int j = 0; j < 16; j++) {
            if (s[j] != 0) {
                all_zero_bytes = false;
                break;
            }
        }
        if (!all_zero_bytes) {
            prf(temp_out, s, m_bytes, f->aes_keys, f->numKeys);
            for (int k = 0; k < mu; k++) {
                unsigned char tempIntBytes[4];
                memcpy(tempIntBytes, &temp_out[4*k], 4);
                y[k] = y[k] ^ byteArr2Int32(tempIntBytes);
            }

            for (int j = 0; j < mu; j++) {
                y[j] = cw[i][j] ^ y[j];
            }
        }
    }

    uint32_t final_ans = y[delta];
    free(y);
    free(temp_out);
    return final_ans;
}
