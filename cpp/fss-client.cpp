// This is the client side code that does the evaluation
#include "fss-client.h"

void initializeClient(Fss* f, uint32_t numBits) {
    // check if there is aes-ni instruction
    uint32_t eax, ebx, ecx, edx;

    eax = ebx = ecx = edx = 0;
    __get_cpuid(1, &eax, &ebx, &ecx, &edx);

    f->numBits = numBits;

    // Initialize keys for Matyas–Meyer–Oseas one-way compression function
    f->aes_keys = (AES_KEY*) malloc(sizeof(AES_KEY)*initPRFLen);
    for (int i = 0; i < initPRFLen; i++) {
        unsigned char rand_bytes[16];
        if (!RAND_bytes(rand_bytes, 16)) {
            printf("Random bytes failed.\n");
        }
        if ((ecx & bit_AES) > 0) {
            aesni_set_encrypt_key(rand_bytes, 128, &(f->aes_keys[i]));
        } else {
            AES_set_encrypt_key(rand_bytes, 128, &(f->aes_keys[i]));
        }
    }
    f->m = 4;
    // We need prime for the point funciton of FSS, but the new point function FSS does not need this
    mpz_class p;
    mpz_ui_pow_ui(p.get_mpz_t(), 2, 32);
    mpz_nextprime(f->prime.get_mpz_t(), p.get_mpz_t());
}

void generateTreeEq(Fss* f, ServerKeyEq* k0, ServerKeyEq* k1, uint64_t a_i, uint64_t b_i){
    uint32_t n = f->numBits;

    // set bits in keys and allocate memory
    k0->cw[0] = (CWEq*) malloc(sizeof(CWEq) * (n-1));
    k0->cw[1] = (CWEq*) malloc(sizeof(CWEq) * (n-1));
    k1->cw[0] = (CWEq*) malloc(sizeof(CWEq) * (n-1));
    k1->cw[1] = (CWEq*) malloc(sizeof(CWEq) * (n-1));

    // Figure out first relevant bit
    // n represents the number of LSB to compare
    int a = getBit(a_i, (64-n+1));
    int na = a ^ 1;

    // create arrays size (AES_key_size*2 + 2)
    unsigned char s0[32];
    unsigned char s1[32];
    int aStart = 16 * a;
    int naStart = 16 *na;

    // Set initial seeds for PRF
    if(!RAND_bytes((unsigned char*) (s0 + aStart), 16)) {
        printf("Random bytes failed\n");
        exit(1);
    }
    if (!RAND_bytes((unsigned char*) (s1 + aStart), 16)) {
        printf("Random bytes failed\n");
        exit(1);
    }
    if (!RAND_bytes((unsigned char*) (s0 + naStart), 16)) {
        printf("Random bytes failed\n");
        exit(1);
    }
    memcpy((unsigned char*)(s1 + naStart), (unsigned char*)(s0 + naStart), 16);

    unsigned char t0[2];
    unsigned char t1[2];
    unsigned char temp[2];
    if (!RAND_bytes((unsigned char*) temp, 2)) {
        printf("Random bytes failed\n");
        exit(1);
    }

    // Figure out initial ts
    // Make sure t0a and t1a are different
    t0[a] = temp[0] % 2;
    t1[a] = (t0[a] + 1) % 2;

    // Make sure t0na = t1na
    t0[na] = temp[1] % 2;
    t1[na] = t0[na];

    memcpy(k0->s[0], s0, 16);
    memcpy(k0->s[1], (unsigned char*)(s0 + 16), 16);
    memcpy(k1->s[0], s1, 16);
    memcpy(k1->s[1], (unsigned char*) (s1 + 16), 16);
    k0->t[0] = t0[0];
    k0->t[1] = t0[1];
    k1->t[0] = t1[0];
    k1->t[1] = t1[1];

    // Pick right keys to put into cipher
    unsigned char key0[16];
    unsigned char key1[16];
    memcpy(key0, (unsigned char*) (s0 + aStart), 16);
    memcpy(key1, (unsigned char*) (s1 + aStart), 16);

    unsigned char tbit0 = t0[a];
    unsigned char tbit1 = t1[a];

    unsigned char pt []= {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02};
    unsigned char cs0[32];
    unsigned char cs1[32];
    unsigned char ct0[2];
    unsigned char ct1[2];
    unsigned char out0[48];
    unsigned char out1[48];

    for (uint32_t i = 0; i < n; i++) {
        prf(out0, key0, pt, 48, f->aes_keys);
        prf(out1, key1, pt, 48, f->aes_keys);

        memcpy(s0, out0, 32);
        memcpy(s1, out1, 32);
        t0[0] = out0[32] % 2;
        t0[1] = out0[33] % 2;
        t1[0] = out1[32] % 2;
        t1[1] = out1[33] % 2;
        //printf("out0: %d %d\n", out0[32], out0[33]);
        // Handle last bit differently, code at the end of the for loop
        if (i == n-1) {
            break;
        }

        // Reset a and na bits
        a = getBit(a_i, (64-n+i+2));
        na = a ^ 1;

        // Redefine aStart and naStart based on new a's
        aStart = 16 * a;
        naStart = 16 * na;

        // Create cs and ct for next bit
        if (!RAND_bytes((unsigned char*) (cs0 + aStart), 16)) {
            printf("Random bytes failed.\n");
            exit(1);
        }
        if (!RAND_bytes((unsigned char*) (cs1 + aStart), 16)) {
            printf("Random bytes failed.\n");
            exit(1);
        }
        if (!RAND_bytes((unsigned char*) (cs0 + naStart), 16)) {
            printf("Random bytes failed.\n");
            exit(1);
        }

        for (uint32_t j = 0; j < 16; j++) {
            cs1[naStart+j] = s0[naStart+j] ^ s1[naStart+j] ^ cs0[naStart+j];
        }

        if (!RAND_bytes(temp, 2)) {
            printf("Random bytes failed.\n");
            exit(1);
        }
        ct0[a] = temp[0] % 2;
        ct1[a] = ct0[a] ^ t0[a] ^ t1[a] ^ 1;

        ct0[na] = temp[1] % 2;
        ct1[na] = ct0[na] ^ t0[na] ^ t1[na];

        //printf("ct0: %d %d, ct1: %d %d, t0: %d %d, t1: %d %d\n", ct0[0], ct0[1], ct1[0], ct1[1], t0[0], t0[1], t1[0], t1[1]);
        //printf("t0: %d %d, t1: %d %d\n", t0[0], t0[1], t1[0], t1[1]);
        // Copy appropriate values into key
        memcpy(k0->cw[0][i].cs[0], cs0, 16);
        memcpy(k0->cw[0][i].cs[1], (unsigned char*) (cs0 + 16), 16);
        k0->cw[0][i].ct[0] = ct0[0];
        k0->cw[0][i].ct[1] = ct0[1];
        memcpy(k0->cw[1][i].cs[0], cs1, 16);
        memcpy(k0->cw[1][i].cs[1], (unsigned char*) (cs1 + 16), 16);
        k0->cw[1][i].ct[0] = ct1[0];
        k0->cw[1][i].ct[1] = ct1[1];

        memcpy(k1->cw[0][i].cs[0], cs0, 16);
        memcpy(k1->cw[0][i].cs[1], (unsigned char*) (cs0 + 16), 16);
        k1->cw[0][i].ct[0] = ct0[0];
        k1->cw[0][i].ct[1] = ct0[1];
        memcpy(k1->cw[1][i].cs[0], cs1, 16);
        memcpy(k1->cw[1][i].cs[1], (unsigned char*) (cs1 + 16), 16);
        k1->cw[1][i].ct[0] = ct1[0];
        k1->cw[1][i].ct[1] = ct1[1];

        unsigned char* cs;
        unsigned char* ct;

        if (tbit0 == 1) {
            cs = cs1;
            ct = ct1;
        } else {
            cs = cs0;
            ct = ct0;
        }
        for (uint32_t j = 0; j < 16; j++) {
            key0[j] = s0[aStart+j] ^ cs[aStart+j];
        }
        tbit0 = t0[a] ^ ct[a];

        if (tbit1 == 1) {
            cs = cs1;
            ct = ct1;
        } else {
            cs = cs0;
            ct = ct0;
        }
        for (uint32_t j = 0; j < 16; j++) {
            key1[j] = s1[aStart+j] ^ cs[aStart+j];
        }
        tbit1 = t1[a] ^ ct[a];
    }

    // Set the w in the keys
    unsigned char intArray0[34];
    unsigned char intArray1[34];
    memcpy(intArray0, s0, 32);
    intArray0[32] = t0[0];
    intArray0[33] = t0[1];
    memcpy(intArray1, s1, 32);
    intArray1[32] = t1[0];
    intArray1[33] = t1[1];

    mpz_class sInt0, sInt1;

    mpz_import(sInt0.get_mpz_t(), 34, 1, sizeof(intArray0[0]), 0, 0, intArray0);
    mpz_import(sInt1.get_mpz_t(), 34, 1, sizeof(intArray1[0]), 0, 0, intArray1);

    if (sInt0 != sInt1) {
        mpz_class diff = sInt0 - sInt1;
        mpz_invert(diff.get_mpz_t(), diff.get_mpz_t(), f->prime.get_mpz_t());
        mpz_class temp_b;
        mpz_import(temp_b.get_mpz_t(), 1, -1, sizeof (uint64_t), 0, 0, &b_i);
        k0->w = (diff * temp_b) % f->prime;
        k1->w = k0->w;
    } else {
        k0->w = 0;
        k1->w = 0;
    }
}
