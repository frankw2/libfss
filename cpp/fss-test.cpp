#include "fss-common.h"
#include "fss-server.h"
#include "fss-client.h"

int main()
{
    // Set up variables
    uint64_t a = 2;
    uint64_t b = 1;
    Fss f;
    ServerKeyEq k0;
    ServerKeyEq k1;

    // Initialize client, use 10 bits in domain as example
    initializeClient(&f, 10); 
    generateTreeEq(&f, &k0, &k1, a, b);
    
    mpz_class ans0, ans1, fin;
    
    ans0 = evaluateEq(&f, &k0, 2);
    ans1 = evaluateEq(&f, &k1, 2);
    fin = ans0 - ans1;
    cout << "FSS Eq Match (should be non-zero): " << fin << endl;
    
    ans0 = evaluateEq(&f, &k0, 3);
    ans1 = evaluateEq(&f, &k1, 3);
    fin = ans0 - ans1;
    cout << "FSS Eq No Match (should be 0): " << fin << endl;

    return 1;
}
