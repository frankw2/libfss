#include "fss-common.h"
#include "fss-server.h"
#include "fss-client.h"

int main()
{
    // Set up variables
    uint64_t a = 3;
    uint64_t b = 1;
    Fss f;
    ServerKeyEq k0;
    ServerKeyEq k1;

    // Initialize client, use 10 bits in domain as example
    initializeClient(&f, 10); 
    
    // Equality FSS test
    generateTreeEq(&f, &k0, &k1, a, b);
    
    mpz_class ans0, ans1, fin;
    
    ans0 = evaluateEq(&f, &k0, a);
    ans1 = evaluateEq(&f, &k1, a);
    fin = ans0 - ans1;
    cout << "FSS Eq Match (should be non-zero): " << fin << endl;
    
    ans0 = evaluateEq(&f, &k0, (a+1));
    ans1 = evaluateEq(&f, &k1, (a+1));
    fin = ans0 - ans1;
    cout << "FSS Eq No Match (should be 0): " << fin << endl;

    // Less than FSS test
    ServerKeyLt lt_k0;
    ServerKeyLt lt_k1;
    
    generateTreeLt(&f, &lt_k0, &lt_k1, a, b);

    uint64_t lt_ans0, lt_ans1, lt_fin;

    lt_ans0 = evaluateLt(&f, &lt_k0, (a-1));
    lt_ans1 = evaluateLt(&f, &lt_k1, (a-1));
    lt_fin = lt_ans0 - lt_ans1;
    cout << "FSS Lt Match (should be non-zero): " << lt_fin << endl;

    lt_ans0 = evaluateLt(&f, &lt_k0, a);
    lt_ans1 = evaluateLt(&f, &lt_k1, a);
    lt_fin = lt_ans0 - lt_ans1;
    cout << "FSS Lt Match (should be 0): " << lt_fin << endl;

    return 1;
}
