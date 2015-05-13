#include <stdio.h>			/* for printf */
#include <stdlib.h>
#include <gmp.h>

#include "include/chacha20.h"
#include "include/curve25519.h"
#include "include/random.h"
#include "include/smp.h"

int main(int argc, char *argv[]) {
    mpz_t _a_secret, _b_secret, _nonce, _data;
    mpz_initrandom(_a_secret, 32);
    mpz_initrandom(_b_secret, 32);
    mpz_initrandom(_nonce, 8);
    mpz_initrandom(_data, 128);

    chat_variable_t* nonce = export_number(_nonce);
    chat_variable_t* data = export_number(_data);

    chat_variable_t* alice_secret = export_number(_a_secret);
    chat_variable_t* bob_secret = export_number(_b_secret);

    chat_variable_t* alice_public = chat_variable_init(32);
    chat_variable_t* bob_public = chat_variable_init(32);

    chat_variable_t* secret = chat_variable_init(32);

    chacha20_t* obj = chacha20_init(secret, nonce);
    chacha20_t* obj2 = chacha20_init(secret, nonce);

    unsigned char basepoint[32] = {9};

    printf("Curve25519...\n");

    curve25519_donna(alice_public->data, alice_secret->data, basepoint);
    curve25519_donna(bob_public->data, bob_secret->data, basepoint);

    curve25519_donna(secret->data, alice_secret->data, bob_public->data);

    chat_variable_t* output = chat_variable_init(0);
    chat_variable_t* output2 = chat_variable_init(0);

    printf("Testing Socialist Millionaire...\n");

    smp_t* alice = smp_init(secret);
    smp_t* bob = smp_init(secret);

    printf("Initialized...\n");

    chat_variable_t* out = smp_step1(alice);
    if ( out == NULL ) goto clean;
    out = smp_step2(bob, out);
    if ( out == NULL ) goto clean;
    out = smp_step3(alice, out);
    if ( out == NULL ) goto clean;
    out = smp_step4(bob, out);
    if ( out == NULL ) goto clean;
    smp_step5(alice, out);
    if ( out == NULL ) goto clean;

    if(bob->match) printf("Bob agrees\n"); else printf("Bob disagrees\n");
    if(alice->match) printf("Alice agrees\n"); else printf("Alice disagrees\n");

    printf("Socialist Millionaire Complete!\nChaCha20 Test...\n");

    chacha20_xor(obj, data, output);
    chacha20_xor(obj2, output, output2);

    for(int i = 0; i < 128; i++) {
        if(data->data[i] != output2->data[i]) {
            printf("[%d] - FAIL\n", i);
            break;
        }
        else {
            printf("[%d] - SUCCESS\n", i);
        }
    }

clean:
    mpz_clears(_a_secret, _b_secret, _nonce, _data, NULL);

    chat_variable_clean(alice_secret);
    chat_variable_clean(bob_secret);
    chat_variable_clean(alice_public);
    chat_variable_clean(bob_public);
    chat_variable_clean(secret);
    chat_variable_clean(nonce);
    chat_variable_clean(data);
    chat_variable_clean(output);
    chat_variable_clean(output2);

    chacha20_clean(obj);
    chacha20_clean(obj2);

    smp_clean(alice);
    smp_clean(bob);

    chat_variable_clean(out);
    return 0;
}
