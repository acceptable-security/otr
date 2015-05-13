#ifndef RANDOM_H
#define RANDOM_H

#include <gmp.h>

void mpz_initrandom(mpz_t obj, size_t bytes);
void mpz_cryptorandom(mpz_t obj, size_t bytes);

#endif
