#ifndef CURVE25519_H
#define CURVE25519_H

#include <stdint.h>

/* Performs the curve25519 computations */
int curve25519_donna(uint8_t *mypublic, const uint8_t *secret, const uint8_t *basepoint);

#endif
