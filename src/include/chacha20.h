#ifndef CHACHA20_H
#define CHACHA20_H

#include <stdint.h>
#include "include/util.h"

struct chacha20 {
    int32_t* state;
};

typedef struct chacha20 chacha20_t;

/* Initializes the ChaCha20 object */
chacha20_t* chacha20_init(chat_variable_t* key, chat_variable_t* nonce);

/* Deinitializes the ChaCha20 object */
void chacha20_clean(chacha20_t* obj);

/* Runs ChaCha20 */
void chacha20_xor(chacha20_t* obj, chat_variable_t* data, chat_variable_t* output);

#endif
