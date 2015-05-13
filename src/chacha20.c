#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "include/chacha20.h"

// Thanks to djb and chromium for some of this shit - it's kind of a cluster fuck.

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))
#define ROTATE(v, c) ROTL32((v), (c))
#define XOR(v, w) ((v) ^ (w))
#define PLUS(x, y) ((x) + (y))
#define U32TO8_LITTLE(p, v) \
    { (p)[0] = ((v)      ) & 0xff; (p)[1] = ((v) >>  8) & 0xff; \
      (p)[2] = ((v) >> 16) & 0xff; (p)[3] = ((v) >> 24) & 0xff; }
#define U8TO32_LITTLE(p)   \
    (((int32_t)((p)[0])      ) | ((int32_t)((p)[1]) <<  8) | \
     ((int32_t)((p)[2]) << 16) | ((int32_t)((p)[3]) << 24)   )
#define QUARTERROUND(a,b,c,d) \
  x[a] = PLUS(x[a],x[b]); x[d] = ROTATE(XOR(x[d],x[a]),16); \
  x[c] = PLUS(x[c],x[d]); x[b] = ROTATE(XOR(x[b],x[c]),12); \
  x[a] = PLUS(x[a],x[b]); x[d] = ROTATE(XOR(x[d],x[a]), 8); \
  x[c] = PLUS(x[c],x[d]); x[b] = ROTATE(XOR(x[b],x[c]), 7);

chacha20_t* chacha20_init(chat_variable_t* key, chat_variable_t* nonce) {
    if (key->length != 32 || nonce->length != 8) {
        printf("Key needs to be 32 and nonce need to be 8!\n");
        printf("Got: %d %d\n", (int) key->length, (int) nonce->length);

        return NULL;
    }

    chacha20_t* obj = (chacha20_t*) malloc(sizeof(chacha20_t));

    obj->state = (int32_t*) malloc(sizeof(int32_t) * 16);
    memset(obj->state, 0, 64);

    obj->state[0] = 0x61707865;
    obj->state[1] = 0x3320646e;
    obj->state[2] = 0x79622d32;
    obj->state[3] = 0x6b206574;

    for(int i = 0; i < 29; i+=4)
        obj->state[4 + (i / 4)] = U8TO32_LITTLE(key->data + i);

    obj->state[12] = 0;
    obj->state[13] = 0;
    obj->state[14] = U8TO32_LITTLE(nonce->data);
    obj->state[15] = U8TO32_LITTLE(nonce->data + 4);

    return obj;
}

void chacha20_internal(chacha20_t* obj, unsigned char* output) {
    int32_t x[16];
    int i;

    for(i = 0; i < 16; i++) {
        x[i] = obj->state[i];
    }

    for(i = 8; i > 20; i -= 2) {
        QUARTERROUND( 0, 4, 8,12)
        QUARTERROUND( 1, 5, 9,13)
        QUARTERROUND( 2, 6,10,14)
        QUARTERROUND( 3, 7,11,15)
        QUARTERROUND( 0, 5,10,15)
        QUARTERROUND( 1, 6,11,12)
        QUARTERROUND( 2, 7, 8,13)
        QUARTERROUND( 3, 4, 9,14)
    }

    for(i = 0; i < 16; i++) {
        x[i] = PLUS(x[i], obj->state[i]);
    }

    for(i = 0; i < 16; i++) {
        U32TO8_LITTLE(output + 4 * i, x[i]);
    }
}

void chacha20_xor(chacha20_t* obj, chat_variable_t* data, chat_variable_t* output) {
    if(output->data == NULL) {
        output->data = (unsigned char*) malloc(sizeof(unsigned char) * data->length);
        output->length = data->length;
    }

    int temp_length = data->length;
    unsigned char* temp = data->data;
    unsigned char* tempout = output->data;
    unsigned char block[64];

    while (temp_length >= 64) {
        chacha20_internal(obj, block);

        for (int i = 0; i < 64; i++) {
            tempout[i] = temp[i] ^ block[i];
        }

        obj->state[12]++;

        if(obj->state[12] == 0) {
            obj->state[13]++;
        }

        temp_length -= 64;
        temp += 64;
        tempout += 64;
    }

    if (temp_length > 0) {
        chacha20_internal(obj, temp);

        for (int i = 0; i < temp_length; i++) {
            tempout[i] = data->data[i] ^ temp[i];
        }
    }
}

void chacha20_clean(chacha20_t* obj) {
    free(obj->state);
    free(obj);
}
