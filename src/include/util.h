#ifndef UTIL_H
#define UTIL_H

#include <gmp.h>

/*
 * For all intents and purposes
 * any references to a "variable"
 * is refering to the struct below.
 */

struct chat_variable {
    unsigned char* data;
    size_t length;
};

typedef struct chat_variable chat_variable_t;

/* Exports number into a variable */
chat_variable_t* export_number(mpz_t number);

/* Imports from a variable into a number */
void import_number(chat_variable_t* bytes, mpz_t number);

/* Packs a list of variables into a variable */
void pack_variables(chat_variable_t** bytes, size_t count, chat_variable_t* output);

/* Unpacks a variable into a list of variables */
size_t unpack_variables(chat_variable_t* packed, chat_variable_t*** bytes);

/* Makes and Cleans up a chat_variable_t for the lAZY PEOPLE */
chat_variable_t* chat_variable_init(size_t length);
void chat_variable_clean(chat_variable_t* obj);
void chat_variable_cleans(chat_variable_t** obj, size_t count);

#endif
