#ifndef SMP_H
#define SMP_H

#include <gmp.h>
#include <stdbool.h>

#include "include/util.h"

/*
 * Object for Socialist Millionaire Protocol Interactions.
 */

struct smp {
    mpz_t mod;
    mpz_t modOrder;
    mpz_t gen;
    mpz_t secret;
    bool match;

    mpz_t x2;
    mpz_t x3;

    mpz_t g2;
    mpz_t g3;

    mpz_t g2a;
    mpz_t g3a;

    mpz_t g2b;
    mpz_t g3b;

    mpz_t ga2;
    mpz_t ga3;

    mpz_t gb2;
    mpz_t gb3;

    mpz_t pa;
    mpz_t pb;

    mpz_t qa;
    mpz_t qb;

    mpz_t ra;
};

typedef struct smp smp_t;

/* Initialize Socialist Millionaire Object */
smp_t* smp_init(chat_variable_t* key);

/* Deinitialize Socialist Millionaire Object */
void smp_clean(smp_t* obj);

/* Do step 1 of Socialist Millionaire */
chat_variable_t* smp_step1(smp_t* smp);

/* Do step 2 of Socialist Millionare */
chat_variable_t* smp_step2(smp_t* smp, chat_variable_t* buffer);

/* Take a guess. */
chat_variable_t* smp_step3(smp_t* smp, chat_variable_t* buffer);

/* No really */
chat_variable_t* smp_step4(smp_t* smp, chat_variable_t* buffer);

/* What do you think */
void smp_step5(smp_t* smp, chat_variable_t* buffer);


/* Functions for internal usage only */
void smp_create_log_proof(smp_t* obj, char* version, mpz_t x, mpz_t c, mpz_t d);
bool smp_check_log_proof(smp_t* obj, char* version, mpz_t g, mpz_t c, mpz_t d);

void smp_create_coords_proof(smp_t* obj, char* version, mpz_t g2, mpz_t g3, mpz_t r, mpz_t c, mpz_t d1, mpz_t d2);
bool smp_check_coords_proof(smp_t* obj, char* version, mpz_t c, mpz_t d1, mpz_t d2, mpz_t g2, mpz_t g3, mpz_t p, mpz_t q);

void smp_create_equal_logs_proof(smp_t* obj, char* version, mpz_t qa, mpz_t qb, mpz_t x, mpz_t c, mpz_t d);
bool smp_check_equal_logs_proof(smp_t* obj, char* version, mpz_t c, mpz_t d, mpz_t g3, mpz_t qab, mpz_t r);

void smp_invm(smp_t* obj, mpz_t x, mpz_t y);
bool smp_valid_argument(smp_t* obj, mpz_t x);

#endif
