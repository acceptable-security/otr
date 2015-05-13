#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "include/random.h"
#include "include/sha256.h"
#include "include/smp.h"

#define GENERATOR "2"
#define MODULUS "2410312426921032588552076022197566074856950548502459942654116941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919"

smp_t* smp_init(chat_variable_t* key) {
    smp_t* obj = (smp_t*) malloc(sizeof(smp_t));

    mpz_init_set_str(obj->mod, MODULUS, 10);
    mpz_init(obj->modOrder);

    // modOrder = (modulus - 1) / 2

    mpz_sub_ui(obj->modOrder, obj->mod, 1);
    mpz_div_ui(obj->modOrder, obj->modOrder, 2);

    obj->match = false;

    mpz_init_set_str(obj->gen, GENERATOR, 10);

    mpz_init(obj->x2);
    mpz_init(obj->x3);

    mpz_init(obj->g2);
    mpz_init(obj->g3);

    mpz_init(obj->g2a);
    mpz_init(obj->g3a);

    mpz_init(obj->g2b);
    mpz_init(obj->g3b);

    mpz_init(obj->ga2);
    mpz_init(obj->ga3);

    mpz_init(obj->gb2);
    mpz_init(obj->gb3);

    mpz_init(obj->pa);
    mpz_init(obj->pb);

    mpz_init(obj->qa);
    mpz_init(obj->qb);

    mpz_init(obj->ra);

    mpz_init(obj->secret);
    import_number(key, obj->secret);

    return obj;
}

void smp_clean(smp_t* obj) {
    mpz_clear(obj->mod);
    mpz_clear(obj->modOrder);
    mpz_clear(obj->gen);

    mpz_clear(obj->x2);
    mpz_clear(obj->x3);

    mpz_clear(obj->g2);
    mpz_clear(obj->g3);

    mpz_clear(obj->g2a);
    mpz_clear(obj->g3a);

    mpz_clear(obj->g2b);
    mpz_clear(obj->g3b);

    mpz_clear(obj->ga2);
    mpz_clear(obj->ga3);

    mpz_clear(obj->gb2);
    mpz_clear(obj->gb3);

    mpz_clear(obj->pa);
    mpz_clear(obj->pb);

    mpz_clear(obj->qa);
    mpz_clear(obj->qb);

    mpz_clear(obj->ra);

    free(obj);
}

void debug_variable(chat_variable_t* obj) {
    for(int i = 0; i < obj->length; i++)
        printf("%d ", obj->data[i]);
    printf("\n");
}

void debug_number(mpz_t number, int base) {
    char* num = (char*) malloc(sizeof(char) * mpz_sizeinbase(number, base) + 2);

    mpz_get_str(num, base, number);

    printf("%s\n", num);

    free(num);
}

chat_variable_t* smp_step1(smp_t* obj) {
    mpz_cryptorandom(obj->x2, 192);
    mpz_cryptorandom(obj->x3, 192);

    mpz_powm(obj->g2, obj->gen, obj->x2, obj->mod); // g2 = gen ^ x2 % mod
    mpz_powm(obj->g3, obj->gen, obj->x3, obj->mod); // g3 = gen ^ x3 % mod

    mpz_t c1, d1;
    mpz_t c2, d2;

    mpz_inits(c1, d1, c2, d2, NULL);

    smp_create_log_proof(obj, "1", obj->x2, c1, d1);
    smp_create_log_proof(obj, "2", obj->x3, c2, d2);


    chat_variable_t* _g2 = export_number(obj->g2);
    chat_variable_t* _g3 = export_number(obj->g3);
    chat_variable_t* _c1 = export_number(c1);
    chat_variable_t* _d1 = export_number(d1);
    chat_variable_t* _c2 = export_number(c2);
    chat_variable_t* _d2 = export_number(d2);

    chat_variable_t* out[6] = { _g2, _g3, _c1, _d1, _c2, _d2 };

    chat_variable_t* variable = chat_variable_init(0);

    pack_variables(out, 6, variable);

    chat_variable_clean(_g2);
    chat_variable_clean(_g3);
    chat_variable_clean(_c1);
    chat_variable_clean(_d1);
    chat_variable_clean(_c2);
    chat_variable_clean(_d2);

    mpz_clears(c1, d1, c2, d2, NULL);

    return variable;
}

chat_variable_t* smp_step2(smp_t* obj, chat_variable_t* buffer) {
    mpz_t g2a, g3a, c1, d1, c2, d2;

    mpz_inits(g2a, g3a, c1, d1, c2, d2, NULL);

    chat_variable_t** bytes;

    size_t length = unpack_variables(buffer, &bytes);

    if (length != 6) {
        mpz_clears(g2a, g3a, c1, d1, c2, d2, NULL);

        printf("ERROR: Step 2 didn't get 6 variables. :(\n");
        return NULL;
    }

    import_number(bytes[0], g2a);
    import_number(bytes[1], g3a);
    import_number(bytes[2], c1);
    import_number(bytes[3], d1);
    import_number(bytes[4], c2);
    import_number(bytes[5], d2);

    if (!smp_valid_argument(obj, g2a) || !smp_valid_argument(obj, g3a)) {
        mpz_clears(g2a, g3a, c1, d1, c2, d2, NULL);

        chat_variable_cleans(bytes, 6);

        printf("ERROR: Step 2 got invalid g2a/g3a values.\n");
        return NULL;
    }


    if (!smp_check_log_proof(obj, "1", g2a, c1, d1)) {
        mpz_clears(g2a, g3a, c1, d1, c2, d2, NULL);
        chat_variable_cleans(bytes, 6);

        printf("ERROR: Proof 1 check failed.\n");
        return NULL;
    }

    if (!smp_check_log_proof(obj, "2", g3a, c2, d2)) {
        mpz_clears(g2a, g3a, c1, d1, c2, d2, NULL);
        chat_variable_cleans(bytes, 6);

        printf("ERROR: Proof 2 check failed.\n");
        return NULL;
    }

    // self.g2 = pow(self.gen, self.x2, self.mod)
    // self.g3 = pow(self.gen, self.x3, self.mod)
    //
    // (c3, d3) = self.createLogProof('3', self.x2)
    // (c4, d4) = self.createLogProof('4', self.x3)
    //
    // self.gb2 = pow(self.g2a, self.x2, self.mod)
    // self.gb3 = pow(self.g3a, self.x3, self.mod)
    //
    // self.pb = pow(self.gb3, r, self.mod)
    // self.qb = mulm(pow(self.gen, r, self.mod), pow(self.gb2, self.secret, self.mod), self.mod)


    mpz_set(obj->g2a, g2a);
    mpz_set(obj->g3a, g3a);

    mpz_cryptorandom(obj->x2, 192);
    mpz_cryptorandom(obj->x3, 192);

    mpz_t r;
    mpz_init(r);
    mpz_cryptorandom(r, 192);

    mpz_powm(obj->g2, obj->gen, obj->x2, obj->mod);
    mpz_powm(obj->g3, obj->gen, obj->x3, obj->mod);

    mpz_t c3, d3;
    mpz_t c4, d4;

    mpz_inits(c3, d3, c4, d4, NULL);

    smp_create_log_proof(obj, "3", obj->x2, c3, d3);
    smp_create_log_proof(obj, "4", obj->x3, c4, d4);

    mpz_powm(obj->gb2, obj->g2a, obj->x2, obj->mod);
    mpz_powm(obj->gb3, obj->g3a, obj->x3, obj->mod);

    mpz_powm(obj->pb, obj->gb3, r, obj->mod);

    mpz_t tmp1, tmp2;

    mpz_inits(tmp1, tmp2, NULL);

    mpz_powm(tmp1, obj->gen, r, obj->mod);
    mpz_powm(tmp2, obj->gb2, obj->secret, obj->mod);
    mpz_mul(obj->qb, tmp1, tmp2);
    mpz_mod(obj->qb, obj->qb, obj->mod);

    mpz_t c5, d5, d6;

    mpz_inits(c5, d5, d6, NULL);

    //(c5, d5, d6) = self.createCoordsProof('5', self.gb2, self.gb3, r)
    smp_create_coords_proof(obj, "5", obj->gb2, obj->gb3, r, c5, d5, d6);


    //packList(self.g2, self.g3, self.pb, self.qb, c3, d3, c4, d4, c5, d5, d6)
    chat_variable_t* _g2 = export_number(obj->g2);
    chat_variable_t* _g3 = export_number(obj->g3);
    chat_variable_t* _pb = export_number(obj->pb);
    chat_variable_t* _qb = export_number(obj->qb);
    chat_variable_t* _c3 = export_number(c3);
    chat_variable_t* _d3 = export_number(d3);
    chat_variable_t* _c4 = export_number(c4);
    chat_variable_t* _d4 = export_number(d4);
    chat_variable_t* _c5 = export_number(c5);
    chat_variable_t* _d5 = export_number(d5);
    chat_variable_t* _d6 = export_number(d6);

    chat_variable_t* out[11] = { _g2, _g3, _pb, _qb, _c3, _d3, _c4, _d4, _c5, _d5, _d6 };

    chat_variable_t* variable = chat_variable_init(0);

    pack_variables(out, 11, variable);

    chat_variable_clean(_g2);
    chat_variable_clean(_g3);
    chat_variable_clean(_pb);
    chat_variable_clean(_qb);
    chat_variable_clean(_c3);
    chat_variable_clean(_d3);
    chat_variable_clean(_c4);
    chat_variable_clean(_d4);
    chat_variable_clean(_c5);
    chat_variable_clean(_d5);
    chat_variable_clean(_d6);

    mpz_clears(g2a, g3a, c1, d1, c2, d2, c3, d3, c4, d4, tmp1, tmp2, c5, d5, d6, NULL);

    chat_variable_cleans(bytes, 6);

    return variable;
}

chat_variable_t* smp_step3(smp_t* obj, chat_variable_t* buffer) {
    mpz_t g2b, g3b, pb, qb, c3, d3, c4, d4, c5, d5, d6;

    mpz_inits(g2b, g3b, pb, qb, c3, d3, c4, d4, c5, d5, d6, NULL);

    chat_variable_t** bytes;

    size_t length = unpack_variables(buffer, &bytes);

    if (length != 11) {
        mpz_clears(g2b, g3b, pb, qb, c3, d3, c4, d4, c5, d5, d6, NULL);
        chat_variable_cleans(bytes, 11);

        printf("ERROR: Step 2 didn't get 6 variables. :(\n");
        return NULL;
    }

    import_number(bytes[0], g2b);
    import_number(bytes[1], g3b);
    import_number(bytes[2], pb);
    import_number(bytes[3], qb);
    import_number(bytes[4], c3);
    import_number(bytes[5], d3);
    import_number(bytes[6], c4);
    import_number(bytes[7], d4);
    import_number(bytes[8], c5);
    import_number(bytes[9], d5);
    import_number(bytes[10], d6);

    if (!smp_valid_argument(obj, g2b) || !smp_valid_argument(obj, g3b) || !smp_valid_argument(obj, pb) || !smp_valid_argument(obj, qb)) {
        mpz_clears(g2b, g3b, pb, qb, c3, d3, c4, d4, c5, d5, d6, NULL);
        chat_variable_cleans(bytes, 11);

        printf("ERROR: Step 2 got invalid g2a/g3a values.\n");
        return NULL;
    }

    if (!smp_check_log_proof(obj, "3", g2b, c3, d3)) {
        mpz_clears(g2b, g3b, pb, qb, c3, d3, c4, d4, c5, d5, d6, NULL);
        chat_variable_cleans(bytes, 11);

        printf("ERROR: Proof 3 check failed.\n");
        return NULL;
    }

    if (!smp_check_log_proof(obj, "4", g3b, c4, d4)) {
        mpz_clears(g2b, g3b, pb, qb, c3, d3, c4, d4, c5, d5, d6, NULL);
        chat_variable_cleans(bytes, 11);

        printf("ERROR: Proof 4 check failed.\n");
        return NULL;
    }

    mpz_set(obj->g2b, g2b);
    mpz_set(obj->g3b, g3b);

    mpz_powm(obj->ga2, obj->g2b, obj->x2, obj->mod);
    mpz_powm(obj->ga3, obj->g3b, obj->x3, obj->mod);

    if (!smp_check_coords_proof(obj, "5", c5, d5, d6, obj->ga2, obj->ga3, pb, qb)) {
        mpz_clears(g2b, g3b, pb, qb, c3, d3, c4, d4, c5, d5, d6, NULL);
        chat_variable_cleans(bytes, 11);

        printf("ERROR: Proof 5 check failed.\n");
        return NULL;
    }

    mpz_t tmp1, tmp2;
    mpz_init(tmp1);
    mpz_init(tmp2);

    // self.qa = mulm(t1, pow(self.ga2, self.secret, self.mod), self.mod)

    mpz_t s;
    mpz_init(s);
    mpz_cryptorandom(s, 192);

    mpz_set(obj->qb, qb);
    mpz_set(obj->pb, pb);
    mpz_powm(obj->pa, obj->ga3, s, obj->mod);

    mpz_powm(tmp1, obj->gen, s, obj->mod);
    mpz_powm(tmp2, obj->ga2, obj->secret, obj->mod);
    mpz_mul(obj->qa, tmp1, tmp2);
    mpz_mod(obj->qa, obj->qa, obj->mod);

    mpz_t c6, d7, d8;
    mpz_inits(c6, d7, d8, NULL);

    smp_create_coords_proof(obj, "6", obj->ga2, obj->ga3, s, c6, d7, d8);

    mpz_t inv;
    mpz_init(inv);
    smp_invm(obj, qb, inv);

    mpz_mul(tmp1, obj->qa, inv);
    mpz_mod(tmp1, tmp1, obj->mod);
    mpz_powm(obj->ra, tmp1, obj->x3, obj->mod);

    mpz_t c7, d9;
    mpz_inits(c7, d9, NULL);

    smp_create_equal_logs_proof(obj, "7", obj->qa, inv, obj->x3, c7, d9);

    chat_variable_t* _pa = export_number(obj->pa);
    chat_variable_t* _qa = export_number(obj->qa);
    chat_variable_t* _ra = export_number(obj->ra);
    chat_variable_t* _c6 = export_number(c6);
    chat_variable_t* _d7 = export_number(d7);
    chat_variable_t* _d8 = export_number(d8);
    chat_variable_t* _c7 = export_number(c7);
    chat_variable_t* _d9 = export_number(d9);

    chat_variable_t* out[8] = { _pa, _qa, _ra, _c6, _d7, _d8, _c7, _d9 };

    chat_variable_t* variable = chat_variable_init(0);

    pack_variables(out, 8, variable);

    chat_variable_clean(_pa);
    chat_variable_clean(_qa);
    chat_variable_clean(_ra);
    chat_variable_clean(_c6);
    chat_variable_clean(_d7);
    chat_variable_clean(_d8);
    chat_variable_clean(_c7);
    chat_variable_clean(_d9);

    mpz_clears(g2b, g3b, pb, qb, c3, d3, c4, d4, c5, d5, d6, tmp1, tmp2, s, c6, d7, d8, inv, c7, d9, NULL);

    chat_variable_cleans(bytes, 10);

    return variable;
}

chat_variable_t* smp_step4(smp_t* obj, chat_variable_t* buffer) {
    mpz_t pa, qa, ra, c6, d7, d8, c7, d9;

    mpz_inits(pa, qa, ra, c6, d7, d8, c7, d9, NULL);

    chat_variable_t** bytes;

    size_t length = unpack_variables(buffer, &bytes);

    if (length != 8) {
        mpz_clears(pa, qa, ra, c6, d7, d8, c7, d9, NULL);
        chat_variable_cleans(bytes, 8);

        printf("ERROR: Step 4 didn't get 8 variables. :(\n");
        return NULL;
    }

    import_number(bytes[0], pa);
    import_number(bytes[1], qa);
    import_number(bytes[2], ra);
    import_number(bytes[3], c6);
    import_number(bytes[4], d7);
    import_number(bytes[5], d8);
    import_number(bytes[6], c7);
    import_number(bytes[7], d9);

    if (!smp_valid_argument(obj, pa) || !smp_valid_argument(obj, qa) || !smp_valid_argument(obj, ra)) {
        mpz_clears(pa, qa, ra, c6, d7, d8, c7, d9, NULL);
        chat_variable_cleans(bytes, 8);

        printf("ERROR: Step 4 got invalid g2a/g3a values.\n");
        return NULL;
    }

    if (!smp_check_coords_proof(obj, "6", c6, d7, d8, obj->gb2, obj->gb3, pa, qa)) {
        mpz_clears(pa, qa, ra, c6, d7, d8, c7, d9, NULL);
        chat_variable_cleans(bytes, 8);

        printf("ERROR: Proof 6 check failed.\n");
        return NULL;
    }

    mpz_t inv, tmp2;
    mpz_inits(inv, tmp2, NULL);

    smp_invm(obj, obj->qb, inv);
    mpz_mul(tmp2, qa, inv);
    mpz_mod(tmp2, tmp2, obj->mod);

    if (!smp_check_equal_logs_proof(obj, "7", c7, d9, obj->g3a, tmp2, ra)) {
        mpz_clears(pa, qa, ra, c6, d7, d8, c7, d9, inv, tmp2, NULL);
        chat_variable_cleans(bytes, 8);

        printf("ERROR: Proof 7 check failed.\n");
        return NULL;
    }

    mpz_t rb;
    mpz_init(rb);

    mpz_mul(tmp2, qa, inv);
    mpz_mod(tmp2, tmp2, obj->mod);
    mpz_powm(rb, tmp2, obj->x3, obj->mod);

    mpz_t c8, d10;
    mpz_inits(c8, d10, NULL);

    smp_create_equal_logs_proof(obj, "8", qa, inv, obj->x3, c8, d10);

    mpz_t rab;
    mpz_init(rab);

    mpz_powm(rab, ra, obj->x3, obj->mod);

    smp_invm(obj, obj->pb, inv);

    mpz_mul(tmp2, pa, inv);
    mpz_mod(tmp2, tmp2, obj->mod);

    if (mpz_cmp(rab, tmp2) == 0) {
        obj->match = true;
    }

    chat_variable_t* _rb = export_number(rb);
    chat_variable_t* _c8 = export_number(c8);
    chat_variable_t* _d10 = export_number(d10);

    chat_variable_t* out[3] = { _rb, _c8, _d10 };

    chat_variable_t* variable = chat_variable_init(0);

    pack_variables(out, 3, variable);

    chat_variable_clean(_rb);
    chat_variable_clean(_c8);
    chat_variable_clean(_d10);

    mpz_clears(pa, qa, ra, c6, d7, d8, c7, d9, inv, tmp2, rb, c8, d10, rab, NULL);

    chat_variable_cleans(bytes, 8);

    return variable;
}

void smp_step5(smp_t* obj, chat_variable_t* buffer) {
    mpz_t rb, c8, d10;

    mpz_inits(rb, c8, d10, NULL);

    chat_variable_t** bytes;

    size_t length = unpack_variables(buffer, &bytes);

    if (length != 3) {
        mpz_clears(rb, c8, d10, NULL);
        chat_variable_cleans(bytes, 3);

        printf("ERROR: Step 5 didn't get 3 variables. :(\n");
        return;
    }

    import_number(bytes[0], rb);
    import_number(bytes[1], c8);
    import_number(bytes[2], d10);

    if (!smp_valid_argument(obj, rb)) {
        mpz_clears(rb, c8, d10, NULL);
        chat_variable_cleans(bytes, 3);

        printf("ERROR: Step 5 got invalid rb values.\n");
        return;
    }

    mpz_t tmp1, tmp2;
    mpz_inits(tmp1, tmp2, NULL);

    smp_invm(obj, obj->qb, tmp1);
    mpz_mul(tmp2, obj->qa, tmp1);
    mpz_mod(tmp2, tmp2, obj->mod);

    if (!smp_check_equal_logs_proof(obj, "8", c8, d10, obj->g3b, tmp2, rb)) {
        mpz_clears(rb, c8, d10, NULL);
        chat_variable_cleans(bytes, 3);

        printf("ERROR: Proof 8 failed! Close but no cigar.\n");
        return;
    }

    // rab = pow(rb, self.x3, self.mod)
    //
    //    inv = self.invm(self.pb)
    //    if rab == mulm(self.pa, inv, self.mod):
    //        self.match = True

    mpz_t rab, inv;
    mpz_inits(rab, inv, NULL);

    mpz_powm(rab, rb, obj->x3, obj->mod);

    smp_invm(obj, obj->pb, inv);

    mpz_mul(tmp1, obj->pa, inv);
    mpz_mod(tmp1, tmp1, obj->mod);

    if (mpz_cmp(rab, tmp1) == 0)
        obj->match = true;

    mpz_clears(rb, c8, d10, tmp1, tmp2, rab, inv, NULL);
    chat_variable_cleans(bytes, 3);
}

void smp_create_log_proof(smp_t* obj, char* version, mpz_t x, mpz_t c, mpz_t d) {
    // Create a random exponent
    mpz_t exponent;
    mpz_init(exponent);
    mpz_cryptorandom(exponent, 192);

    mpz_t temp;
    mpz_init(temp);

    mpz_powm(temp, obj->gen, exponent, obj->mod);

    char* num = (char*) malloc(mpz_sizeinbase(temp, 10) + 1);

    mpz_get_str(num, 10, temp);

    unsigned char* c_temp = (unsigned char*) malloc(strlen(version) + strlen(num) + 1); // version, number, null term.
    int length = sprintf((char*) c_temp, "%s%s", version, num);

    sha256_context ctx;
    char output[65];
    unsigned char digest[32];

    sha256_starts(&ctx);
    sha256_update(&ctx, c_temp, length+1); // + 1 for null byte.
    sha256_finish(&ctx, digest);

    for(int i = 0; i < 32; i++ ) {
        sprintf(output + i * 2, "%02x", digest[i]);
    }

    mpz_set_str(c, output, 16);

    // d = (exponent - ((x * c) % obj.modOrder) % obj.modOrder)

    mpz_mul(d, x, c);
    mpz_mod(d, d, obj->modOrder);
    mpz_sub(d, exponent, d);
    mpz_mod(d, d, obj->modOrder);

    free(num);
    free(c_temp);

    mpz_clear(temp);
    mpz_clear(exponent);
}

bool smp_check_log_proof(smp_t* obj, char* version, mpz_t g, mpz_t c, mpz_t d) {
    mpz_t gd, gc, gdgc, verify;

    mpz_init(gd);
    mpz_init(gc);
    mpz_init(gdgc);
    mpz_init(verify);

    mpz_powm(gd, obj->gen, d, obj->mod); // gd = (gen ^ d) % mod
    mpz_powm(gc, g, c, obj->mod); // gc = (g ^ c) % mod
    mpz_mul(gdgc, gd, gc); // (gd * gc) % mod
    mpz_mod(gdgc, gdgc, obj->mod);


    char* num = (char*) malloc(mpz_sizeinbase(gdgc, 10) + 1);

    mpz_get_str(num, 10, gdgc);

    unsigned char* temp = (unsigned char*) malloc(strlen(version) + strlen(num) + 1); // version, number, null term.
    int length = sprintf((char*) temp, "%s%s", version, num);

    sha256_context ctx;
    char output[65];
    unsigned char digest[32];

    sha256_starts(&ctx);
    sha256_update(&ctx, temp, length+1); // + 1 for null byte.
    sha256_finish(&ctx, digest);

    for(int i = 0; i < 32; i++ ) {
        sprintf(output + i * 2, "%02x", digest[i]);
    }

    mpz_set_str(verify, output, 16);

    bool correct = mpz_cmp(verify, c) == 0;

    mpz_clear(gd);
    mpz_clear(gc);
    mpz_clear(gdgc);
    mpz_clear(verify);

    free(temp);
    free(num);

    return correct;
}

void smp_create_coords_proof(smp_t* obj, char* version, mpz_t g2, mpz_t g3, mpz_t r, mpz_t c, mpz_t d1, mpz_t d2) {
    mpz_t r1, r2;
    mpz_t tmp1, tmp2;
    mpz_t _tmp1, _tmp2;

    mpz_init(r1);
    mpz_init(r2);

    mpz_init(tmp1);
    mpz_init(tmp2);

    mpz_init(_tmp1);
    mpz_init(_tmp2);


    // tmp1 = pow(g3, r1, self.mod)
    // _tmp1 = pow(self.gen, r1, self.mod)
    // _tmp2 = pow(g2, r2, self.mod)
    // tmp2 = _tmp1 * _tmp2
    // tmp2 = tmp2 % self.mod

    mpz_powm(tmp1, g3, r1, obj->mod); // tmp1 = (g3 ^ r1) % mod

    // tmp2 = (((gen ^ r1) % mod) * ((g2 ^ r2) % mod)) % mod

    mpz_powm(_tmp1, obj->gen, r1, obj->mod);
    mpz_powm(_tmp2, g2, r2, obj->mod);

    mpz_mul(tmp2, _tmp1, _tmp2);
    mpz_mod(tmp2, tmp2, obj->mod);

    char* num1 = (char*) malloc(mpz_sizeinbase(tmp1, 10) + 1);
    char* num2 = (char*) malloc(mpz_sizeinbase(tmp2, 10) + 1);

    mpz_get_str(num1, 10, tmp1);
    mpz_get_str(num2, 10, tmp2);

    unsigned char* temp = (unsigned char*) malloc(strlen(version) + strlen(num1) + strlen(num2) + 1); // version, number, null term.
    int length = sprintf((char*) temp, "%s%s%s", version, num1, num2);

    sha256_context ctx;
    char output[65];
    unsigned char digest[32];

    sha256_starts(&ctx);
    sha256_update(&ctx, temp, length+1); // + 1 for null byte.
    sha256_finish(&ctx, digest);

    for(int i = 0; i < 32; i++ ) {
        sprintf(output + i * 2, "%02x", digest[i]);
    }

    mpz_set_str(c, output, 16);

    // d1 = (r1 - ((r * c) % modOrder)) % modOrder

    mpz_mul(_tmp1, r, c);
    mpz_mod(_tmp1, _tmp1, obj->modOrder);

    mpz_sub(d1, r1, _tmp1);
    mpz_mod(d1, d1, obj->modOrder);

    // d2 = (r2 - ((secret * c) % modOrder)) % modOrder

    mpz_mul(_tmp2, obj->secret, c);
    mpz_mod(_tmp2, _tmp2, obj->modOrder);

    mpz_sub(d2, r2, _tmp2);
    mpz_mod(d2, d2, obj->modOrder);

    mpz_clear(r1);
    mpz_clear(r2);

    mpz_clear(tmp1);
    mpz_clear(tmp2);

    mpz_clear(_tmp1);
    mpz_clear(_tmp2);

    free(temp);
    free(num1);
    free(num2);
}

bool smp_check_coords_proof(smp_t* obj, char* version, mpz_t c, mpz_t d1, mpz_t d2, mpz_t g2, mpz_t g3, mpz_t p, mpz_t q) {
    mpz_t tmp1, tmp2;
    mpz_t _tmp1, _tmp2, _tmp3;
    mpz_t c_prime;

    mpz_init(tmp1);
    mpz_init(tmp2);
    mpz_init(_tmp1);
    mpz_init(_tmp2);
    mpz_init(_tmp3);
    mpz_init(c_prime);

    mpz_powm(_tmp1, g3, d1, obj->mod);
    mpz_powm(_tmp2, p, c, obj->mod);
    mpz_mul(tmp1, _tmp1, _tmp2);
    mpz_mod(tmp1, tmp1, obj->mod);

    mpz_powm(_tmp1, obj->gen, d1, obj->mod);
    mpz_powm(_tmp2, g2, d2, obj->mod);
    mpz_mul(_tmp1, _tmp1, _tmp2);
    mpz_mod(_tmp1, _tmp1, obj->mod);
    mpz_powm(_tmp2, q, c, obj->mod);
    mpz_mul(tmp2, _tmp1, _tmp2);
    mpz_mod(tmp2, tmp2, obj->mod);

    char* num1 = (char*) malloc(mpz_sizeinbase(tmp1, 10) + 1);
    char* num2 = (char*) malloc(mpz_sizeinbase(tmp2, 10) + 1);

    mpz_get_str(num1, 10, tmp1);
    mpz_get_str(num2, 10, tmp2);

    unsigned char* temp = (unsigned char*) malloc(strlen(version) + strlen(num1) + strlen(num2) + 1); // version, number, null term.
    int length = sprintf((char*) temp, "%s%s%s", version, num1, num2);

    sha256_context ctx;
    char output[65];
    unsigned char digest[32];

    sha256_starts(&ctx);
    sha256_update(&ctx, temp, length+1); // + 1 for null byte.
    sha256_finish(&ctx, digest);

    for(int i = 0; i < 32; i++ ) {
        sprintf(output + i * 2, "%02x", digest[i]);
    }

    mpz_set_str(c_prime, output, 16);

    bool verify = (mpz_cmp(c_prime, c) == 0);

    mpz_clear(tmp1);
    mpz_clear(tmp2);
    mpz_clear(_tmp1);
    mpz_clear(_tmp2);
    mpz_clear(_tmp3);
    mpz_clear(c_prime);

    free(num1);
    free(num2);
    free(temp);

    return verify;
}

void smp_create_equal_logs_proof(smp_t* obj, char* version, mpz_t qa, mpz_t qb, mpz_t x, mpz_t c, mpz_t d) {
    mpz_t r, qab;
    mpz_t tmp1, tmp2;

    mpz_init(r);
    mpz_init(qab);
    mpz_init(tmp1);
    mpz_init(tmp2);

    mpz_cryptorandom(r, 192);
    mpz_powm(tmp1, obj->gen, r, obj->mod);

    mpz_mul(qab, qa, qb);
    mpz_mod(qab, qab, obj->mod);

    mpz_powm(tmp2, qab, r, obj->mod);

    char* num1 = (char*) malloc(mpz_sizeinbase(tmp1, 10) + 1);
    char* num2 = (char*) malloc(mpz_sizeinbase(tmp2, 10) + 1);

    mpz_get_str(num1, 10, tmp1);
    mpz_get_str(num2, 10, tmp2);

    unsigned char* temp = (unsigned char*) malloc(strlen(version) + strlen(num1) + strlen(num2) + 1); // version, number, null term.
    int length = sprintf((char*) temp, "%s%s%s", version, num1, num2);

    sha256_context ctx;
    char output[65];
    unsigned char digest[32];

    sha256_starts(&ctx);
    sha256_update(&ctx, temp, length+1); // + 1 for null byte.
    sha256_finish(&ctx, digest);

    for(int i = 0; i < 32; i++ ) {
        sprintf(output + i * 2, "%02x", digest[i]);
    }

    mpz_set_str(c, output, 16);

    mpz_mul(tmp1, x, c);
    mpz_mod(tmp1, tmp1, obj->modOrder);

    mpz_sub(d, r, tmp1);
    mpz_mod(d, d, obj->modOrder);

    mpz_clear(r);
    mpz_clear(qab);
    mpz_clear(tmp1);
    mpz_clear(tmp2);

    free(num1);
    free(num2);
    free(temp);
}

bool smp_check_equal_logs_proof(smp_t* obj, char* version, mpz_t c, mpz_t d, mpz_t g3, mpz_t qab, mpz_t r) {
    mpz_t c_prime, tmp1, tmp2;
    mpz_t _tmp1, _tmp2;

    mpz_init(c_prime);
    mpz_init(tmp1);
    mpz_init(tmp2);
    mpz_init(_tmp1);
    mpz_init(_tmp2);

    mpz_powm(_tmp1, obj->gen, d, obj->mod);
    mpz_powm(_tmp2, g3, c, obj->mod);
    mpz_mul(tmp1, _tmp1, _tmp2);
    mpz_mod(tmp1, tmp1, obj->mod);

    mpz_powm(_tmp1, qab, d, obj->mod);
    mpz_powm(_tmp2, r, c, obj->mod);
    mpz_mul(tmp2, _tmp1, _tmp2);
    mpz_mod(tmp2, tmp2, obj->mod);

    char* num1 = (char*) malloc(mpz_sizeinbase(tmp1, 10) + 1);
    char* num2 = (char*) malloc(mpz_sizeinbase(tmp2, 10) + 1);

    mpz_get_str(num1, 10, tmp1);
    mpz_get_str(num2, 10, tmp2);

    unsigned char* temp = (unsigned char*) malloc(strlen(version) + strlen(num1) + strlen(num2) + 1); // version, number, null term.
    int length = sprintf((char*) temp, "%s%s%s", version, num1, num2);

    sha256_context ctx;
    char output[65];
    unsigned char digest[32];

    sha256_starts(&ctx);
    sha256_update(&ctx, temp, length+1); // + 1 for null byte.
    sha256_finish(&ctx, digest);

    for(int i = 0; i < 32; i++ ) {
        sprintf(output + i * 2, "%02x", digest[i]);
    }

    mpz_set_str(c_prime, output, 16);

    bool verify = (mpz_cmp(c_prime, c) == 0);

    mpz_clear(c_prime);
    mpz_clear(tmp1);
    mpz_clear(tmp2);
    mpz_clear(_tmp1);
    mpz_clear(_tmp2);

    free(num1);
    free(num2);
    free(temp);

    return verify;
}

void smp_invm(smp_t* obj, mpz_t x, mpz_t y) {
    mpz_t tmp;
    mpz_init(tmp);

    mpz_sub_ui(tmp, obj->mod, 2);

    mpz_powm(y, x, tmp, obj->mod);

    mpz_clear(tmp);
}

bool smp_valid_argument(smp_t* obj, mpz_t x) {
    int cmp1 = mpz_cmp_ui(x, 2);

    mpz_t tmp;
    mpz_init(tmp);

    mpz_sub_ui(tmp, obj->mod, 2);

    int cmp2 = mpz_cmp(x, tmp);

    mpz_clear(tmp);

    return cmp1 > 0 && cmp2 < 0;
}
