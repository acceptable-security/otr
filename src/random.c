#include "include/random.h"
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

void mpz_initrandom(mpz_t obj, size_t bytes) {
    mpz_init(obj);
    mpz_cryptorandom(obj, bytes);
}

void mpz_cryptorandom(mpz_t obj, size_t bytes) {
    int file = open("/dev/urandom", O_RDONLY); // Loonux only :(

    char* data = (char*) malloc((size_t) sizeof(char) * bytes);
    size_t len = 0;

    while (len < (sizeof(char) * bytes)) {
        int result = read(file, data + len, (sizeof(char) * bytes) - len);

        if (result < 0) {
            free(data);
        }

        len += result;
    }

    close(file);

    mpz_import(obj, (sizeof(char) * bytes), 1, sizeof(data[0]), 0, 0, data);
}
