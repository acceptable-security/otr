#include "include/util.h"

#include <stdlib.h>

chat_variable_t* export_number(mpz_t number) {
    int size = sizeof(unsigned char);
    int nail = 0;

    int numb = 8 * size - nail;
    int count = (mpz_sizeinbase(number, 2) + numb - 1) / numb;

    unsigned char* output = (unsigned char* ) malloc(count * size);

    int quantity = 0;
    output = mpz_export(output, (unsigned long* )&quantity, -1, size, 0, nail, number);

    chat_variable_t* bytes = (chat_variable_t* ) malloc(sizeof(chat_variable_t));

    bytes->data = output;
    bytes->length = quantity;

    return bytes;
}

void import_number(chat_variable_t* bytes, mpz_t number) {
    mpz_import(number, bytes->length, -1, sizeof(unsigned char), 0, 0, bytes->data);
}

void pack_variables(chat_variable_t** bytes, size_t count, chat_variable_t* output) {
    // Format:
    // | amount | size | bytes[0][0] | bytes[0][1] | size | bytes[1][0] | etc...

    int length = count + 1; // we'll need to write the size for each variable plus amount of packed variables

    for (int i = 0; i < count; i++) {
        length += bytes[i]->length;
    }

    output->data = (unsigned char*) malloc(sizeof(unsigned char) * length);
    output->length = length;

    output->data[0] = (unsigned char) count;

    int index = 1;

    for (int i = 0; i < count; i++) {
        output->data[index] = bytes[i]->length;

        if (bytes[i]->length > 0) {
            for (int j = 0; j < bytes[i]->length; j++) {
                output->data[index + j + 1] = bytes[i]->data[j];
            }
        }

        index += bytes[i]->length + 1;
    }
}

size_t unpack_variables(chat_variable_t* packed, chat_variable_t*** bytes) {
    size_t size = (size_t) packed->data[0];

    *bytes = (chat_variable_t**) malloc(sizeof(chat_variable_t*) * size);

    size_t unpacked = 0;

    int index = 1;

    while(unpacked < size) {
        if (index > packed->length) {
            for ( int i = 0; i < unpacked; i++ ) {
                free((*bytes)[i]->data);
                free((*bytes)[i]);
            }

            free(*bytes);

            return -1;
        }

        size_t length = packed->data[index];

        if (length <= 0) {
            index += 1;

            continue;
        }

        (*bytes)[unpacked] = (chat_variable_t*) malloc(sizeof(chat_variable_t));
        (*bytes)[unpacked]->length = length;
        (*bytes)[unpacked]->data = (unsigned char*) malloc(sizeof(unsigned char) * length);

        for (int i = index + 1; i < index + 1 + length; i++) {
            if (i > packed->length) {
                for ( int i = 0; i <= unpacked; i++ ) {
                    free((*bytes)[i]->data);
                    free((*bytes)[i]);
                }

                free(*bytes);

                return -1;
            }

            (*bytes)[unpacked]->data[i - (index + 1)] = packed->data[i];
        }

        unpacked += 1;
        index += 1 + length;
    }

    return size;
}

chat_variable_t* chat_variable_init(size_t length) {
    chat_variable_t* obj = (chat_variable_t*) malloc(sizeof(chat_variable_t));

    if (length > 0) {
        obj->data = (unsigned char*) malloc(sizeof(unsigned char) * length);
        obj->length = length;
    }
    else {
        obj->data = NULL;
    }

    return obj;
}

void chat_variable_clean(chat_variable_t* obj) {
    if ( obj->data != NULL) {
        free(obj->data);
    }

    free(obj);
}

void chat_variable_cleans(chat_variable_t** obj, size_t count) {
    for (int i = 0; i < count; i++)
        chat_variable_clean(obj[i]);

    free(obj);
}
