#include "helper.h"


#ifndef __UM_EX_CRYPTO_H
#define __UM_EX_CRYPTO_H

#define HELPER_CRYPTO_BASE EX_H_INTERNAL_CMDS


#define H_CRYPTO_CREATE_AES_CONTEXT (HELPER_CRYPTO_BASE + 1)
struct c_aes_init_data {
    int keylen;
    char key; /* Maximum key size 256 bits == 32 bytes */
};


#define H_CRYPTO_CREATE_CONTEXT_REPLY (HELPER_CRYPTO_BASE + 2)
struct c_aes_context_reply {
    unsigned long long context; /* We pass back out pointer address. It is unique,
                                 * so it can double up as a handle on the other side */
    int status;
};


#define H_CRYPTO_DESTROY_AES_CONTEXT (HELPER_CRYPTO_BASE + 3)
struct c_aes_context_destroy {
    unsigned long long context; /* Context to destroy. */
};
#define H_CRYPTO_ENCRYPT (HELPER_CRYPTO_BASE + 4)
/* It is up to the caller to adjust any addresses before sending
 * The number of records is deduced from command->data->data_size
 */
struct c_en_decrypt {
    unsigned long long pSrc; /* src address within mmaped area */
    unsigned long long pDst; /* dst address within mmaped area */
    unsigned long long context;
    unsigned long long pIV;   /* we may need to copy this */
    int pLen;
    unsigned int algo;  /* Actual AES variety */
    int mem_id; /* Memory Region ID */
};
#define H_CRYPTO_DECRYPT (HELPER_CRYPTO_BASE + 5)

#define C_AESCBC 1

extern void init_crypto_helper();

#endif
