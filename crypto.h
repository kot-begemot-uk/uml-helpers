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

/* We can assume that the number of pSrc and pDst in sg-lists is
 * roughly comparable or even equal for most use cases. 
 * As a result, we can allocate all records as src, dst and sizes
 * instead of bothering with separate src and dst lists
 */

struct crypto_addr_list {
    unsigned long long pSrc;
    unsigned long long pDst;
    int pSrcSize;
    int pDstSize;
};

struct c_en_decrypt {
    unsigned long long context;
    unsigned long long pIV;   /* we may need to copy this */
    int srcAddrCount;
    int dstAddrCount;
    int pLen;
    int BlckSize;     /* CFB and OFB Block Size. */
    unsigned int algo;  /* Actual AES variety */
    int mem_id; /* Memory Region ID */
};


#define H_CRYPTO_DECRYPT (HELPER_CRYPTO_BASE + 5)

#define C_AESCBC 1
#define C_AESCFB 2
#define C_AESOFB 3

extern void init_crypto_helper();

#endif
