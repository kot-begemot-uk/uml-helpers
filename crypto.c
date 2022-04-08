#include <stdlib.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/mman.h>
#include "helper.h"
#include "crypto.h"
#include "ippcp.h"

#define MAX_CONTEXTS 256

static void **contexts;
static int first_empty;



static int map_return_code(int ipp_return)
{
    switch (ipp_return) {
        case ippStsNotSupportedModeErr:
        case ippStsCpuNotSupportedErr: return -EOPNOTSUPP;

        case ippStsLengthErr:
        case ippStsBadArgErr:
        case ippStsContextMatchErr:
        case ippStsScaleRangeErr:
        case ippStsOutOfRangeErr:
        case ippStsDivByZeroErr:
        case ippStsNullPtrErr:
        case ippStsRangeErr:
        case ippStsDivByZero:
        case ippStsFeaturesCombination:
        case ippStsErr: {
            return -EINVAL;
        }

        case ippStsNoMemErr:
        case ippStsMemAllocErr: return -ENOMEM;

        case ippStsLoadDynErr: return -ELIBBAD;

        case ippStsNoOperation: 
        case ippStsWaterfall:
        case ippStsNoErr: return 0;
        default: {
            return -EINVAL;
        }
    }
}



static int c_create_aes_context(struct helper_command *cmd)
{
    int ctx_size, i, ret;
    void *ctx = NULL;
    struct c_aes_init_data *initdata = get_data(cmd);
    struct c_aes_context_reply *replydata = get_data(cmd);

    ippsAESGetSize(&ctx_size); 
    for (i = first_empty; i < MAX_CONTEXTS; i++) {
        if (contexts[i] == NULL) {
            ctx = contexts[i] = malloc(ctx_size);
        }
        ret = map_return_code(
            ippsAESInit(
                (const Ipp8u*)&initdata->key,
                initdata->keylen,
                (IppsAESSpec*) ctx,
                ctx_size));
        if (ret == 0) {
            cmd->header.command = H_CRYPTO_CREATE_CONTEXT_REPLY;
            replydata->context = (unsigned long long) ctx;
            replydata->status = 0;
            first_empty = i + 1;
            return 0;
        } else {
            free(ctx);
            contexts[i] = NULL;
            replydata->context = 0;
            replydata->status = 0;
            return ret;
        }
    }
    return -ENOSPC;
}

static int c_destroy_aes_context(struct helper_command *cmd)
{
    int i;
    struct c_aes_context_destroy *destroydata = get_data(cmd);

    for (i=0; i<MAX_CONTEXTS; i++) {
        if (contexts[i] == (void *) destroydata->context) {
            contexts[i] = NULL;
            if (i < first_empty) {
                first_empty = i;
            }
            create_ack(cmd, 0);
        }
    }
    create_ack(cmd, -EINVAL);
    return -EINVAL;
}

/* Compute and check address */

static inline void *compute_address(unsigned long long addr,
                                    size_t size,
                                    struct connection *con,
                                    struct helper_command *cmd)
{
    unsigned long long res = addr;
    struct c_en_decrypt *el = (struct c_en_decrypt *) cmd->data;

    if (res > con->mappings[el->mem_id]->size ||
            res + size > con->mappings[el->mem_id]->size) {
        return NULL;
    }

    res += con->mappings[el->mem_id]->mapped_at;

    return (void *) res;

}

#define AES_BLOCK 16

static inline unsigned long long MIN(unsigned long long a, unsigned long long b)
{
    if (a > b) return b;
    return a;
}

static inline unsigned long long MAX(unsigned long long a, unsigned long long b)
{
    if (a < b) return b;
    return a;
}

static int c_en_decrypt(struct helper_command *cmd, struct connection *con, bool decrypt)
{
    int ret = 0;
    int src = 0, dst = 0;
    int src_off = 0, dst_off = 0;
    size_t size = 0;
    struct c_en_decrypt *el = (struct c_en_decrypt *) cmd->data;
    struct crypto_addr_list *pSrcElem, *pDstElem;
    unsigned long long pSrc, pDst, pIV, nextIV, min, max;

    pIV = el->pIV;

    pSrcElem = pDstElem =
        (struct crypto_addr_list *) ((char *) get_data(cmd) + sizeof(struct c_en_decrypt));

    min = con->mappings[el->mem_id]->size;
    max = 0;


    while (ret >= 0 && src < el->addrCount && dst < el->addrCount) {
        size = pSrcElem[src].pSrcSize - src_off;
        pSrc = pSrcElem[src].pSrc + src_off;
        pDst = pDstElem[dst].pDst + dst_off;
        if (size <= pDstElem[dst].pDstSize - dst_off) {
            /* size OK, src is less or equal to dst */
            dst_off = pDstElem[dst].pDstSize - dst_off - size;
            if (!dst_off) {
                /* no offset in dst block, increment to next
                 * sg list element
                 */
                dst++;
            } 
            src++;
        } else {
            /* dst block smaller than src */
            size = pDstElem[dst].pDstSize - dst_off;
            src_off = pSrcElem[src].pSrcSize - src_off - size;
            dst++;
        }

        min = MIN(pSrc, min);
        min = MIN(pDst, min);
        max = MAX(pSrc + size, max);
        max = MAX(pDst + size, max);

        nextIV = pDst + size - AES_BLOCK;

        switch (el->algo) {
        case C_AESCBC: {
                if (decrypt) {
                    ret = map_return_code(
                        ippsAESDecryptCBC(
                            compute_address(pSrc, size, con, cmd),
                            compute_address(pDst, size, con, cmd),
                            size,
                            (void *) el->context,
                            compute_address(pIV, AES_BLOCK, con, cmd)));
                } else {
                    ret = map_return_code(
                        ippsAESEncryptCBC(
                            compute_address(pSrc, size, con, cmd),
                            compute_address(pDst, size, con, cmd),
                            size,
                            (void *) el->context,
                            compute_address(pIV, AES_BLOCK, con, cmd)));
                }
            }
            break;
        }
        pIV = nextIV; /* output feedback for CBC */
    }
    if (ret >= 0) {
        msync((void *) min + con->mappings[el->mem_id]->mapped_at, max, MS_SYNC);
    }
    create_ack(cmd, ret);
    if (ret) {
        LOG("Failed to en_decrypt %d\n", ret);
    }
    return ret;
}

static int handle_command(struct helper_command *cmd, struct connection *con)
{

    switch(cmd->header.command) {
        case  H_CRYPTO_CREATE_AES_CONTEXT:
            return c_create_aes_context(cmd);
        case  H_CRYPTO_DESTROY_AES_CONTEXT:
            return c_destroy_aes_context(cmd);
        case  H_CRYPTO_ENCRYPT:
            return c_en_decrypt(cmd, con, false);
        case  H_CRYPTO_DECRYPT:
            return c_en_decrypt(cmd, con, true);
        default:
            return -EINVAL;
    }
}


void init_crypto_helper()
{
    int i;

    contexts = calloc(MAX_CONTEXTS, sizeof (void*));
    for (i=0; i<MAX_CONTEXTS; i++) {
        contexts[i] = NULL;
    }
    set_process_command(handle_command);
}


