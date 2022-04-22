#include <stdlib.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/mman.h>
#include "helper.h"
#include "crypto.h"
#include "ippcp.h"


struct crypto_context {
    struct crypto_context *next;
    void *local_ctx;
    unsigned long long remote_ctx;
    struct connection *con;
};


static struct crypto_context *contexts = NULL;

static inline void add_context(struct crypto_context *ctx)
{
    ctx->next = contexts;
    contexts = ctx;
}

static inline void del_ctx_by_id(unsigned long long id)
{
    struct crypto_context *next = contexts->next;
    struct crypto_context *cur = contexts;

    if (contexts->remote_ctx == id) {
        contexts = contexts->next;
        free(cur);
    }
    do {
        if (next->remote_ctx == id) {
            cur->next = next->next;
            free(cur);
            break;
        }
        cur = next;
        next = next->next;
    } while (next);
}

static inline void del_ctx_by_ctx(void *ctx)
{
    struct crypto_context *next = contexts->next;
    struct crypto_context *cur = contexts;

    if (contexts->local_ctx == ctx) {
        contexts = contexts->next;
        free(cur);
    }
    do {
        if (next->local_ctx == ctx) {
            cur->next = next->next;
            free(cur);
            break;
        }
        cur = next;
        next = next->next;
    } while (next);
    
}

static inline void *find_ctx_by_id(unsigned long long id)
{
    struct crypto_context *cur = contexts;
    while (cur) {
        if (cur->remote_ctx == id) {
            return cur->local_ctx;
        }
        cur = cur->next;
    }
    return NULL;
}

static void cleanup_hook(struct connection *con)
{
    struct crypto_context *next;
    struct crypto_context *cur;

    if (contexts) {
        do {
            if (contexts->con == con) {
                cur = contexts;
                contexts = contexts->next;
                free(cur);
            } else {
                break;
            }
        } while (contexts);
    }

    if (contexts) {
        next = contexts->next;
        cur = contexts;
        do {
            if (next->con == con) {
                cur->next = next->next;
                free(cur);
                break;
            }
            cur = next;
            next = next->next;
        } while (next);
    }
}

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



static int c_create_aes_context(struct helper_command *cmd, struct connection *con)
{
    int ctx_size, ret;
    struct c_aes_init_data *initdata = get_data(cmd);
    struct c_aes_context_reply *replydata = get_data(cmd);
    struct crypto_context *rec;

    ippsAESGetSize(&ctx_size); 
    rec = malloc(sizeof(struct crypto_context));
    rec->local_ctx = malloc(ctx_size);
    rec->remote_ctx = initdata->remote_ctx;
    rec->con = con;

    ret = map_return_code(
        ippsAESInit(
            (const Ipp8u*)&initdata->key,
            initdata->keylen,
            (IppsAESSpec*) rec->local_ctx,
            ctx_size));
    if (ret == 0) {
        cmd->header.command = H_CRYPTO_CREATE_CONTEXT_REPLY;
        replydata->context = (unsigned long long) rec->local_ctx;
        replydata->status = 0;
        return 0;
    } else {
        free(rec->local_ctx);
        free(rec);
        replydata->context = 0;
        replydata->status = 0;
        return ret;
    }
    return -ENOSPC;
}

static int c_destroy_aes_context(struct helper_command *cmd)
{
    struct c_aes_context_destroy *destroydata = get_data(cmd);

    if (destroydata->acked) {
        del_ctx_by_ctx((void *)destroydata->context);
    } else {
        del_ctx_by_id(destroydata->context);
    }
    create_ack(cmd, 0);
    return 0;
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
    void *ctx;

    pIV = el->pIV;

    pSrcElem = pDstElem =
        (struct crypto_addr_list *) ((char *) get_data(cmd) + sizeof(struct c_en_decrypt));

    min = con->mappings[el->mem_id]->size;
    max = 0;

    if (el->acked) {
        ctx = (void *) el->context;
    } else {
        ctx = find_ctx_by_id(el->context);
    }


    while (ret >= 0 && src < el->srcAddrCount && dst < el->dstAddrCount) {
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
                            ctx,
                            compute_address(pIV, AES_BLOCK, con, cmd)));
                } else {
                    ret = map_return_code(
                        ippsAESEncryptCBC(
                            compute_address(pSrc, size, con, cmd),
                            compute_address(pDst, size, con, cmd),
                            size,
                            ctx,
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
            return c_create_aes_context(cmd, con);
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
    set_process_command(handle_command);
    set_cleanup_hook(cleanup_hook);
}


