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


static int c_en_decrypt(struct helper_command *cmd, struct connection *con, bool decrypt)
{
    int num_elements = cmd->data_size / sizeof(struct c_en_decrypt);
    int i, ret = 0;
    struct c_en_decrypt *el = (struct c_en_decrypt *) cmd->data;

    for (i = 0; i < num_elements; i++) {
        ret = -EINVAL;
        if ((el->mem_id >= 0 && el->mem_id < MAX_MAPPINGS) &&
              (con->mappings[el->mem_id]->fd > 0)){
            switch (el[i].algo) {
            case C_AESCBC: {
                    if ((el[i].pSrc + el[i].pLen > con->mappings[el->mem_id]->size) ||
                            (el[i].pDst + el[i].pLen > con->mappings[el->mem_id]->size)) {
                        ret = -EINVAL;
                    } else { 
                        if (decrypt) {
                            ret = map_return_code(
                                ippsAESDecryptCBC(
                                    (unsigned char *) (el[i].pSrc + con->mappings[el->mem_id]->mapped_at),
                                    (unsigned char *) (el[i].pDst + con->mappings[el->mem_id]->mapped_at),
                                    el[i].pLen,
                                    (void *) el[i].context,
                                    (unsigned char *) (el[i].pIV  + con->mappings[el->mem_id]->mapped_at)));
                        } else {
                            ret = map_return_code(
                                ippsAESEncryptCBC(
                                    (unsigned char *) (el[i].pSrc + con->mappings[el->mem_id]->mapped_at),
                                    (unsigned char *) (el[i].pDst + con->mappings[el->mem_id]->mapped_at),
                                    el[i].pLen,
                                    (void *) el[i].context,
                                    (unsigned char *) (el[i].pIV  + con->mappings[el->mem_id]->mapped_at)));
                        }
                        msync((char *) el[i].pDst + con->mappings[el->mem_id]->mapped_at, el[i].pLen, MS_SYNC);
                    }
                    break;
                }
            }
        } 
        create_ack(cmd, ret);
        if (ret) {
            LOG("Failed to en_decrypt %d\n", ret);
            break;
        }
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


