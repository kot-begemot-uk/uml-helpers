// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2022 Cambridge Greys Limited
 * Copyright (C) 2022 Red Hat Inc
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <strings.h>
#include <pthread.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <sys/time.h>
#include "helper.h"
#include "crypto.h"


struct command_queue *inq;
struct command_queue *outq;


#define TOTAL_SIZE 134217728
#define KEY_SIZE 16

static void * memblock;

/*! 256-bit secret key */
static unsigned char aeskey[32] = {
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73,
    0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07,
    0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14,
    0xdf, 0xf4
};



unsigned long long context;

static void initialize(int fd)
{
    int mfd = 0;
    struct helper_map_data *mdata;
    struct cmsghdr *cmsg; 
    char *data;

    struct helper_command *cmd;

    struct c_aes_init_data *aesinit;
    struct c_aes_context_reply *aes_ctx;


    inq = create_queue();
    outq = create_queue();

    cmd = h_create_command();

    mdata = get_data(cmd);

    cmsg = (struct cmsghdr *) cmd->control;
    data = cmd->control + sizeof(struct cmsghdr);

    cmd->header.command = EX_H_MAP;

    mdata->mem_id = 1;
    mdata->size = 268435456;
    mfd = open("/tmp/test-map", O_RDWR);
    memblock = mmap(NULL, mdata->size, PROT_WRITE | PROT_READ, MAP_SHARED, mfd, 0);

    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(mfd));
    *((int *)data) = mfd;
    cmd->data_size = sizeof(struct helper_map_data);
    cmd->control_size = sizeof(struct cmsghdr) + sizeof(int);

    h_enqueue_one(outq, cmd);

    cmd = h_create_command();
    cmd->header.command = H_CRYPTO_CREATE_AES_CONTEXT;
    cmd->data_size = KEY_SIZE + sizeof(int);
    aesinit = get_data(cmd);

    aesinit->keylen = KEY_SIZE;
    memcpy(&aesinit->key, aeskey, KEY_SIZE);
    h_enqueue_one(outq, cmd);

    while (h_queue_depth(outq) > 0) {
        send_from_q(outq, fd);
    }
    while ((h_queue_depth(inq) < 2)) {
        recv_to_q(inq, fd);
    };
    
    cmd = h_dequeue_one(inq);
    if (cmd->header.command != EX_H_ACK) {
        fprintf(stderr, "failed to map memory\n");
        exit(1);
    }
    h_destroy_command(cmd);
    cmd = h_dequeue_one(inq);
    aes_ctx = get_data(cmd);
    if (aes_ctx->status) {
        fprintf(stderr, "failed to get context, status %d\n", aes_ctx->status);
        exit(1);
    }
    context = aes_ctx->context;
    h_destroy_command(cmd);
}

#define BLOCK_SIZE 1500
#define DATA_SIZE 1408
#define IVSIZE 16

static struct helper_command *create_test_element(int index)
{
    struct helper_command *cmd;

    struct c_en_decrypt *endata;

    cmd = h_create_command();
    endata = get_data(cmd);

    cmd->header.command = H_CRYPTO_ENCRYPT;
    cmd->data_size = sizeof(struct c_en_decrypt);
    endata->pSrc = index * 2 * BLOCK_SIZE;
    endata->pLen = DATA_SIZE;
    endata->algo = C_AESCBC;
    endata->pIV = index * 2 * BLOCK_SIZE + DATA_SIZE;
    endata->pDst = index * 2 * BLOCK_SIZE + BLOCK_SIZE;
    endata->context = context;
    endata->mem_id = 1;

    return cmd;
}

static int run_benchmark(int fd)
{
    int index = 0, ret;
    struct helper_command *cmd;
    struct helper_ack_data *ack;
    int i = 0;

    while (index < (TOTAL_SIZE / BLOCK_SIZE - 1)) {
        if (h_queue_depth(outq) >= MAX_QUEUE_DEPTH - 1 || index > (TOTAL_SIZE / BLOCK_SIZE - MAX_QUEUE_DEPTH) - 1) {
            ret = send_from_q(outq, fd);
            if (ret < 0 && ret != -EAGAIN) {
                printf("Failed to send, error %i\n", ret);
                exit(1);
            }
        }
        if (h_queue_depth(outq) < MAX_QUEUE_DEPTH - 1) {
            index++;
            h_enqueue_one(outq, create_test_element(index++));
        }
        ret = recv_to_q(inq, fd);
        if (ret < 0 && ret != -EAGAIN) {
            printf("Failed to recv, error %i", ret);
            exit(1);
        } 

        cmd = check_acks_and_dequeue(inq);
        if (cmd != NULL) {
            ack = get_data(cmd);
            if (ack->error < 0) {
                printf("Failed to encrypt, %p cmd %i error %i, element %i queue depth %i\n", ack, cmd->header.command, 
                        ack->error, i, h_queue_depth(inq));
                exit(1);
            }
            i++;
        }
    }
    return 0;
}

static int connect_to_server(char *pathname)
{
    int fd;
    struct sockaddr_un name;
    
    fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK, 0);
    if (fd < 0)
        return -errno;

    name.sun_family = AF_UNIX;
    strncpy((char *) &name.sun_path, pathname, sizeof(name.sun_path) - 1);

    if (connect(fd, (const struct sockaddr *) &name, sizeof(name)) < 0) {
        close(fd);
        printf("Error in connect %d\n", -errno);
        return -errno;
    }
    return fd;
}

#define NSEC_PER_SEC	1000000000L

static inline long long timespec_to_ns(const struct timespec *ts)
{
	return ((long long) ts->tv_sec * NSEC_PER_SEC) + ts->tv_nsec;
}

long long os_persistent_clock_emulation(void)
{
	struct timespec realtime_tp;

	clock_gettime(CLOCK_REALTIME, &realtime_tp);
	return timespec_to_ns(&realtime_tp);
}

int main(int argc, char *argv[])
{
    int fd;
    long long start;
    long long finish;
    if (argc != 2) 
        exit(EINVAL);
    fd = connect_to_server(argv[1]);
    if (fd < 0) {
        printf("Connect error %s\n", strerror(-fd));
        exit(-fd);
    }
    initialize(fd);
    printf("Starting Benchmark %p %llu\n", memblock, context);
    start = os_persistent_clock_emulation();
    run_benchmark(fd);
    finish = os_persistent_clock_emulation();
    printf("%f\n", (TOTAL_SIZE / BLOCK_SIZE - 1) * 1500*8.0/(finish-start));
}

