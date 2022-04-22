// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2022 Cambridge Greys Limited
 * Copyright (C) 2022 Red Hat Inc
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif


#include <sys/types.h>
#include <sys/socket.h>
#include <stdatomic.h>
#include <pthread.h>

#define PROTOCOL_VERSION 1


#ifndef __UM_EX_HELPER_H
#define __UM_EX_HELPER_H

struct helper_header {
    unsigned int version;
    unsigned int command;
    unsigned long sequence;
};

struct helper_command {
    struct helper_header header;
    char *data;                 /* Variable length data. */
    char *control;              /* Control message buffer */
    int data_size, control_size;
};


#define HELPER_MAX_DATA 1024
#define HELPER_MAX_CONTROL 1024


#define EX_H_ACK 0              /* ACK a packet */

struct helper_ack_data {
    int error;
};

#define EX_H_ECHO 1             /* Echo to client */

struct helper_map_data {
    unsigned long mem_id;       /* Memory region ID 0 to MAX_MAPPINGS. */
    unsigned long long size;    /* Memory region size. */
};

#define EX_H_MAP 2              /* Data: helper_map_data, fd in ancilliary SCM_RIGHTS */
#define EX_H_UNMAP 3            /* Data: same as helper init */

#define EX_H_INTERNAL_CMDS 3

/* Command codes 0 - 3 are internal. In order to extend the helper, take over commands
* with higher numbers
*/


#define STATE_UNINIT 0
#define STATE_ERROR -1
#define STATE_RUNNING 1

struct mapping {
    unsigned int id;
    unsigned long long mapped_at;
    size_t size;
    int fd;
};

#define MAX_QUEUE_DEPTH 256
#define MAX_MAPPINGS 16

struct command_queue {
    atomic_int queue_depth;
    int head, tail;
    pthread_spinlock_t head_lock;
    pthread_spinlock_t tail_lock;
    struct helper_command **elements;
    struct mmsghdr *msgvecs;
    struct iovec *iovecs;
};

struct connection {
    int fd;
    struct mapping **mappings;
    struct command_queue *in_queue, *out_queue;
};

#define get_data(c) (void *)c->data

extern int main_event_loop();
extern int init_helper(char *pathname);
extern void set_process_command(
    int (*arg)(
        struct helper_command *command,
        struct connection *con    
        ));
extern void create_ack(struct helper_command *cmd, int error);
extern int recv_to_q(struct command_queue *q, int fd);
extern int send_from_q(struct command_queue *q, int fd);
extern struct helper_command *h_dequeue_one(struct command_queue *q);
extern void h_enqueue_one(struct command_queue *q, struct helper_command *cmd);
extern struct helper_command *h_create_command();
extern void h_destroy_command(struct helper_command *cmd);
extern struct command_queue *create_queue();
extern int h_queue_depth(struct command_queue *q);
extern struct helper_command *check_acks_and_dequeue(struct command_queue *q);
extern void set_cleanup_hook(void (*arg)(struct connection *con));

#ifdef DEBUG
#define LOG(...) fprintf (stderr, __VA_ARGS__)
#else
#define LOG(...) do {} while (false)
#endif

#endif
