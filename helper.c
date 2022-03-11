// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2022 Cambridge Greys Limited
 * Copyright (C) 2022 Red Hat Inc
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <strings.h>
#include <pthread.h>
#include <fcntl.h>
#include <assert.h>
#include <time.h>
#include "helper.h"

#define STATE_UNINIT 0
#define STATE_ERROR -1
#define STATE_RUNNING 1

struct mapping {
    unsigned int id;
    unsigned long long mapped_at;
    unsigned long long size;
    unsigned int state;
    int fd;
};

#define MAX_QUEUE_DEPTH 256

struct command_queue {
    atomic_int queue_depth;
	int head, tail;
    pthread_spinlock_t head_lock;
    pthread_spinlock_t tail_lock;
    struct helper_command **elements;
    struct mmsghdr msgvecs[MAX_QUEUE_DEPTH];
};

struct connection {
    int fd;
    struct mapping *mappings;
    struct command_queue *in_queue, *out_queue;
};

static void *(*process_command)(struct helper_command *command);

#define MAX_CLIENTS 256

static struct connection *clients;
static struct timespec ZERO;

static int epoll_fd;

void set_process_command(void *(*arg)(struct helper_command *command))
{
	process_command = arg;
}
/* To be done strictly under a head lock */

static int queue_advance_head(struct command_queue *q, int advance)
{
    int ret;
	q->head = (q->head + advance) % MAX_QUEUE_DEPTH;
	ret = atomic_fetch_sub_explicit(&q->queue_depth, advance, memory_order_acq_rel);
    assert(ret >= 0);
    return ret;
}

/*	Advance the queue tail by n = advance.
 *	This is called by enqueuers which neet to hold the tail lock
 */

static int queue_advance_tail(struct command_queue *q, int advance)
{
    int ret;
	q->tail = (q->tail + advance) % MAX_QUEUE_DEPTH;
	ret = atomic_fetch_add_explicit(&q->queue_depth, advance, memory_order_acq_rel);
    assert(ret >= 0);
    return ret;
}

static int q_depth(struct command_queue *q)
{
	return atomic_load_explicit(&q->queue_depth, memory_order_acquire);
}



/* Queueing operations specifically optimized for use in
 * recvmmsg/sendmmsg using multiple element enqueue/dequeue
 * in one operation.
 */

static struct command_queue *create_queue()
{
    struct command_queue *result;
    struct helper_command *cm;
    int i;

    result = malloc(sizeof(struct command_queue));
    result->tail = 0;
    result->head = 0;
    atomic_init (&result->queue_depth, 0);
    result->elements = calloc(MAX_QUEUE_DEPTH, sizeof(struct helper_command *));
    for (i = 0; i < MAX_QUEUE_DEPTH; i++) {
        cm = result->elements[i] = malloc(sizeof(struct helper_command));
        cm->header.command = 0;
        cm->header.sequence = 0;
        cm->data = malloc(HELPER_MAX_DATA);
        cm->control = malloc(HELPER_MAX_CONTROL);
        result->msgvecs[i].msg_hdr.msg_iov = calloc(2, sizeof(struct iovec));
    }
    pthread_spin_init(&result->head_lock, PTHREAD_PROCESS_PRIVATE);
    pthread_spin_init(&result->tail_lock, PTHREAD_PROCESS_PRIVATE);
    return result;
}

static struct command_queue *destroy_queue(struct command_queue *q)
{
    int i;

    for (i = 0; i < MAX_QUEUE_DEPTH; i++) {
        free(q->msgvecs[i].msg_hdr.msg_iov);
    }
    pthread_spin_destroy(&q->head_lock);
    pthread_spin_destroy(&q->tail_lock);
    free(q->elements);
    free(q);
}

static int run_processing(struct connection *con)
{
    int queue_depth, queue_avail, i;
    struct command_queue *in = con->in_queue;
    struct command_queue *out = con->out_queue;

    struct helper_command *command;


	queue_depth = q_depth(in);
	queue_avail = (MAX_QUEUE_DEPTH - 1) - q_depth(out);

	if (queue_depth > queue_avail) {
		queue_depth = queue_avail;
	}


    if (queue_depth > 0) {

		pthread_spin_lock(&in->head_lock);
		for (i = 0; i < queue_depth; i++) {
			if (process_command) {
				process_command(
					in->elements[(in->head + i) % MAX_QUEUE_DEPTH]);
			}
		}

		pthread_spin_lock(&out->tail_lock);
		for (i = 0; i < queue_depth; i++) {
			void *swap;
			swap = out->elements[(out->tail + i) % MAX_QUEUE_DEPTH];

			out->elements[(out->tail + i) % MAX_QUEUE_DEPTH] = 
				in->elements[(in->head + i) % MAX_QUEUE_DEPTH];

			in->elements[(in->head + i) % MAX_QUEUE_DEPTH] = swap;
		}

        queue_advance_tail(out, queue_depth);
        queue_advance_head(in, queue_depth);
    
		pthread_spin_unlock(&in->head_lock);
		pthread_spin_unlock(&out->tail_lock);
    }
	return q_depth(out);
}

static int recv_to_q(struct command_queue *q, int fd)
{
    int max_packets, i, ret = 0;
	int queue_depth = 0;
    struct helper_command *cm;

	/* rewrite as atomic fetch */

    while (ret >= 0) {
        queue_depth = q_depth(q);

        if (queue_depth == MAX_QUEUE_DEPTH) 
            return -EAGAIN;

        pthread_spin_lock(&q->tail_lock);
        max_packets = MAX_QUEUE_DEPTH - queue_depth;

        for (i=0; i< max_packets; i++) {

            cm = q->elements[(q->tail + i) % MAX_QUEUE_DEPTH];

            q->msgvecs[i].msg_hdr.msg_iov[0].iov_base = cm;
            q->msgvecs[i].msg_hdr.msg_iov[0].iov_len = sizeof(struct helper_header);
            q->msgvecs[i].msg_hdr.msg_iov[1].iov_base = cm->data;
            q->msgvecs[i].msg_hdr.msg_iov[1].iov_len = HELPER_MAX_DATA;
            q->msgvecs[i].msg_hdr.msg_iovlen = 2;
            q->msgvecs[i].msg_hdr.msg_control = cm->control;
            q->msgvecs[i].msg_hdr.msg_controllen = HELPER_MAX_CONTROL;
            q->msgvecs[i].msg_hdr.msg_name = NULL;
            q->msgvecs[i].msg_hdr.msg_namelen = 0;
            q->msgvecs[i].msg_hdr.msg_flags = 0;
        }

        ret = recvmmsg(fd, q->msgvecs, max_packets, 0, &ZERO);

        if (ret > 0) {
            for (i = 0; i < ret; i++) {
                /* Update all received records with correct size. */
                q->elements[(q->tail + i) % MAX_QUEUE_DEPTH]->data_size = q->msgvecs[i].msg_len - sizeof(struct helper_header);
                q->elements[(q->tail + i) % MAX_QUEUE_DEPTH]->control_size = q->msgvecs[i].msg_hdr.msg_controllen;
            }
            queue_advance_tail(q, ret);
        } else {
            ret = -errno;
        }
        pthread_spin_unlock(&q->tail_lock);
    }
    return ret;
}

static int send_from_q(struct command_queue *q, int fd)
{
    int i, ret = 0;
    int queue_depth;
    struct helper_command *cm;

    queue_depth = q_depth(q);

    if (queue_depth) {

        pthread_spin_lock(&q->head_lock);

        for (i=0; i< queue_depth; i++) {
            if (q->elements[(q->head + i) % MAX_QUEUE_DEPTH] != NULL) {
                cm = q->elements[(q->head + i) % MAX_QUEUE_DEPTH];
                q->msgvecs[i].msg_hdr.msg_iov[0].iov_base = cm;
                q->msgvecs[i].msg_hdr.msg_iov[0].iov_len = sizeof(struct helper_header);
                q->msgvecs[i].msg_hdr.msg_iov[1].iov_base = cm->data;
                q->msgvecs[i].msg_hdr.msg_iov[1].iov_len = cm->data_size;
                q->msgvecs[i].msg_hdr.msg_iovlen = 2;
                if (cm->control_size) {
                    q->msgvecs[i].msg_hdr.msg_controllen = cm->control_size;
                    q->msgvecs[i].msg_hdr.msg_control = cm->control;
                } else {
                    q->msgvecs[i].msg_hdr.msg_controllen = cm->control_size;
                    q->msgvecs[i].msg_hdr.msg_control = NULL;
                }
                q->msgvecs[i].msg_hdr.msg_flags = MSG_EOR | MSG_NOSIGNAL;
                q->msgvecs[i].msg_hdr.msg_name = NULL;
                q->msgvecs[i].msg_hdr.msg_namelen = 0;
            }
        }
        ret = sendmmsg(fd, q->msgvecs, queue_depth, 0);
        if (ret > 0) {
            queue_advance_head(q, ret);
        } else {
            ret = -errno;
        }
        pthread_spin_unlock(&q->head_lock);
    }
    return q_depth(q);
}

/* Init socket and bind */

int init_helper(char *pathname)
{
    struct sockaddr_un name;
    struct epoll_event ctl;
    int i;

    epoll_fd = epoll_create(64);

    clients = calloc(MAX_CLIENTS, sizeof(struct connection));
    memset(clients, MAX_CLIENTS * sizeof(struct connection), 0);
    memset(&name, sizeof(struct sockaddr_un), 0);

    clients[0].fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK, 0);
    if (clients[0].fd < 0)
        return -errno;

    name.sun_family = AF_UNIX;
    strncpy((char *) &name.sun_path, pathname, sizeof(name.sun_path) - 1);

    if (bind(clients[0].fd, &name, sizeof(name)) < 0) {
        close(clients[0].fd);
        return -errno;
    }

    if (listen(clients[0].fd, 64) < 0) {
        close(clients[0].fd);
        return -errno;
    }

    ctl.events = EPOLLIN | EPOLLHUP | EPOLLPRI;
    ctl.data.ptr = &clients[0];
    clients[0].mappings = NULL;
    clients[0].in_queue = NULL;
    clients[0].out_queue = NULL;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, clients[0].fd, &ctl)) {
        close(clients[0].fd);
        return -errno;
    }
    for (i=1; i<MAX_CLIENTS; i++) {
        clients[i].fd = -1;
    }
    return clients[0].fd;
}

static void destroy_mappings(struct mapping *m)
{
	/* Do nothing for now until all IO is done */
}

static int close_connection(struct connection *con)
{
    if (con->fd > 0) {
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, con->fd, NULL); 
        destroy_mappings(con->mappings);
        destroy_queue(con->in_queue);
        destroy_queue(con->out_queue);
        con->in_queue = NULL;
        con->out_queue = NULL;
        close(con->fd);
        con->fd = -1;
    }
}


static int accept_connection(int fd)
{
    int i;
    struct epoll_event ctl;

    for (i=1; i < MAX_CLIENTS; i++) {
        if (clients[i].fd == -1) {
            clients[i].fd = accept4(fd, NULL, NULL, SOCK_NONBLOCK);
            if (clients[i].fd > 0) {
                ctl.events = EPOLLIN | EPOLLHUP | EPOLLPRI;
                ctl.data.ptr = &clients[i];
                if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, clients[i].fd, &ctl) < 0) {
                    close(clients[i].fd);
                    clients[i].fd = -1;
                    return -ENOSPC;
                }
    			clients[i].mappings = NULL;
				clients[i].in_queue = create_queue();
				clients[i].out_queue = create_queue();
                return 0;
            } else {
                return -EAGAIN;
            }
        }
    }
    return -ENOSPC; 
}

int main_event_loop()
{
    int num_events;
    int event, i;
    struct connection *cl;
    struct helper_command *command;
    struct epoll_event ev[64];
    bool have_data = false;

    while (42) {
        if (!have_data) {
            num_events = epoll_wait(epoll_fd, ev, 64, -1);
            have_data = false;
            if (num_events > 0) {
                for (event=0; event < num_events; event++) {
                    cl = ev[event].data.ptr;
                    if (ev[event].events & (EPOLLRDHUP | EPOLLERR | EPOLLHUP)) {
                        close_connection(cl);
                    } else {
                        if (cl->fd == clients[0].fd) {
                            accept_connection(clients[0].fd); 
                        } else {
                            recv_to_q(cl->in_queue, cl->fd);
                        }
                    }
                }
            }
        }
        /* This will go to a different thread as it will be
         * coupled to sendmmsg
         */
        for (i=1; i < MAX_CLIENTS; i++) {
            if (clients[i].fd > 0) {
                run_processing(&clients[i]);
            }
        }
        for (i=1; i < MAX_CLIENTS; i++) {
            if (clients[i].fd > 0) {
                int ret = send_from_q(clients[i].out_queue, clients[i].fd);
                have_data |= ret > 0;
            }
        }
    }
}

