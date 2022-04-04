// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2022 Cambridge Greys Limited
 * Copyright (C) 2022 Red Hat Inc
 */

#define _GNU_SOURCE 1
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <strings.h>
#include <fcntl.h>
#include <assert.h>
#include <time.h>
#include "helper.h"

static int (*process_command)(
        struct helper_command *command, struct connection *con 
        );

#define MAX_CLIENTS 256

static struct connection *clients;
static struct timespec ZERO = {0, 0};

static int epoll_fd;

void set_process_command(int (*arg)(struct helper_command *command, struct connection *con))
{
	process_command = arg;
}

static int queue_advance_head(struct command_queue *q, int advance)
{
	q->head = (q->head + advance) % MAX_QUEUE_DEPTH;
    q->queue_depth -= advance;
    assert(q->queue_depth >= 0);
    return q->queue_depth;
}

/*	Advance the queue tail by n = advance.
 */

static int queue_advance_tail(struct command_queue *q, int advance)
{
    int ret;
	q->tail = (q->tail + advance) % MAX_QUEUE_DEPTH;
    q->queue_depth += advance;
    assert(ret <= MAX_QUEUE_DEPTH);
    return q->queue_depth;
}

static int seq;

struct helper_command *h_create_command()
{

    struct helper_command *res = malloc(sizeof(struct helper_command));

    /* TODO: use a pool */

	res->header.sequence = seq++;
    res->header.command = 0;
    res->data = malloc(HELPER_MAX_DATA);
    res->control = malloc(HELPER_MAX_CONTROL);
    res->control_size = 0;
    
    return res;
}
void h_destroy_command(struct helper_command *cmd)
{
    /* TODO: use a pool */

    if (cmd) {
        free(cmd->data);
        free(cmd->control);
        free(cmd);
    }
}

void h_enqueue_one(struct command_queue *q, struct helper_command *cmd)
{
    h_destroy_command(q->elements[q->tail]);
    q->elements[q->tail] = cmd;
    queue_advance_tail(q, 1);
}

struct helper_command *h_dequeue_one(struct command_queue *q)
{
    struct helper_command *res;
   
    res = q->elements[q->head];
    q->elements[q->head] = NULL;
    queue_advance_head(q, 1);

    return res;
}

int h_queue_depth(struct command_queue *q)
{
	return q->queue_depth;
}

/* Queueing operations specifically optimized for use in
 * recvmmsg/sendmmsg using multiple element enqueue/dequeue
 * in one operation.
 */

struct command_queue *create_queue()
{
    struct command_queue *result;
    int i;

    result = malloc(sizeof(struct command_queue));
    result->tail = 0;
    result->head = 0;
    result->queue_depth = 0;
    result->elements = calloc(MAX_QUEUE_DEPTH, sizeof(struct helper_command *));
    result->msgvecs = calloc(MAX_QUEUE_DEPTH, sizeof(struct mmsghdr));
    result->iovecs = calloc(MAX_QUEUE_DEPTH * 2, sizeof(struct iovec));
    for (i = 0; i < MAX_QUEUE_DEPTH; i++) {
        result->elements[i] = h_create_command();
        result->msgvecs[i].msg_hdr.msg_iov = &result->iovecs[i*2];
    }
    return result;
}

static void destroy_queue(struct command_queue *q)
{
    free(q->msgvecs);
    free(q->elements);
    free(q->iovecs);
    free(q);
}

static struct mapping *create_mapping(struct helper_command *cmd)
{
    int fd;
    char *data = ((char *)cmd->control) + sizeof(struct cmsghdr);
    struct mapping *map = NULL;
    struct helper_map_data *cdata = (struct helper_map_data *) cmd->data;

    if (cmd->header.command == EX_H_MAP && cmd->control_size) {
        fd = *((int*) data);
        map = malloc(sizeof(struct mapping));
        map->id = cdata->mem_id;
        map->fd = fd;
        map->mapped_at = (unsigned long long) mmap(
                NULL, cdata->size, PROT_WRITE | PROT_READ, MAP_SHARED, map->fd, 0);
        map->size = cdata->size;
        if (map->mapped_at == (unsigned long long) MAP_FAILED) {
            LOG("failed to map\n");
            close(map->fd);
            free(map);
            map = NULL;
        }
        cmd->control_size = 0;
        close(fd);
    }
    return map;
}



static void delete_mapping(struct mapping *map)
{
    if (map) {
        LOG("delete map %d\n", map->id);
        munmap((void *)map->mapped_at, map->size);
        close(map->fd);
        free(map);
    }
}

static int process_delete_map(struct helper_command *cmd, struct connection *con)
{
    struct helper_map_data *cdata = get_data(cmd);

    if (cdata->mem_id > 0 && cdata->mem_id < MAX_MAPPINGS && con->mappings[cdata->mem_id]) {
        delete_mapping(con->mappings[cdata->mem_id]);
        con->mappings[cdata->mem_id] = NULL;
        return 0;
    }
    return -ENOENT;
}

void create_ack(struct helper_command *cmd, int error)
{
    struct helper_ack_data *err = (struct helper_ack_data *) cmd->data;
    if (cmd->header.command != EX_H_ECHO) {
        cmd->header.command = EX_H_ACK;
        err->error = error;
        cmd->data_size = sizeof(struct helper_ack_data);
    }
}

static int process_internal_command(
        struct helper_command *cmd, struct connection *con)
{
    int ret;

    switch(cmd->header.command) {
    case EX_H_MAP: {
        struct helper_map_data *cdata = get_data(cmd);

        if (cdata->mem_id > 0 && cdata->mem_id < MAX_MAPPINGS &&
                (con->mappings[cdata->mem_id] == NULL)) {
            con->mappings[cdata->mem_id] = create_mapping(cmd);
            if (con->mappings[cdata->mem_id]) {
                create_ack(cmd, 0);
                return 0;
            }
            create_ack(cmd, -EINVAL);
            return -EINVAL;
        } 
        create_ack(cmd, -EBUSY);
        return -EBUSY;
    }
    case EX_H_UNMAP:
        ret = process_delete_map(cmd, con);
        create_ack(cmd, ret);
        return ret;
    }
    return 0;
}

static int run_processing(struct connection *con)
{
    int queue_depth, queue_avail, i;
    struct command_queue *in = con->in_queue;
    struct command_queue *out = con->out_queue;

    struct helper_command *cmd;


	queue_depth = h_queue_depth(in);
	queue_avail = (MAX_QUEUE_DEPTH - 1) - h_queue_depth(out);

	if (queue_depth > queue_avail) {
		queue_depth = queue_avail;
	}


    if (queue_depth > 0) {

		for (i = 0; i < queue_depth; i++) {
            cmd = in->elements[(in->head + i) % MAX_QUEUE_DEPTH];
            if (cmd->header.command <= EX_H_INTERNAL_CMDS) {
                process_internal_command(cmd, con);
            } else {
                if (process_command) {
                    process_command(cmd, con);
                }
            }
		}

		for (i = 0; i < queue_depth; i++) {
			void *swap;
			swap = out->elements[(out->tail + i) % MAX_QUEUE_DEPTH];
			out->elements[(out->tail + i) % MAX_QUEUE_DEPTH] = 
				in->elements[(in->head + i) % MAX_QUEUE_DEPTH];

			in->elements[(in->head + i) % MAX_QUEUE_DEPTH] = swap;
		}

        queue_advance_tail(out, queue_depth);
        queue_advance_head(in, queue_depth);
    
    }
	return h_queue_depth(out);
}

int recv_to_q(struct command_queue *q, int fd)
{
    int max_packets, i, ret = 0;
	int queue_depth = 0;
    struct helper_command *cm;

    while (ret >= 0) {
        queue_depth = h_queue_depth(q);

        if (queue_depth == MAX_QUEUE_DEPTH - 1) 
            return -EAGAIN;

        max_packets = MAX_QUEUE_DEPTH - queue_depth - 1;

        for (i = 0; i< max_packets; i++) {

            cm = q->elements[(q->tail + i) % MAX_QUEUE_DEPTH];

            if (!cm) {
                cm = q->elements[(q->tail + i) % MAX_QUEUE_DEPTH] = h_create_command();
            }

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
                cm = q->elements[(q->tail + i) % MAX_QUEUE_DEPTH];
                cm->data_size = q->msgvecs[i].msg_len - sizeof(struct helper_header);
                cm->control_size = q->msgvecs[i].msg_hdr.msg_controllen;
            }
            queue_advance_tail(q, ret);
        } else {
            if (errno) {
                ret = -errno;
            } else {
                LOG("EOF\n");
                ret = -EPIPE;
            }
        }
    }
    return ret;
}

int send_from_q(struct command_queue *q, int fd)
{
    int i, ret = 0;
    int queue_depth;
    struct helper_command *cm;

    queue_depth = h_queue_depth(q);

    if (queue_depth) {


        for (i=0; i< queue_depth; i++) {
            if (q->elements[(q->head + i) % MAX_QUEUE_DEPTH] != NULL) {
                cm = q->elements[(q->head + i) % MAX_QUEUE_DEPTH];
                q->msgvecs[i].msg_hdr.msg_iov[0].iov_base = cm;
                q->msgvecs[i].msg_hdr.msg_iov[0].iov_len = sizeof(struct helper_header);
                q->msgvecs[i].msg_hdr.msg_iov[1].iov_base = cm->data;
                q->msgvecs[i].msg_hdr.msg_iov[1].iov_len = cm->data_size;
                q->msgvecs[i].msg_hdr.msg_iovlen = 2;
                q->msgvecs[i].msg_hdr.msg_controllen = cm->control_size;
                if (cm->control_size) {
                    q->msgvecs[i].msg_hdr.msg_control = cm->control;
                } else {
                    q->msgvecs[i].msg_hdr.msg_control = NULL;
                }
                q->msgvecs[i].msg_hdr.msg_flags =  MSG_NOSIGNAL;
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
    }
    return ret;
}


/* Return last element with ack or first non-ack element.
 * Takes ownership of dequeued command.
 * All acks prior to the last one are destroyed.
 */
struct helper_command *check_acks_and_dequeue(struct command_queue *q)
{
    int i, ret;
    struct helper_command *result = NULL, *oldresult = NULL;
    struct helper_ack_data *ack;

    if (h_queue_depth(q) == 0) {
        return NULL;
    }

    ret = h_queue_depth(q);

    for (i = 0; i < ret; i++) {
        result = q->elements[(q->head + i) % MAX_QUEUE_DEPTH];
        q->elements[(q->head + i) % MAX_QUEUE_DEPTH] = NULL;
        if (result) {
            if (result->header.command != EX_H_ACK) {
                LOG("Fail ack %d\n", result->header.command);
                return result;
            }
            ack = get_data(result);
            if (ack->error < 0) {
                LOG("Fail %d\n", ack->error);
                return result;
            } else {
                h_destroy_command(oldresult);
                oldresult = result;
            }
        } 
    }
    q->head = (q->head + ret) % MAX_QUEUE_DEPTH;
    q->queue_depth -= ret;
    return result;
}


/* Init socket and bind */

int init_helper(char *pathname)
{
    struct sockaddr_un name;
    struct epoll_event ctl;
    int i;

    process_command = NULL;

    epoll_fd = epoll_create(64);

    clients = calloc(MAX_CLIENTS, sizeof(struct connection));
    memset(clients, 0, MAX_CLIENTS * sizeof(struct connection));
    memset(&name, 0, sizeof(struct sockaddr_un));

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

static void close_connection(struct connection *con)
{
    int i;

    LOG("close requested\n");

    if (con->fd > 0) {
        LOG("closing fd %i\n", con->fd);
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, con->fd, NULL); 
        for (i=0; i<MAX_MAPPINGS; i++) {
            delete_mapping(con->mappings[i]);
        }
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
    int i, j;
    struct epoll_event ctl;

    LOG("accept\n");

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
    			clients[i].mappings = calloc(MAX_MAPPINGS, sizeof(struct mapping *));
				clients[i].in_queue = create_queue();
				clients[i].out_queue = create_queue();
                for (j=0; j<MAX_MAPPINGS; j++) {
                    clients[i].mappings[j] = NULL;
                }
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
    struct epoll_event ev[64];
    bool have_data = false;

    while (42) {
        if (!have_data) {
            num_events = epoll_wait(epoll_fd, ev, 64, -1);
            if (num_events > 0) {
                for (event=0; event < num_events; event++) {
                    cl = ev[event].data.ptr;
                    if (ev[event].events & (EPOLLRDHUP | EPOLLERR | EPOLLHUP)) {
                        close_connection(cl);
                    } else {
                        if (cl->fd == clients[0].fd) {
                            accept_connection(clients[0].fd); 
                        } else {
                            int ret = recv_to_q(cl->in_queue, cl->fd);
                            if (ret < 0 && ret != -EAGAIN) {
                                close_connection(cl);
                            }
                        }
                    }
                }
            }
        }
        have_data = false;
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
                have_data |= h_queue_depth(clients[i].out_queue);
                if (ret < 0 && ret != -EAGAIN && ret != -ENOBUFS) {
                    close_connection(&clients[i]);
                }
            }
        }
    }
}

