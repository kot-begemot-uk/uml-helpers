// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2022 Cambridge Greys Limited
 * Copyright (C) 2022 Red Hat Inc
 */

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
#include "helper.h"


struct helper_command to_send, to_recv;


static int recv_command(int fd) 
{
	struct msghdr msg;
	struct iovec iov[2];
    int ret;
	
    msg.msg_iov = iov;
    msg.msg_name = NULL;
    msg.msg_namelen = 0;
	msg.msg_iov[0].iov_base = &to_recv;
    msg.msg_iov[0].iov_len = sizeof(struct helper_header);
    msg.msg_iov[1].iov_base = to_recv.data;
    msg.msg_iov[1].iov_len = HELPER_MAX_DATA;
    msg.msg_iovlen = 2;
    msg.msg_control = to_recv.control;
    msg.msg_controllen = HELPER_MAX_CONTROL;
    msg.msg_flags = 0;

    ret = recvmsg(fd, &msg, 0);
    if (ret > 0) {
        to_recv.data_size = ret - sizeof(struct helper_header);
        to_recv.control_size = msg.msg_controllen;
    }
    return ret;
}

static int send_command(int fd) 
{
	struct msghdr msg;
	struct iovec iov[2];
    int ret;
	
    msg.msg_iov = iov;
    msg.msg_name = NULL;
    msg.msg_namelen = 0;
	msg.msg_iov[0].iov_base = &to_send;
    msg.msg_iov[0].iov_len = sizeof(struct helper_header);
    msg.msg_iov[1].iov_base = to_send.data;
    msg.msg_iov[1].iov_len = to_send.data_size;
    msg.msg_iovlen = 2;
    msg.msg_control = to_send.control;
    msg.msg_controllen = to_send.control_size;
    msg.msg_flags = 0;

    ret = sendmsg(fd, &msg, MSG_EOR);
    return ret;
}

static bool compare_cmds()
{
    bool result = true;

    result = to_recv.header.command == to_send.header.command;

    if (!result) {
        printf("Header command mismatch\n");
        return result;
    }

    result = to_recv.header.sequence == to_send.header.sequence;
    if (!result) {
        printf("Header seq mismatch\n");
        return result;
    }

    result = to_recv.data_size == to_send.data_size ; 
    if (!result) {
        printf("Data size mismatch %d %d\n", to_recv.data_size, to_send.data_size);
        return result;
    }

    result = to_recv.control_size == to_send.control_size;
    if (!result) {
        printf("Control size mismatch %i %i\n",
                to_recv.control_size, to_send.control_size);
        return result;
    }

    result = memcmp(to_recv.data, to_send.data, to_send.data_size) == 0;
    if (!result) {
        printf("Data contents mismatch\n");
        return result;
    }
    
	return true;
}

static bool check_ack()
{
    bool result = true;
    struct helper_ack_data *data = (struct helper_ack_data *) to_recv.data;


    result = to_recv.header.command == EX_H_ACK;

    if (!result) {
        printf("Header command mismatch\n");
        return result;
    }

    result = to_recv.header.sequence == to_send.header.sequence;
    if (!result) {
        printf("Header seq mismatch\n");
        return result;
    }
    
	return (data->error >= 0);
}
static int connect_to_server(char *pathname)
{
    int fd;
    struct sockaddr_un name;
    
    fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
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

const char *testpattern = "Test 01";

static void init()
{
    to_send.data = malloc(HELPER_MAX_DATA);
    to_recv.data = malloc(HELPER_MAX_DATA);
    to_send.control_size = 0;
    to_send.control = malloc(1024);
    to_recv.control = malloc(1024);
}

static void clear()
{
    memset(to_send.data, 0, HELPER_MAX_DATA);
    memset(to_recv.data, 0, HELPER_MAX_DATA);
    to_send.control_size = 0;
    to_recv.control_size = 0;
}

static int test01(int fd)
{
    int ret = 0;
    clear();
    to_send.header.command = EX_H_ECHO;
    to_send.header.sequence = 31337;
    to_send.data_size = 256;
    memcpy(to_send.data, testpattern, strlen(testpattern));
    ret = send_command(fd);
    if (ret < 0) {
        printf("Send error %s\n", strerror(-ret));
        return ret;
    }
    ret = recv_command(fd);
    if (ret < 0) {
        printf("Recv error %s\n", strerror(-ret));
        return ret;
    }
    if (compare_cmds(fd)) {
        return 0;
    }
    return -EINVAL;
}

static int test02(int fd)
{
    int ret, mfd = 0;
    struct helper_map_data *mdata = (struct helper_map_data *) to_send.data;
    struct cmsghdr *cmsg = (struct cmsghdr *) to_send.control;
    char *data = to_send.control + sizeof(struct cmsghdr);


    clear();
    to_send.header.command = EX_H_MAP;
    to_send.header.sequence = 31338;

    mdata->mem_id = 1;
    mdata->size = 65536;
    mfd = open("/tmp/test-map", O_RDWR);

    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(mfd));
    *((int *)data) = mfd;
    to_send.data_size = sizeof(struct helper_map_data);
    to_send.control_size = sizeof(struct cmsghdr) + sizeof(int);

    ret = send_command(fd);
    if (ret < 0) {
        printf("Send error %s\n", strerror(-ret));
        return ret;
    }
    ret = recv_command(fd);
    if (ret < 0) {
        printf("Recv error %s\n", strerror(-ret));
        return ret;
    }
    if (check_ack()) {
        return 0;
    }
    return -EINVAL;
}

static void run_tests(int fd)
{
    int ret;
    ret = test01(fd);
    if (ret == 0 ) {
        printf("Test 01 successful\n");
    } else {
        printf("Test 01 failed, error %d\n", ret);
    }
    ret = test02(fd);
    if (ret == 0 ) {
        printf("Test 02 successful\n");
    } else {
        printf("Test 02 failed, error %d\n", ret);
    }
}

int main(int argc, char *argv[])
{
    int fd;
    if (argc != 2) 
        exit(EINVAL);
    fd = connect_to_server(argv[1]);
    if (fd < 0) {
        printf("Connect error %s\n", strerror(-fd));
        exit(-fd);
    }
    init();
    run_tests(fd);
}

