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
#include <sys/mman.h>
#include "helper.h"
#include "crypto.h"


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
    strncpy((char *) &name.sun_path, pathname, sizeof(name.sun_path));

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
    memset(to_send.data, HELPER_MAX_DATA, 0);
    memset(to_recv.data, HELPER_MAX_DATA, 0);
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

static void * memblock;

static int test02(int fd)
{
    int ret, mfd = 0;
    struct helper_map_data *mdata = (struct helper_map_data *) to_send.data;
    void * test_f;
    struct cmsghdr *cmsg = (struct cmsghdr *) to_send.control;
    unsigned char *data = to_send.control + sizeof(struct cmsghdr);


    clear();
    to_send.header.command = EX_H_MAP;
    to_send.header.sequence = 31338;

    mdata->mem_id = 1;
    mdata->size = 65536;
    mfd = open("/tmp/test-map", O_RDWR);
    memblock = mmap(NULL, mdata->size, PROT_WRITE | PROT_READ, MAP_SHARED, mfd, 0);

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



/*! Key size in bytes */
#define KEY_SIZE 32
#define DATA_SIZE 16

/*! 256-bit secret key */
static unsigned char aeskey[32] = {
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73,
    0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07,
    0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14,
    0xdf, 0xf4
};



/*! Plain text */
static unsigned char plainText[DATA_SIZE] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 
    0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
    0x17, 0x2a
};

/*! Cipher text */
static unsigned char cipherText[DATA_SIZE] = {
    0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba,
    0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6
};


/*! Cipher text */
static unsigned char IV[DATA_SIZE] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};


unsigned long long context;

static int test03(int fd)
{
    int ret = 0;
    struct c_aes_init_data *data = get_data((&to_send));
    struct c_aes_context_reply *rdata = get_data((&to_recv));


    clear();
    to_send.header.command = H_CRYPTO_CREATE_AES_CONTEXT;
    to_send.header.sequence = 31337;
    to_send.data_size = KEY_SIZE + sizeof(int);

    
    data->keylen = KEY_SIZE;
    memcpy(&data->key, aeskey, KEY_SIZE);
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
    if (rdata->status) {
        printf("crypto error %s\n", strerror(rdata->status));
        return rdata->status;
    }
    context = rdata->context;
    printf("contxt is %lli\n", context);
    return 0;
    
}

static void hexdump(unsigned char *dump, int size)
{
    int i;

    for (i = 0; i< size; i++) {
        printf("%0x ", dump[i]);
    }
    printf("\n");
}

static int test04(int fd)
{
    int ret = 0;
    struct c_en_decrypt *endata = get_data((&to_send));
    struct helper_ack_data *rdata = get_data((&to_recv));

    memcpy(memblock, plainText, DATA_SIZE);
    memcpy(((char *)memblock) + DATA_SIZE, IV, DATA_SIZE);

    clear();
    to_send.header.command = H_CRYPTO_ENCRYPT;
    to_send.header.sequence = 31337;
    to_send.data_size = sizeof(struct c_en_decrypt); /* one record */
    endata->pSrc = 0;
    endata->pLen = DATA_SIZE;
    endata->algo = C_AESCBC;
    endata->pIV = DATA_SIZE;
    endata->pDst = DATA_SIZE * 2;
    endata->context = context;
    endata->mem_id = 1;
    
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
    if (rdata->error) {
        printf("crypto error %s\n", strerror(rdata->error));
        return rdata->error;
    }
    if (memcmp(cipherText, ((char *)memblock) + DATA_SIZE * 2, DATA_SIZE) == 0) {
        printf("encrypted OK\n");
    } else {
        printf("GOT "); hexdump(((char *)memblock) + DATA_SIZE * 2, DATA_SIZE);
        printf("WANT "); hexdump(((char *)cipherText), DATA_SIZE);
        return -EINVAL;
    }
    return 0;
    
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
    ret = test03(fd);
    if (ret == 0 ) {
        printf("Test 03 successful\n");
    } else {
        printf("Test 03 failed, error %d\n", ret);
    }
    ret = test04(fd);
    if (ret == 0 ) {
        printf("Test 04 successful\n");
    } else {
        printf("Test 04 failed, error %d\n", ret);
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

