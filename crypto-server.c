// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) 2022 Cambridge Greys Limited
 * Copyright (C) 2022 Red Hat Inc
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <strings.h>
#include <pthread.h>
#include "helper.h"
#include "crypto.h"


int main(int argc, char *argv[]) 
{
    int fd;

	if (argc != 2) 
		exit(EINVAL);


	fd = init_helper(argv[1]);
	if (fd < 0) {
        printf("Error: %s\n", strerror(-fd));
    }
    init_crypto_helper();
	main_event_loop();
}
