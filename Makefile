VER = 0.1
RELEASE = v$(VER)


HEADERS = helper.h crypto.h
LIB=libhelperlib.a

CFILES = helper.c
CRYPTO = crypto.c $(CFILES)

objects = $(CFILES:.c=.o)
crypto = $(CRYPTO:.c=.o)

CFLAGS += -g -O2 -pthread
CRYPTO_LDFLAGS = -L ./ $(LIB) -lcrypto_mb -lippcp

helper: $(crypto)


test: libhelper.a
	$(CC) $(CFLAGS) -o self-test-client self-test-client.c 
	$(CC) $(CFLAGS) -o self-test-client-crypto self-test-client-crypto.c
	$(CC) $(CFLAGS) -o self-test-server $(objects) self-test-server.c -L ./ $(LIB)
	$(CC) $(CFLAGS) -o self-test-crypto-server $(crypto) self-test-crypto-server.c $(CRYPTO_LDFLAGS)

libhelper.a: $(crypto)
	$(AR) rcs $(LIB) $(crypto)

clean:
	rm -rf $(objects) $(crypto) self-test-client self-test-server self-test-client-crypto self-test-crypto-server

