VER = 0.1
RELEASE = v$(VER)


HEADERS = helper.h crypto.h
LIB=helper

CFILES = helper.c
CRYPTO = crypto.c $(CFILES)

objects = $(CFILES:.c=.o)
crypto = $(CRYPTO:.c=.o)

CFLAGS += -g -O2 -Wall
CRYPTO_LDFLAGS = -L ./ -l$(LIB) -lcrypto_mb -lippcp


libhelper.a: $(crypto) $(objects)
	$(AR) rcs libhelper.a $(crypto)

crypto-server: libhelper.a
	$(CC) $(CFLAGS) -o crypto-server crypto-server.c $(CRYPTO_LDFLAGS)

clean:
	rm -rf $(objects) $(crypto) crypto-server libhelper.a
	$(MAKE) -C examples/ clean

examples: libhelper.a
	$(MAKE) -C examples/

all: crypto-server
