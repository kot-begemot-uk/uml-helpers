CFLAGS = -I../ -g -O2 -Wall -DDEBUG=1
LIB=helper
CRYPTO_LDFLAGS = -L ../ -l$(LIB) -lcrypto_mb -lippcp

bench:
	$(CC) $(CFLAGS) -o crypto-benchmark crypto-benchmark.c $(CRYPTO_LDFLAGS)

crypto-test-server:
	$(CC) $(CFLAGS) -o test-crypto-server $(crypto) test-crypto-server.c $(CRYPTO_LDFLAGS)

tests:
	$(CC) $(CFLAGS) -o test-client test-client.c 
	$(CC) $(CFLAGS) -o test-client-crypto test-client-crypto.c
	$(CC) $(CFLAGS) -o test-server $(objects) test-server.c -L ../ -l$(LIB)

clean:
	rm -rf self-test-client self-test-server self-test-client-crypto self-test-crypto-server crypto-benchmark

all: bench test-crypto-server
