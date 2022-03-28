VER = 0.1
RELEASE = v$(VER)


HEADERS = helper.h crypto.h
LIB=libhelperlib.a

CFILES = helper.c crypto.c
TESTCFILES = self-test-server.c self-test-client.c

objects = $(CFILES:.c=.o)
testobjects = $(TESTCFILES:.c=.o)

CFLAGS += -O2
LDFLAGS = -lhelperlib

libbelperlib.a: $(objects)
	$(AR) rcs $(LIB) $(objects)

test: all
	$(CC) -L./ $(LDFLAGS) -o self-test-server self-test-server.c

all: libhelperlib.a

clean:
	rm -rf $(objects) $(testobjects) libhelperlib.a
