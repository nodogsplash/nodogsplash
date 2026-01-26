CC?=gcc
CFLAGS?=-O2 -g -Wall
CFLAGS+=-I../../src
CFLAGS+=-Wno-missing-prototypes
CFLAGS+=-Wl,--unresolved-symbols=ignore-all
CFLAGS+=-no-pie

# mock functions
LDFLAGS+=-Wl,--wrap=fopen

LDLIBS+=-ljson-c

.PHONY: all tests

all: test_utils

tests: run_test_utils

TEST_STATE_FILE_OBJECT := \
	test_utils.c \
	../../src/client_list.c \
	../../src/safe.c \
	../../src/conf.c \
	../../src/debug.c \
	../../src/fw_abstract.c \
	../../src/fw_common.c

test_utils: $(TEST_STATE_FILE_OBJECT)
	$(CC) $(CFLAGS) $(LDFLAGS) -o test_utils $+ $(LDLIBS)

run_test_utils: test_utils
	./test_utils
