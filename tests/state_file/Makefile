
CC?=gcc
CFLAGS?=-O2 -g -Wall
CFLAGS+=-I../../src
CFLAGS+= -DWITH_STATE_FILE

LDLIBS+=-ljson-c

.PHONY: all tests

all: test_state_file

tests: run_test_state_file

TEST_STATE_FILE_OBJECT := \
	test_state_file.c \
	../../src/client_list.c \
	../../src/conf.c \
	../../src/debug.c \
	../../src/fw_abstract.c \
	../../src/fw_iptables.c \
	../../src/safe.c \
	../../src/state_file.c \
	../../src/tc.c \
	../../src/util.c

test_state_file: $(TEST_STATE_FILE_OBJECT)
	$(CC) $(CFLAGS) $(LDFLAGS) -o test_state_file $+ $(LDLIBS)

run_test_state_file: test_state_file
	./test_state_file
