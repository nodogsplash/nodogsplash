
CC?=gcc
CFLAGS?=-O2 -g -Wall
CFLAGS+=-I../../src
CFLAGS+=-D__NDS_UNIT_TEST

.PHONY: all tests

all: test_conf

tests: run_test_conf

TEST_CONF_OBJECT := \
	test_conf.c \
	../../src/conf.c \
	../../src/debug.c \
	../../src/safe.c

test_conf: $(TEST_CONF_OBJECT)
	$(CC) $(CFLAGS) $(LDFLAGS) -o test_conf $+ $(LDLIBS)

run_test_conf: test_conf
	./test_conf

clean:
	rm test_conf
