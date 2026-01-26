/** @file test_utils.c
    @brief Test cases for utils functions
    @author Copyright (C) 2025 Alexander Couzens <lynxis@fe80.eu>
*/

#define ARP_FOUND 0
#define ARP_NOT_FOUND -1

#include <asm-generic/errno-base.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../../src/util.c"

static char *arp_test_file;

extern FILE* __real_fopen(const char *path, const char *mode);

// catch fopen("/proc/net/arp", "r");
FILE*
__wrap_fopen(const char *path, const char *mode)
{
    if (strcmp(path, "/proc/net/arp")) {
        return __real_fopen(path, mode);
    }

    return __real_fopen(arp_test_file, mode);
}

int test_utils_get_client_mac_proc(char mac[18], const char* ip)
{
    return get_client_mac_proc(mac, ip);
}

struct a_test {
	const char *description;
	char *filename;
    int (*test_func)(char mac[18], const char* ip);
    const char *ip;
    const char *mac;
    const int result;
};

struct a_test tests[] = {
    {"one entry, MAC found", "one_entry.arp", test_utils_get_client_mac_proc, "127.0.0.1", "ff:ff:ff:ff:ff:ff", ARP_FOUND},
    {"one entry, MAC not found", "one_entry.arp", test_utils_get_client_mac_proc, "127.0.0.2", "ff:ff:ff:ff:ff:00", ARP_NOT_FOUND},
    {"partial IP match", "one_entry.arp", test_utils_get_client_mac_proc, "127.0.0.11", "ff:ff:ff:ff:ff:00", ARP_NOT_FOUND},
    {"huge ARP table (>64k bytes), MAC found", "huge_table.arp", test_utils_get_client_mac_proc, "127.0.0.1", "ff:ff:ff:ff:ff:ff", ARP_FOUND},
    {"huge ARP table (>64k bytes), MAC not found", "huge_table.arp", test_utils_get_client_mac_proc, "127.0.0.11", "ff:ff:ff:ff:ff:00", ARP_NOT_FOUND},
    {"empty table", "empty_table.arp", test_utils_get_client_mac_proc, "127.0.0.11", "ff:ff:ff:ff:ff:00", ARP_NOT_FOUND},
    {NULL, NULL, NULL},
};

int main(int argc, char **argv)
{
	int rc, len;
    char ip[64];
    struct a_test *current = &tests[0];

	for (; current->test_func != NULL; current++) {
        char foundmac[18] = {};
		fprintf(stderr, "Starting test %s with file %s\n", current->description, current->filename);
        arp_test_file = current->filename;

        len = strlen(current->ip);
	    if ((len + 2) > sizeof(ip)) {
		    return -1;
	    }

	    // Extend search string by one space
	    memcpy(ip, current->ip, len);
	    ip[len] = ' ';
	    ip[len+1] = '\0';

		rc = current->test_func(foundmac, ip);
        // check if result is expected
        if (rc != current->result) {
            fprintf(stderr, "test failed: unexpected result %d\n", rc);
            assert(0);
        }
        // check if foundmac is correct
        if ((rc == ARP_FOUND) && (strcmp(current->mac, foundmac))) {
            fprintf(stderr, "test failed: returned wrong MAC %s when %s was expected\n", foundmac, current->mac);
            assert(0);
        }
	}
	fprintf(stderr, "Finished all tests.\n");
}


