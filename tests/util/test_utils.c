/** @file test_utils.c
    @brief Test cases for utils functions
*/

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../../src/util.h"

struct a_test {
	const char *description;
	const char *ip;
	const int result;
	const char *mac;
};

struct a_test tests[] = {
	/* ips that should never be found */
	{"unknown IPv4 (TEST-NET)", "192.0.2.1", -1, NULL},
	{"unknown IPv6 (documentation prefix)", "2001:db8::1", -1, NULL},

	/* test for not an IP address */
	{"invalid IP string", "not_an_ip", 1, NULL},

	/* IPv4 neighbor entries set up by tests_in_network_namespace.sh */
	{"IPv4 single entry", "192.168.1.100", 0, "00:bb:cc:dd:ee:ff"},
	{"IPv4 shared MAC first entry", "192.168.1.101", 0, "11:bb:cc:dd:ee:ff"},
	{"IPv4 shared MAC second entry", "192.168.1.102", 0, "11:bb:cc:dd:ee:ff"},

	/* IPv6 neighbor entries set up by tests_in_network_namespace.sh */
	{"IPv6 single entry", "2001:db8::100", 0, "22:bb:cc:dd:ee:ff"},
	{"IPv6 shared MAC first entry", "2001:db8::101", 0, "33:bb:cc:dd:ee:ff"},
	{"IPv6 shared MAC second entry", "2001:db8::102", 0, "33:bb:cc:dd:ee:ff"},

	{NULL, NULL, 0, NULL},
};

int main(int argc, char **argv)
{
	struct a_test *current = &tests[0];

	for (; current->description != NULL; current++) {
		char mac[18] = {};
		fprintf(stderr, "Starting test: %s\n", current->description);

		int rc = get_client_mac(mac, current->ip);
		if (rc != current->result) {
			fprintf(stderr, "test failed: expected rc=%d, got rc=%d\n", current->result, rc);
			assert(0);
		}
		if (rc == 0 && strcmp(mac, current->mac) != 0) {
			fprintf(stderr, "test failed: expected mac=%s, got mac=%s\n", current->mac, mac);
			assert(0);
		}
	}
	fprintf(stderr, "Finished all tests.\n");
	return 0;
}
