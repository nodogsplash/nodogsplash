/** @file test_state_file.c
    @brief Test cases for state_file feature
    @author Copyright (C) 2025 Alexander Couzens <lynxis@fe80.eu>
*/


#include <asm-generic/errno-base.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../../src/client_list.h"
#include "../../src/conf.h"
#include "../../src/state_file.h"

time_t started_time = 0;
unsigned int authenticated_since_start = 0;

int auth_change_state(t_client *client, const unsigned int new_state, const char *reason)
{
	return 0;
}

void test_mini_json(void)
{
	assert(state_file_import("mini.json") == 0);
	assert(get_client_list_length() == 0);
}

void test_other_version(void)
{
	assert(state_file_import("other_version.json") == -EINVAL);
}

void test_other_name(void)
{
	assert(state_file_import("other_name.json") == -EINVAL);
}

void test_missing_version(void)
{
	assert(state_file_import("missing_version.json") == -EINVAL);
}

void test_missing_name(void)
{
	assert(state_file_import("missing_name.json") == -EINVAL);
}

void test_inval_json(void)
{
	assert(state_file_import("inval.json") == -1);
}

void file_not_exist(void)
{
	assert(state_file_import("file_not_exist.json") == 1);
}

void validate_client_a(t_client *client)
{
	assert(client);
	assert(!strcmp(client->mac, "00:16:3e:d8:29:6e"));
	assert(!strcmp(client->ip, "192.168.42.222"));
	assert(!strcmp(client->token, "fb843328"));
	assert(client->id == 1);
	assert(client->counters.last_updated == 1756220171);
	assert(client->counters.incoming == 1586);
	assert(client->counters.outgoing == 918);
}

void validate_client_b(t_client *client)
{
	assert(client);
	assert(!strcmp(client->mac, "00:16:3e:06:e3:7c"));
	assert(!strcmp(client->ip, "192.168.42.44"));
	assert(!strcmp(client->token, "49c1fb0e"));
	assert(client->id == 2);
	assert(client->counters.last_updated == 1756220222);
	assert(client->counters.incoming == 6890102);
	assert(client->counters.outgoing == 113871);
}

void validate_client_c(t_client *client)
{
	assert(client);
	assert(!strcmp(client->mac, "00:16:3e:06:ea:aa"));
	assert(!strcmp(client->ip, "192.168.42.42"));
	assert(!strcmp(client->token, "13523b0e"));
	assert(client->id == 3);
	assert(client->counters.last_updated == 1756220222);
	assert(client->counters.incoming == 6890102);
	assert(client->counters.outgoing == 113871);
}

void print_client_list(void)
{
	t_client *client = client_get_first_client();
	while (client != NULL) {
		fprintf(stderr, "Client id %d\n", client->id);

		fprintf(stderr, "  IP: %s MAC: %s\n", client->ip, client->mac);
		fprintf(stderr, "  Token: %s\n", client->token ? client->token : "none");

		fprintf(stderr, "  session_start: %ld\n", client->session_start);
		fprintf(stderr, "  session_end: %ld\n", client->session_end);

		fprintf(stderr, "  counters.last_updated: %ld\n", client->counters.last_updated);
		fprintf(stderr, "  counters.incoming: %lld\n", client->counters.incoming);
		fprintf(stderr, "  counters.outgoing: %lld\n", client->counters.outgoing);
		fprintf(stderr, "  download_limit: %d\n", client->download_limit);
		fprintf(stderr, "  upload_limit: %d\n", client->upload_limit);

		client = client->next;
	}
}

void one_client(void)
{
	assert(state_file_import("one_client.json") == 0);
	assert(get_client_list_length() == 1);
	t_client *client = client_get_first_client();
	validate_client_b(client);
}

void one_client_no_counter(void)
{
	assert(state_file_import("one_client_no_counter.json") == -3);
}

void one_client_missing_counter(void)
{
	assert(state_file_import("one_client_missing_counter.json") == -3);
}

void three_clients(void)
{
	assert(state_file_import("three_clients.json") == 0);
	print_client_list();

	assert(get_client_list_length() == 3);
	t_client *client = client_get_first_client();
	validate_client_a(client);

	client = client->next;
	validate_client_b(client);

	client = client->next;
	validate_client_c(client);
}

void three_clients_dup_id(void)
{
	assert(state_file_import("three_clients_dup_id.json") == -3);
	print_client_list();
}

void three_clients_dup_mac(void)
{
	/* 3 clients, but with 2 clients containing only the same mac, but not ip */
	assert(state_file_import("three_clients_dup_mac.json") == 0);
	print_client_list();
	assert(get_client_list_length() == 3);
}

void three_clients_dup_ip(void)
{
	/* 3 clients, but with 2 clients containing only the same ip, but not mac */
	assert(state_file_import("three_clients_dup_ip.json") == 0);
	print_client_list();
	assert(get_client_list_length() == 3);
}

struct a_test {
	const char *name;
	const char *description;
	void (*test_func)(void);
};

struct a_test tests[] = {
    {"mini.json", "Test with a minimal version of the json", test_mini_json},
    {"other_version.json", "Test with a wrong version", test_other_version},
    {"other_name.json", "Test with a wrong name", test_other_name},
    {"missing_version.json", "Test with version missing", test_missing_version},
    {"missing_name.json", "Test with name missing", test_missing_name},
    {"inval.json", "Test with an invalid json", test_inval_json},
    {"file_not_exist.json", "Test with a missing json file", file_not_exist},
    {"one_client.json", "Test with a valid state file containing a single client", one_client},
    {"one_client_no_counter.json", "Test with an invalid state which doesn't have counter elements", one_client_no_counter},
    {"one_client_missing_counter.json", "Test with an invalid state which doesn't have counters key", one_client_missing_counter},
    {"three_clients.json", "Test with a valid state file containing a three clients", three_clients},
    {"three_clients_dup_id.json", "Test invalid state file containing a duplicate id", three_clients_dup_id},
    {"three_clients_dup_ip.json", "Test valid state file containing a duplicate ip", three_clients_dup_ip},
    {"three_clients_dup_mac.json", "Test valid state file containing a duplicate mac", three_clients_dup_mac},
    {NULL, NULL},
    };

int main(int argc, char **argv)
{
	s_config *config = config_get_config();
	config->maxclients = 256;

	client_list_init();
	struct a_test *current = &tests[0];
	for (; current->test_func != NULL; current++) {
		fprintf(stderr, "Starting test %s (%s)\n", current->name, current->description);
		current->test_func();
		client_list_flush();
	}
	fprintf(stderr, "Finished all tests.");
}
