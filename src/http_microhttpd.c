/********************************************************************\
 * This program is free software; you can redistribute it and/or		*
 * modify it under the terms of the GNU General Public License as	 *
 * published by the Free:Software Foundation; either version 2 of	 *
 * the License, or (at your option) any later version.							*
 *																																	*
 * This program is distributed in the hope that it will be useful,	*
 * but WITHOUT ANY WARRANTY; without even the implied warranty of	 *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the		*
 * GNU General Public License for more details.										 *
\********************************************************************/

/** @internal
 * @file http_microhttpd.c
 * @brief a httpd implementation using libmicrohttpd
 * @author Copyright (C) 2015 Alexander Couzens <lynxis@fe80.eu>
 */


#include <microhttpd.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <linux/limits.h>
#include <fcntl.h>
#include <unistd.h>

#include "client_list.h"
#include "conf.h"
#include "debug.h"
#include "firewall.h"
#include "auth.h"
#include "http_microhttpd.h"
#include "http_microhttpd_utils.h"
#include "mimetypes.h"
#include "safe.h"
#include "template.h"
#include "util.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

/* how much memory we reserve for extending template variables */
#define TMPLVAR_SIZE 4096

static t_client *add_client(const char *ip_addr);
static int authenticated(struct MHD_Connection *connection, const char *ip_addr, const char *mac, const char *url, t_client *client);
static int preauthenticated(struct MHD_Connection *connection, const char *ip_addr, const char *mac, const char *url, t_client *client);
static int authenticate_client(struct MHD_Connection *connection, const char *ip_addr, const char *mac, const char *url, t_client *client);
static int get_host_value_callback(void *cls, enum MHD_ValueKind kind, const char *key, const char *value);
static int serve_file(struct MHD_Connection *connection, t_client *client, const char *url);
static int show_splashpage(struct MHD_Connection *connection, t_client *client);
static int encode_and_redirect_to_splashpage(struct MHD_Connection *connection, const char *originurl);
static int redirect_to_splashpage(struct MHD_Connection *connection, t_client *client, const char *host, const char *url);
static int send_error(struct MHD_Connection *connection, int error);
static int send_redirect_temp(struct MHD_Connection *connection, const char *url);
static int send_refresh(struct MHD_Connection *connection);
static int is_foreign_hosts(struct MHD_Connection *connection, const char *host);
static int is_splashpage(const char *host, const char *url);
static int get_query(struct MHD_Connection *connection, char **collect_query);
static const char *get_redirect_url(struct MHD_Connection *connection);

static const char *lookup_mimetype(const char *filename);


struct collect_query {
	int i;
	char **elements;
};

struct collect_query_key {
	const char *key;
	const char *value;
};

static int collect_query_key(void *cls, enum MHD_ValueKind kind, const char *key, const char *value)
{
	struct collect_query_key *query_key = cls;
	query_key->value = NULL;

	if (!query_key)
		return MHD_NO;

	if (!key) {
		return MHD_YES;
	}

	if (!strcmp(key, query_key->key)) {
		query_key->value = value;
		/* stop execution of iterator */
		return MHD_NO;
	}
	return MHD_YES;
}

static int collect_query_string(void *cls, enum MHD_ValueKind kind, const char *key, const char * value)
{
	/* what happens when '?=foo' supplied? */
	struct collect_query *collect_query = cls;
	if (key && !value) {
		collect_query->elements[collect_query->i] = safe_strdup(key);
	} else if (key && value) {
		safe_asprintf(&(collect_query->elements[collect_query->i]), "%s=%s", key, value);
	}
	collect_query->i++;
	return MHD_YES;
}

/* a dump iterator required for counting all elements */
static int counter_iterator(void *cls, enum MHD_ValueKind kind, const char *key, const char *value)
{
	return MHD_YES;
}

static int is_foreign_hosts(struct MHD_Connection *connection, const char *host)
{
	char our_host[24];
	s_config *config = config_get_config();
	snprintf(our_host, 24, "%s:%u", config->gw_address, config->gw_port);

	/* we serve all request without a host entry as well we serve all request going to our gw_address */
	if (host == NULL)
		return 0;

	if (!strcmp(host, our_host))
		return 0;

	/* port 80 is special, because the hostname doesn't need a port */
	if (config->gw_port == 80 && !strcmp(host, config->gw_address))
		return 0;

	return 1;
}

static int is_splashpage(const char *host, const char *url)
{
	char our_host[24];
	s_config *config = config_get_config();
	snprintf(our_host, 24, "%s:%u", config->gw_address, config->gw_port);

	if (host == NULL) {
		/* no hostname given
		 * '/' -> splash
		 * '' -> splash [is this even possible with MHD?
		 */
		if (strlen(url) == 0 ||
				!strcmp("/", url)) {
			return 1;
		}
	} else {
		/* hostname give - check if it's our hostname */

		if (strcmp(host, our_host)) {
			/* hostname isn't ours */
			return 0;
		}

		/* '/' -> splash
		 * '' -> splash
		 */
		if (strlen(url) == 0 ||
				!strcmp("/", url)) {
			return 1;
		}

		if (strlen(url) > 0 &&
				!strcmp(config->splashpage, url+1)) {
			return 1;
		}
	}
	/* doesnt hit one of our rules - this isn't the splashpage */
	return 0;
}

/**
 * @brief get_ip
 * @param connection
 * @return ip address - must be freed by caller
 */
static char *
get_ip(struct MHD_Connection *connection)
{
	const union MHD_ConnectionInfo *connection_info;
	char *ip_addr = NULL;
	const struct sockaddr *client_addr;
	const struct sockaddr_in *addrin;
	const struct sockaddr_in6 *addrin6;
	if (!(connection_info = MHD_get_connection_info(connection, MHD_CONNECTION_INFO_CLIENT_ADDRESS))) {
		return NULL;
	}

	/* cast required for legacy MHD API < 0.9.6*/
	client_addr = (const struct sockaddr *)connection_info->client_addr;
	addrin = (const struct sockaddr_in *) client_addr;
	addrin6 = (const struct sockaddr_in6 *) client_addr;

	switch(client_addr->sa_family) {
	case AF_INET:
		ip_addr = calloc(1, INET_ADDRSTRLEN+1);
		if (ip_addr == NULL) {
			return NULL;
		}
		if (!inet_ntop(addrin->sin_family, &(addrin->sin_addr), ip_addr, sizeof(struct sockaddr_in))) {
			free(ip_addr);
			return NULL;
		}
		break;

	case AF_INET6:
		ip_addr = calloc(1, INET6_ADDRSTRLEN+1);
		if (ip_addr == NULL) {
			return NULL;
		}
		if (!inet_ntop(addrin6->sin6_family, &(addrin6->sin6_addr), ip_addr, sizeof(struct sockaddr_in6))) {
			free(ip_addr);
			return NULL;
		}
		break;
	}

	return ip_addr;
}

/**
 * @brief libmicrohttpd_cb called when the client do a request to this server
 * @param cls unused
 * @param connection - client connection
 * @param url - which url was called
 * @param method - POST / GET / ...
 * @param version http 1.0 or 1.1
 * @param upload_data - unused
 * @param upload_data_size - unused
 * @param ptr - unused
 * @return
 */
int
libmicrohttpd_cb(void *cls,
				struct MHD_Connection *connection,
				const char *url,
				const char *method,
				const char *version,
				const char *upload_data, size_t *upload_data_size, void **ptr)
{

	t_client *client;
	char *ip_addr;
	char *mac;
	int ret;

	debug(LOG_DEBUG, "access: %s %s", method, url);

	/* only allow get */
	if (0 != strcmp(method, "GET")) {
		debug(LOG_DEBUG, "Unsupported http method %s", method);
		return send_error(connection, 503);
	}

	/* switch between preauth, authenticated */
	/* - always - set caching headers
	 * a) possible implementation - redirect first and serve them using a tempo redirect
	 * b) serve direct
	 * should all requests redirected? even those to .css, .js, ... or respond with 404/503/...
	 */

	ip_addr = get_ip(connection);
	mac = arp_get(ip_addr);

	client = client_list_find(ip_addr, mac);
	if (client) {
		if (client->fw_connection_state == FW_MARK_AUTHENTICATED ||
				client->fw_connection_state == FW_MARK_TRUSTED) {
			/* client already authed - dangerous!!! This should never happen */
			ret = authenticated(connection, ip_addr, mac, url, client);
			free(mac);
			free(ip_addr);
			return ret;
		}
	}
	ret = preauthenticated(connection, ip_addr, mac, url, client);
	free(mac);
	free(ip_addr);
	return ret;
}

/**
 * @brief check if url contains authdir
 * @param url
 * @param authdir
 * @return
 *
 * url must look ("/%s/", authdir) to match this
 */
static int check_authdir_match(const char *url, const char *authdir)
{
	if (strlen(url) != strlen(authdir)+2)
		return 0;

	if (strncmp(url+1, authdir, strlen(authdir)))
		return 0;

	/* match */
	return 1;
}

static int check_token_is_valid(struct MHD_Connection *connection, t_client *client)
{
	/* token check */
	struct collect_query_key token_key = { .key = "token" };
	struct collect_query_key tok_key = { .key = "tok" };

	MHD_get_connection_values(connection, MHD_GET_ARGUMENT_KIND, &collect_query_key, &token_key);
	MHD_get_connection_values(connection, MHD_GET_ARGUMENT_KIND, &collect_query_key, &tok_key);

	/* token not found in query string */
	if (!token_key.value && !tok_key.value)
		return 0;

	if (token_key.value && !strcmp(client->token, token_key.value))
		return 1;

	if (tok_key.value && !strcmp(client->token, tok_key.value))
		return 1;

	return 0;
}


/**
 * @brief try_to_authenticate
 * @param connection
 * @param client
 * @param host
 * @param url
 * @return
 */
static int try_to_authenticate(struct MHD_Connection *connection, t_client *client, const char *host, const char *url)
{
	/* a successful auth looks like
	 * http://192.168.42.1:2050/nodogsplash_auth/?redir=http%3A%2F%2Fberlin.freifunk.net%2F&tok=94c4cdd2
	 * when authaction -> http://192.168.42.1:2050/nodogsplash_auth/
	 */
	s_config *config = config_get_config();

	/* we are checking here for the second '/' of /denydir/ */
	if (check_authdir_match(url, config->authdir)) {
		/* matched to authdir */
		if (check_token_is_valid(connection, client)) {
			return 1; /* valid token */
		}
	} else if (check_authdir_match(url, config->denydir)) {
		/* matched to deauth */
		/* TODO: do we need denydir? */
		return 0;
	}

	return 0;
}

/**
 * @brief authenticate the client and redirect them
 * @param connection
 * @param ip_addr - needs to be freed
 * @param mac - needs to be freed
 * @param redirect_url - redirect the client to this url
 * @return
 */
static int authenticate_client(struct MHD_Connection *connection,
							const char *ip_addr,
							const char *mac,
							const char *redirect_url,
							t_client *client)
{
	/* TODO: handle redirect_url == NULL */
	auth_client_action(ip_addr, mac, AUTH_MAKE_AUTHENTICATED);
	if (redirect_url)
		return send_redirect_temp(connection, redirect_url);
	else
		return send_error(connection, 200);
}

/**
 * @brief authenticated - called for all request from authenticated clients.
 * @param connection
 * @param ip_addr
 * @param mac
 * @param url
 * @param client
 * @return
 *
 * It's unsual to received request from clients which are already authed.
 * Happens when the user:
 * - clicked in multiple windows on "accept" -> redirect to origin - no checking
 * - when the user reloaded a splashpage -> redirect to origin
 * - when a user calls deny url -> deauth it
 */
static int authenticated(struct MHD_Connection *connection,
						const char *ip_addr,
						const char *mac,
						const char *url,
						t_client *client)
{
	s_config *config = config_get_config();
	const char *redirect_url;
	const char *host = NULL;
	char redirect_to_us[128];

	MHD_get_connection_values(connection, MHD_HEADER_KIND, get_host_value_callback, &host);

	if (is_splashpage(host, url) ||
			check_authdir_match(url, config->authdir)) {
		redirect_url = get_redirect_url(connection);
		/* TODO: what should we do when we get such request? */
		if (redirect_url == NULL || strlen(redirect_url) == 0)
			return show_splashpage(connection, client);
		else
			return authenticate_client(connection, ip_addr, mac, redirect_url, client);
	} else if (check_authdir_match(url, config->denydir)) {
		auth_client_action(ip_addr, mac, AUTH_MAKE_DEAUTHENTICATED);
		snprintf(redirect_to_us, 128, "http://%s:%u/", config->gw_address, config->gw_port);
		return send_redirect_temp(connection, redirect_to_us);
	}


	/* check if this is an late request meaning the user tries to get the internet, but ended up here,
	 * because the iptables rule came to late */
	if (is_foreign_hosts(connection, host)) {
		/* might happen if the firewall rule isn't yet installed */
		return send_refresh(connection);
	}

	/* user doesn't wants the splashpage or tried to auth itself */
	return serve_file(connection, client, url);
}

/**
 * @brief preauthenticated - called for all request of a client in this state.
 * @param connection
 * @param ip_addr
 * @param mac
 * @return
 */
static int preauthenticated(struct MHD_Connection *connection,
							const char *ip_addr,
							const char *mac,
							const char *url,
							t_client *client)
{
	const char *host = NULL;
	const char *redirect_url;
	s_config *config = config_get_config();

	if (!client) {
		client = add_client(ip_addr);
		if (!client)
			return send_error(connection, 503);
	}

	MHD_get_connection_values(connection, MHD_HEADER_KIND, get_host_value_callback, &host);

	/* check if this is a redirect query with a foreign host as target */
	if (is_foreign_hosts(connection, host)) {
		return redirect_to_splashpage(connection, client, host, url);
	}

	/* request is directed to us */
	/* check if client wants to be authenticated */
	if (check_authdir_match(url, config->authdir)) {

		/* Only the first request will redirected to config->redirectURL.
		 * When the client reloads a page when it's authenticated, it should be redirected
		 * to their origin url
		 */
		if (config->redirectURL)
			redirect_url = config->redirectURL;
		else
			redirect_url = get_redirect_url(connection);

		if (try_to_authenticate(connection, client, host, url)) {
			return authenticate_client(connection, ip_addr, mac, redirect_url, client);
		} else {
			/* user used an invalid token, redirect to splashpage but hold query "redir" intact */
			return encode_and_redirect_to_splashpage(connection, redirect_url);
		}
	}

	if (is_splashpage(host, url)) {
		return show_splashpage(connection, client);
	}

	/* no special handling left - try to serve static content to the user */
	return serve_file(connection, client, url);
}

/**
 * @brief encode originurl and redirect the client to the splash page
 * @param connection
 * @param client
 * @param originurl
 * @return
 */
static int encode_and_redirect_to_splashpage(struct MHD_Connection *connection, const char *originurl)
{
	char *splashpageurl = NULL;
	char encoded[2048];
	int ret;
	s_config *config = config_get_config();

	memset(encoded, 0, sizeof(encoded));
	if (originurl) {
		if (uh_urlencode(encoded, sizeof(encoded), originurl, strlen(originurl)) == -1) {
			debug(LOG_WARNING, "could not encode url");
		} else {
			debug(LOG_DEBUG, "originurl: %s", originurl);
		}
	}

	if (encoded[0])
		safe_asprintf(&splashpageurl, "http://%s:%u%s?redir=%s", config->gw_address , config->gw_port, "/splash.html", encoded);
	else
		safe_asprintf(&splashpageurl, "http://%s:%u%s", config->gw_address , config->gw_port, "/splash.html");

	debug(LOG_DEBUG, "splashpageurl: %s", splashpageurl);

	ret = send_redirect_temp(connection, splashpageurl);
	free(splashpageurl);
	return ret;
}

/**
 * @brief redirect_to_splashpage
 * @param connection
 * @param client
 * @param host
 * @param url
 * @return
 */
static int redirect_to_splashpage(struct MHD_Connection *connection, t_client *client, const char *host, const char *url)
{
	char *originurl = NULL;
	char *query = NULL;
	int ret = 0;

	get_query(connection, &query);
	if (!query) {
		/* no mem */
		return send_error(connection, 503);
	}

	safe_asprintf(&originurl, "http://%s%s%s%s", host, url, strlen(query) ? "?" : "" , query);
	ret = encode_and_redirect_to_splashpage(connection, originurl);
	free(originurl);
	free(query);
	return ret;
}


/**
 *	Add client making a request to client list.
 *	Return pointer to the client list entry for this client.
 *
 *	N.B.: This does not authenticate the client; it only makes
 *	their information available on the client list.
 */
static t_client *
add_client(const char *ip_addr)
{
	t_client *client;

	LOCK_CLIENT_LIST();
	client = client_list_add_client(ip_addr);
	UNLOCK_CLIENT_LIST();
	return client;
}

int send_redirect_temp(struct MHD_Connection *connection, const char *url)
{
	struct MHD_Response *response;
	int ret;
	char *redirect = NULL;

	const char *redirect_body = "<html><head></head><body><a href='%s'>Click here to continue to<br>%s</a></body></html>";
	safe_asprintf(&redirect, redirect_body, url, url);

	response = MHD_create_response_from_buffer(strlen(redirect), redirect, MHD_RESPMEM_MUST_FREE);
	if (!response)
		return send_error(connection, 503);

	// MHD_set_response_options(response, MHD_RF_HTTP_VERSION_1_0_ONLY, MHD_RO_END);
	MHD_add_response_header(response, "Location", url);
	MHD_add_response_header(response, "Connection", "close");
	ret = MHD_queue_response(connection, MHD_HTTP_TEMPORARY_REDIRECT, response);
	MHD_destroy_response(response);

	return ret;
}


/**
 * @brief get_url_from_query
 * @param connection
 * @param redirect_url as plaintext - not url encoded
 * @param redirect_url_len
 * @return NULL or redirect url
 */
static const char *get_redirect_url(struct MHD_Connection *connection)
{
	struct collect_query_key query_key = { .key = "redir" };

	MHD_get_connection_values(connection, MHD_GET_ARGUMENT_KIND, &collect_query_key, &query_key);

	if (!query_key.value)
		return NULL;

	return query_key.value;
}

/* save the query or empty string into **query.
 * the call must free query later */
static int get_query(struct MHD_Connection *connection, char **query)
{
	int element_counter;
	char **elements;
	struct collect_query collect_query;
	int i;
	int j;
	int length = 0;

	element_counter = MHD_get_connection_values(connection, MHD_GET_ARGUMENT_KIND, counter_iterator, NULL);
	if (element_counter == 0) {
		*query = safe_strdup("");
		return 0;
	}
	elements = calloc(element_counter, sizeof(char *));
	if (elements == NULL) {
		return 0;
	}
	collect_query.i = 0;
	collect_query.elements = elements;

	// static int get_host_value_callback(void *cls, enum MHD_ValueKind kind, const char *key, const char *value) {
	MHD_get_connection_values(connection, MHD_GET_ARGUMENT_KIND, collect_query_string, &collect_query);

	for(i=0; i<element_counter; i++) {
		if (!elements[i])
			continue;
		length += strlen(elements[i]);

		if (i >0) /* q=foo&o=bar the '&' need also some space */
			length++;
	}

	/* don't miss the zero terminator */
	*query = calloc(1, length+1);
	if (*query == NULL) {
		for(i=0; i < element_counter; i++) {
			free(elements[i]);
		}
		free(elements);
		return 0;
	}

	for(i=0, j=0; i<element_counter; i++) {
		if (!elements[i])
			continue;
		strncpy(*query + j, elements[i], length-j);
		free(elements[i]);
	}

	free(elements);
	return 0;
}

static int send_refresh(struct MHD_Connection *connection)
{
	struct MHD_Response *response = NULL;

	const char *refresh = "<html><meta http-equiv=\"refresh\" content=\"1\"><head/></html>";
	const char *mimetype = lookup_mimetype("foo.html");
	int ret;

	response = MHD_create_response_from_buffer(strlen(refresh), (char *)refresh, MHD_RESPMEM_PERSISTENT);
	MHD_add_response_header(response, "Content-Type", mimetype);
	MHD_add_response_header (response, MHD_HTTP_HEADER_CONNECTION, "close");
	ret = MHD_queue_response(connection, 200, response);

	return ret;
}

static int send_error(struct MHD_Connection *connection, int error)
{
	struct MHD_Response *response = NULL;
	// cannot automate since cannot translate automagically between error number and MHD's status codes -- and cannot rely on MHD_HTTP_ values to provide an upper bound for an array
	const char *page_200 = "<html><header><title>Authenticated</title><body><h1>Authenticated</h1></body></html>";
	const char *page_400 = "<html><head><title>Error 400</title></head><body><h1>Error 400 - Bad Request</h1></body></html>";
	const char *page_403 = "<html><head><title>Error 403</title></head><body><h1>Error 403 - Forbidden</h1></body></html>";
	const char *page_404 = "<html><head><title>Error 404</title></head><body><h1>Error 404 - Not Found</h1></body></html>";
	const char *page_500 = "<html><head><title>Error 500</title></head><body><h1>Error 500 - Internal Server Error. Oh no!</body></html>";
	const char *page_501 = "<html><head><title>Error 501</title></head><body><h1>Error 501 - Not Implemented</h1></body></html>";
	const char *page_503 = "<html><head><title>Error 503</title></head><body><h1>Error 503 - Internal Server Error</h1></body></html>";

	const char *mimetype = lookup_mimetype("foo.html");

	int ret = MHD_NO;

	switch (error) {
	case 200:
		response = MHD_create_response_from_buffer(strlen(page_200), (char *)page_200, MHD_RESPMEM_PERSISTENT);
		MHD_add_response_header(response, "Content-Type", mimetype);
		ret = MHD_queue_response(connection, error, response);
		break;

	case 400:
		response = MHD_create_response_from_buffer(strlen(page_400), (char *)page_400, MHD_RESPMEM_PERSISTENT);
		MHD_add_response_header(response, "Content-Type", mimetype);
		ret = MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, response);
		break;

	case 403:
		response = MHD_create_response_from_buffer(strlen(page_403), (char *)page_403, MHD_RESPMEM_PERSISTENT);
		MHD_add_response_header(response, "Content-Type", mimetype);
		ret = MHD_queue_response(connection, MHD_HTTP_FORBIDDEN, response);
		break;

	case 404:
		response = MHD_create_response_from_buffer(strlen(page_404), (char *)page_404, MHD_RESPMEM_PERSISTENT);
		MHD_add_response_header(response, "Content-Type", mimetype);
		ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, response);
		break;

	case 500:
		response = MHD_create_response_from_buffer(strlen(page_500), (char *)page_500, MHD_RESPMEM_PERSISTENT);
		MHD_add_response_header(response, "Content-Type", mimetype);
		ret = MHD_queue_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
		break;

	case 501:
		response = MHD_create_response_from_buffer(strlen(page_501), (char *)page_501, MHD_RESPMEM_PERSISTENT);
		MHD_add_response_header(response, "Content-Type", mimetype);
		ret = MHD_queue_response(connection, MHD_HTTP_NOT_IMPLEMENTED, response);
		break;
	case 503:
		response = MHD_create_response_from_buffer(strlen(page_503), (char *)page_503, MHD_RESPMEM_PERSISTENT);
		MHD_add_response_header(response, "Content-Type", mimetype);
		ret = MHD_queue_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
		break;
	}

	if (response)
		MHD_destroy_response(response);
	return ret;
}

/**
 * @brief get_host_value_callback safe Host into cls which is a char**
 * @param cls - a char ** pointer to our target buffer. This buffer will be alloc in this function.
 * @param kind - see doc of	MHD_KeyValueIterator's
 * @param key
 * @param value
 * @return MHD_YES or MHD_NO. MHD_NO means we found our item and this callback will not called again.
 */
static int get_host_value_callback(void *cls, enum MHD_ValueKind kind, const char *key, const char *value)
{
	const char **host = (const char **)cls;
	if (MHD_HEADER_KIND != kind) {
		*host = NULL;
		return MHD_NO;
	}

	if (!strcmp("Host", key)) {
		*host = value;
		return MHD_NO;
	}

	return MHD_YES;
}

/**
 * @brief show_splashpage is called when the client clicked on Ok as well when the client doesn't know us yet.
 * @param connection
 * @param client
 * @return
 */
static int show_splashpage(struct MHD_Connection *connection, t_client *client)
{
	struct MHD_Response *response;
	struct templater templor;
	s_config *config = config_get_config();
	int ret = -1;
	char filename[PATH_MAX];
	const char *mimetype;
	int size = 0, bytes = 0;
	int splashpage_fd;
	char *splashpage_result;
	char *splashpage_tmpl;

	snprintf(filename, PATH_MAX, "%s/%s",config->webroot ,config->splashpage);

	splashpage_fd = open(filename, O_RDONLY);
	if (splashpage_fd < 0)
		return send_error(connection, 404);

	mimetype = lookup_mimetype(filename);

	/* input size */
	size = lseek(splashpage_fd, 0, SEEK_END);
	lseek(splashpage_fd, 0, SEEK_SET);

	/* we TMPLVAR_SIZE for template variables */
	splashpage_tmpl = calloc(1, size);
	if (splashpage_tmpl == NULL) {
		close(splashpage_fd);
		return send_error(connection, 503);
	}
	splashpage_result = calloc(1, size + TMPLVAR_SIZE);
	if (splashpage_result == NULL) {
		close(splashpage_fd);
		free(splashpage_tmpl);
		return send_error(connection, 503);
	}

	while (bytes < size) {
		ret = read(splashpage_fd, splashpage_tmpl+bytes, size-bytes);
		if (ret < 0) {
			free(splashpage_result);
			free(splashpage_tmpl);
			close(splashpage_fd);
			return send_error(connection, 503);
		}
		bytes += ret;
	}

	char *uptime = get_uptime_string();
	char *nclients = NULL;
	char *maxclients = NULL;
	char *denyaction = NULL;
	char *authaction = NULL;
	char *authtarget = NULL;
	const char *redirect_url = NULL;
	char redirect_url_encoded[2048];
	char *imagesdir = NULL;
	char *pagesdir = NULL;

	memset(redirect_url_encoded, 0, sizeof(redirect_url_encoded));
	redirect_url = get_redirect_url(connection);
	if (redirect_url) {
		uh_urlencode(redirect_url_encoded, sizeof(redirect_url_encoded), redirect_url, strlen(redirect_url));
	}

	safe_asprintf(&nclients, "%d", get_client_list_length());
	safe_asprintf(&maxclients, "%d", config->maxclients);
	safe_asprintf(&denyaction, "http://%s:%d/%s/", config->gw_address, config->gw_port, config->denydir);
	safe_asprintf(&authaction, "http://%s:%d/%s/", config->gw_address, config->gw_port, config->authdir);
	safe_asprintf(&authtarget, "http://%s:%d/%s/?token=%s&redir=%s", config->gw_address, config->gw_port, config->authdir, client->token, redirect_url_encoded);
	safe_asprintf(&pagesdir, "/%s", config->pagesdir);
	safe_asprintf(&imagesdir, "/%s", config->imagesdir);

	tmpl_init_templor(&templor);
	tmpl_set_variable(&templor, "authaction", authaction);
	tmpl_set_variable(&templor, "authtarget", authtarget);
	tmpl_set_variable(&templor, "clientip", client->ip);
	tmpl_set_variable(&templor, "clientmac", client->mac);
	tmpl_set_variable(&templor, "denyaction", denyaction);
	tmpl_set_variable(&templor, "error_msg", "");

	tmpl_set_variable(&templor, "gatewaymac", config->gw_mac);
	tmpl_set_variable(&templor, "gatewayname", config->gw_name);

	tmpl_set_variable(&templor, "imagesdir", imagesdir);
	tmpl_set_variable(&templor, "pagesdir", pagesdir);

	tmpl_set_variable(&templor, "maxclients", maxclients);
	tmpl_set_variable(&templor, "nclients", nclients);

	tmpl_set_variable(&templor, "redir", redirect_url);
	tmpl_set_variable(&templor, "tok", client->token);
	tmpl_set_variable(&templor, "token", client->token);
	tmpl_set_variable(&templor, "uptime", uptime);
	tmpl_set_variable(&templor, "version", VERSION);

	tmpl_parse(&templor, splashpage_result, size + TMPLVAR_SIZE, splashpage_tmpl, size);
	free(splashpage_tmpl);
	free(uptime);
	free(nclients);
	free(maxclients);
	free(denyaction);
	free(authaction);
	free(authtarget);
	free(pagesdir);
	free(imagesdir);

	response = MHD_create_response_from_buffer(strlen(splashpage_result), (void *)splashpage_result, MHD_RESPMEM_MUST_FREE);
	if (!response) {
		close(splashpage_fd);
		return send_error(connection, 503);
	}

	MHD_add_response_header(response, "Content-Type", mimetype);
	ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
	MHD_destroy_response(response);

	close(splashpage_fd);

	return ret;
}

/**
 * @brief return an extension like `csv` if file = '/bar/foobar.csv'.
 * @param filename
 * @return a pointer within file is returned. NULL can be returned as well as
 */
const char *get_extension(const char *filename)
{
	int pos = strlen(filename);
	while(pos > 0) {
		pos--;
		switch (filename[pos]) {
		case '/':
			return NULL;
		case '.':
			return (filename+pos+1);
		}
	}

	return NULL;
}

#define DEFAULT_MIME_TYPE "application/octet-stream"

const char *lookup_mimetype(const char *filename)
{
	int i;
	const char *extension;

	if (!filename) {
		return NULL;
	}

	extension = get_extension(filename);
	if (!extension)
		return DEFAULT_MIME_TYPE;

	for(i=0; i< ARRAY_SIZE(uh_mime_types); i++) {
		if (strcmp(extension, uh_mime_types[i].extn) == 0) {
			return uh_mime_types[i].mime;
		}
	}

	debug(LOG_INFO, "Could not find corresponding mimetype for %s extension", extension);

	return DEFAULT_MIME_TYPE;
}

/**
 * @brief serve_file try to serve a request via filesystem. Using webroot as root.
 * @param connection
 * @param client
 * @return
 */
static int serve_file(struct MHD_Connection *connection, t_client *client, const char *url)
{
	struct stat stat_buf;
	s_config *config = config_get_config();
	struct MHD_Response *response;
	char filename[PATH_MAX];
	int ret = MHD_NO;
	const char *mimetype = NULL;
	off_t size;

	snprintf(filename, PATH_MAX, "%s/%s", config->webroot, url);

	/* check if file exists and is not a directory */
	ret = stat(filename, &stat_buf);
	if (ret) {
		/* stat failed */
		return send_error(connection, 404);
	}

	if (!S_ISREG(stat_buf.st_mode)) {
#ifdef S_ISLNK
		/* ignore links */
		if (!S_ISLNK(stat_buf.st_mode))
#endif /* S_ISLNK */
		return send_error(connection, 404);
	}

	int fd = open(filename, O_RDONLY);
	if (fd < 0)
		return send_error(connection, 404);

	mimetype = lookup_mimetype(filename);

	/* serving file and creating response */
	size = lseek(fd, 0, SEEK_END);
	if (size < 0)
		return send_error(connection, 404);

	response = MHD_create_response_from_fd(size, fd);
	if (!response)
		return send_error(connection, 503);

	MHD_add_response_header(response, "Content-Type", mimetype);
	ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
	MHD_destroy_response(response);

	return ret;
}
