/************************************************************************\
 * This program is free software; you can redistribute it and/or	*
 * modify it under the terms of the GNU General Public License as	*
 * published by the Free:Software Foundation; either version 2 of	*
 * the License, or (at your option) any later version.			*
 *									*
 * This program is distributed in the hope that it will be useful,	*
 * but WITHOUT ANY WARRANTY; without even the implied warranty of	*
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the		*
 * GNU General Public License for more details.				*
\************************************************************************/

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
#include "common.h"
#include "debug.h"
#include "auth.h"
#include "http_microhttpd.h"
#include "http_microhttpd_utils.h"
#include "fw_iptables.h"
#include "mimetypes.h"
#include "safe.h"
#include "template.h"
#include "util.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

/* how much memory we reserve for extending template variables */
#define TMPLVAR_SIZE 4096

/* Max length of a query string QUERYMAXLEN in bytes defined in common.h */

/* Max dynamic html page size HTMLMAXSIZE in bytes defined in common.h */


static t_client *add_client(const char mac[], const char ip[]);
static int authenticated(struct MHD_Connection *connection, const char *url, t_client *client);
static int preauthenticated(struct MHD_Connection *connection, const char *url, t_client *client);
static int authenticate_client(struct MHD_Connection *connection, const char *redirect_url, t_client *client);
static int get_host_value_callback(void *cls, enum MHD_ValueKind kind, const char *key, const char *value);
static int get_user_agent_callback(void *cls, enum MHD_ValueKind kind, const char *key, const char *value);
static int serve_file(struct MHD_Connection *connection, t_client *client, const char *url);
static int show_splashpage(struct MHD_Connection *connection, t_client *client);
static int show_statuspage(struct MHD_Connection *connection, t_client *client);
static int show_preauthpage(struct MHD_Connection *connection, const char *query);
static int encode_and_redirect_to_splashpage(struct MHD_Connection *connection, t_client *client, const char *originurl, const char *querystr);
static int redirect_to_splashpage(struct MHD_Connection *connection, t_client *client, const char *host, const char *url);
static int send_error(struct MHD_Connection *connection, int error);
static int send_redirect_temp(struct MHD_Connection *connection, t_client *client, const char *url);
static int send_refresh(struct MHD_Connection *connection);
static int is_foreign_hosts(struct MHD_Connection *connection, const char *host);
static int is_splashpage(const char *host, const char *url);
static int get_query(struct MHD_Connection *connection, char **collect_query, const char *separator);
static char *construct_querystring(t_client *client, char *originurl, char *querystr);
static const char *get_redirect_url(struct MHD_Connection *connection);
static const char *lookup_mimetype(const char *filename);


/* Call the BinAuth script */
static int do_binauth(struct MHD_Connection *connection, const char *binauth, t_client *client,
	int *seconds_ret, int *upload_ret, int *download_ret, const char *redirect_url)
{
	char username_enc[64] = {0};
	char password_enc[64] = {0};
	char redirect_url_enc_buf[QUERYMAXLEN] = {0};
	const char *username;
	const char *password;
	char msg[255] = {0};
	char *argv = NULL;
	const char *user_agent = NULL;
	char enc_user_agent[256] = {0};
	int seconds;
	int upload;
	int download;
	int rc;

	MHD_get_connection_values(connection, MHD_HEADER_KIND, get_user_agent_callback, &user_agent);

	debug(LOG_INFO, "BinAuth: User Agent is [ %s ]", user_agent);

	username = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "username");
	password = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "password");

	if (!username || strlen(username) == 0) {
		username="na";
	}

	if (!password || strlen(password) == 0) {
		password="na";
	}

	uh_urlencode(username_enc, sizeof(username_enc), username, strlen(username));
	uh_urlencode(password_enc, sizeof(password_enc), password, strlen(password));
	uh_urlencode(redirect_url_enc_buf, sizeof(redirect_url_enc_buf), redirect_url, strlen(redirect_url));
	uh_urlencode(enc_user_agent, sizeof(enc_user_agent), user_agent, strlen(user_agent));

	// Note: username, password and user_agent may contain spaces so argument should be quoted
	safe_asprintf(&argv,"%s auth_client %s '%s' '%s' '%s' '%s' '%s'",
		binauth, client->mac, username_enc, password_enc, redirect_url_enc_buf, enc_user_agent, client->ip);

	debug(LOG_INFO, "BinAuth argv: %s", argv);
	rc = execute_ret_url_encoded(msg, sizeof(msg) - 1, argv);
	free(argv);

	if (rc != 0) {
		return -1;
	}

	rc = sscanf(msg, "%d %d %d", &seconds, &upload, &download);

	// store assigned parameters
	switch (rc) {
		case 3:
			*download_ret = MAX(download, 0);
		case 2:
			*upload_ret = MAX(upload, 0);
		case 1:
			*seconds_ret = MAX(seconds, 0);
		case 0:
			break;
		default:
			return -1;
	}

	return 0;
}

struct collect_query {
	int i;
	char **elements;
};

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
	char our_host[MAX_HOSTPORTLEN];
	s_config *config = config_get_config();
	snprintf(our_host, MAX_HOSTPORTLEN, "%s", config->gw_address);

	/* we serve all request without a host entry as well we serve all request going to our gw_address */
	if (host == NULL)
		return 0;

	if (!strcmp(host, our_host))
		return 0;

	/* port 80 is special, because the hostname doesn't need a port */
	if (config->gw_port == 80 && !strcmp(host, config->gw_ip))
		return 0;

	return 1;
}

static int is_splashpage(const char *host, const char *url)
{
	char our_host[MAX_HOSTPORTLEN];
	s_config *config = config_get_config();
	snprintf(our_host, MAX_HOSTPORTLEN, "%s", config->gw_address);

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


/* @brief Get client mac by ip address from neighbor cache */
int
get_client_mac(char mac[18], const char req_ip[])
{
	char line[255] = {0};
	char ip[64];
	FILE *stream;
	int len;

	len = strlen(req_ip);

	if ((len + 2) > sizeof(ip)) {
		return -1;
	}

	// Extend search string by one space
	memcpy(ip, req_ip, len);
	ip[len] = ' ';
	ip[len+1] = '\0';

	stream = popen("ip neigh show", "r");
	if (!stream) {
		return -1;
	}

	while (fgets(line, sizeof(line) - 1, stream) != NULL) {
		if (0 == strncmp(line, ip, len + 1)) {
			if (1 == sscanf(line, "%*s %*s %*s %*s %17[A-Fa-f0-9:] ", mac)) {
				pclose(stream);
				return 0;
			}
		}
	}

	pclose(stream);

	return -1;
}

/**
 * @brief get_client_ip
 * @param connection
 * @return ip address - must be freed by caller
 */
static int
get_client_ip(char ip_addr[INET6_ADDRSTRLEN], struct MHD_Connection *connection)
{
	const union MHD_ConnectionInfo *connection_info;
	const struct sockaddr *client_addr;
	const struct sockaddr_in *addrin;
	const struct sockaddr_in6 *addrin6;

	if (!(connection_info = MHD_get_connection_info(connection, MHD_CONNECTION_INFO_CLIENT_ADDRESS))) {
		return -1;
	}

	/* cast required for legacy MHD API < 0.9.6*/
	client_addr = (const struct sockaddr *) connection_info->client_addr;
	addrin = (const struct sockaddr_in *) client_addr;
	addrin6 = (const struct sockaddr_in6 *) client_addr;

	switch (client_addr->sa_family) {
	case AF_INET:
		if (inet_ntop(AF_INET, &addrin->sin_addr, ip_addr, INET_ADDRSTRLEN)) {
			return 0;
		}
		break;

	case AF_INET6:
		if (inet_ntop(AF_INET6, &addrin6->sin6_addr, ip_addr, INET6_ADDRSTRLEN)) {
			return 0;
		}
		break;
	}

	return -1;
}

/**
 * @brief libmicrohttpd_cb called when the client does a request to this server
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
	char ip[INET6_ADDRSTRLEN+1];
	char mac[18];
	int rc = 0;

	debug(LOG_DEBUG, "access: %s %s", method, url);

	/* only allow get */
	if (0 != strcmp(method, "GET")) {
		debug(LOG_DEBUG, "Unsupported http method %s", method);
		return send_error(connection, 403);
	}

	/* switch between preauth, authenticated */
	/* - always - set caching headers
	 * a) possible implementation - redirect first and serve them using a tempo redirect
	 * b) serve direct
	 * should all requests redirected? even those to .css, .js, ... or respond with 404/503/...
	 */

	rc = get_client_ip(ip, connection);
	if (rc != 0) {
		return send_error(connection, 503);
	}

	rc = get_client_mac(mac, ip);
	if (rc != 0) {
		return send_error(connection, 503);
	}

	client = client_list_find(mac, ip);
	if (!client) {
		client = add_client(mac, ip);
		if (!client) {
			return send_error(connection, 403);
		}
	}

	if (client && (client->fw_connection_state == FW_MARK_AUTHENTICATED ||
			client->fw_connection_state == FW_MARK_TRUSTED)) {
		/* client already authed - dangerous!!! This should never happen */
		return authenticated(connection, url, client);
	}

	return preauthenticated(connection, url, client);
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
	if (strlen(url) != (2 + strlen(authdir)))
		return 0;

	if (strncmp(url + 1, authdir, strlen(authdir)))
		return 0;

	/* match */
	return 1;
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
	s_config *config;
	const char *tok;
	char hid[128] = {0};
	char rhid[128] = {0};
	char *rhidraw = NULL;

	/* a successful auth looks like
	 * http://192.168.42.1:2050/nodogsplash_auth/?redir=http%3A%2F%2Fberlin.freifunk.net%2F&tok=94c4cdd2
	 * when authaction -> http://192.168.42.1:2050/nodogsplash_auth/
	 */
	config = config_get_config();

	/* Check for authdir */
	if (check_authdir_match(url, config->authdir)) {
		tok = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "tok");
		debug(LOG_DEBUG, "client->token=%s tok=%s ", client->token, tok );

		//Check if token (tok) or hash_id (hid) mode
		if (strlen(tok) > 8) {
			// hid mode
			hash_str(hid, sizeof(hid), client->token);
			safe_asprintf(&rhidraw, "%s%s", hid, config->fas_key);
			hash_str(rhid, sizeof(rhid), rhidraw);
			free (rhidraw);
			if (tok && !strcmp(rhid, tok)) {
				/* rhid is valid */
				return 1;
			}
		} else {
			// tok mode
			if (tok && !strcmp(client->token, tok)) {
				/* Token is valid */
				return 1;
			}
		}
	}

	debug(LOG_WARNING, "Token is invalid" );

/*	//TODO: do we need denydir?
	if (check_authdir_match(url, config->denydir)) {
		// matched to deauth
		return 0;
	}
*/

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
							const char *redirect_url,
							t_client *client)
{
	s_config *config = config_get_config();
	time_t now = time(NULL);
	int seconds = 60 * config->session_timeout;
	int upload = 0;
	int download = 0;
	int rc;
	int ret;
	char query_str[QUERYMAXLEN] = {0};
	char redirect_url_enc[QUERYMAXLEN] = {0};
	char *querystr = query_str;

	debug(LOG_INFO, "redirect_url is [ %s ]", redirect_url);

	if (config->binauth) {
		rc = do_binauth(connection, config->binauth, client, &seconds, &upload, &download, redirect_url);
		if (rc != 0) {
			/*BinAuth denies access so redirect client back to login/splash page where they can try again.
				If FAS is enabled, this will cause nesting of the contents of redirect_url,
				FAS should account for this if used with BinAuth.
			*/

			uh_urlencode(redirect_url_enc, sizeof(redirect_url_enc), redirect_url, strlen(redirect_url));

			debug(LOG_DEBUG, "redirect_url after binauth deny: %s", redirect_url);
			debug(LOG_DEBUG, "redirect_url_enc after binauth deny: %s", redirect_url_enc);

			querystr=construct_querystring(client, redirect_url_enc, querystr);
			ret = encode_and_redirect_to_splashpage(connection, client, redirect_url_enc, querystr);
			return ret;
		}
		rc = auth_client_auth(client->id, "client_auth");
	} else {
		rc = auth_client_auth(client->id, NULL);
	}

	if (rc != 0) {
		return send_error(connection, 503);
	}

	/* set client values */
	client->download_limit = download;
	client->upload_limit = upload;
	client->session_start = now;

	if (seconds) {
		client->session_end = now + seconds;
	} else {
		client->session_end = 0;
	}

	if (redirect_url) {
		return send_redirect_temp(connection, client, redirect_url);
	} else {
		return send_error(connection, 200);
	}
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
 * It's unsual to received request from clients which are already authenticated.
 * Happens when the user:
 * - clicked in multiple windows on "accept" -> redirect to origin - no checking
 * - when the user reloaded a splashpage -> redirect to origin
 * - when a user calls deny url -> deauth it
 */
static int authenticated(struct MHD_Connection *connection,
						const char *url,
						t_client *client)
{
	s_config *config = config_get_config();
	const char *host = NULL;
	char redirect_to_us[128];
	char *fasurl = NULL;
	int ret;

	ret = MHD_get_connection_values(connection, MHD_HEADER_KIND, get_host_value_callback, &host);

	if (ret < 1) {
		debug(LOG_ERR, "authenticated: Error getting host");
		return ret;
	}

	/* check if this is a late request, meaning the user tries to get the internet, but ended up here,
	 * because the iptables rule came too late */
	if (is_foreign_hosts(connection, host)) {
		/* might happen if the firewall rule isn't yet installed */
		return send_refresh(connection);
	}

	if (check_authdir_match(url, config->denydir)) {
		auth_client_deauth(client->id, "client_deauth");
		snprintf(redirect_to_us, sizeof(redirect_to_us), "http://%s/", config->gw_address);
		return send_redirect_temp(connection, client, redirect_to_us);
	}

	if (check_authdir_match(url, config->authdir)) {
		if (config->fas_port && !config->preauth) {
			safe_asprintf(&fasurl, "%s?clientip=%s&gatewayname=%s&gatewayaddress=%s&status=authenticated",
				config->fas_url, client->ip, config->gw_name, config->gw_address);
			debug(LOG_DEBUG, "fasurl %s", fasurl);
			ret = send_redirect_temp(connection, client, fasurl);
			free(fasurl);
			return ret;
		} else if (config->fas_port && config->preauth) {
			safe_asprintf(&fasurl, "?clientip=%s%sgatewayname=%s%sgatewayaddress=%s%sstatus=authenticated",
				client->ip, QUERYSEPARATOR, config->gw_name, QUERYSEPARATOR,  config->gw_address, QUERYSEPARATOR);
			debug(LOG_DEBUG, "fasurl %s", fasurl);
			ret = show_preauthpage(connection, fasurl);
			free(fasurl);
			return ret;	
		} else {
			return show_statuspage(connection, client);
		}
	}

	if (check_authdir_match(url, config->preauthdir)) {
		if (config->fas_port) {
			safe_asprintf(&fasurl, "?clientip=%s&gatewayname=%s&gatewayaddress=%s&status=authenticated",
				client->ip, config->gw_name, config->gw_address);
			debug(LOG_DEBUG, "fasurl %s", fasurl);
			ret = show_preauthpage(connection, fasurl);
			free(fasurl);
			return ret;
		} else {
			return show_statuspage(connection, client);
		}
	}

	/* user doesn't want the splashpage or tried to auth itself */
	return serve_file(connection, client, url);
}

/**
 * @brief show_preauthpage - run preauth script and serve output.
 */
static int show_preauthpage(struct MHD_Connection *connection, const char *query)
{
	s_config *config = config_get_config();
	char msg[HTMLMAXSIZE] = {0};
	const char *user_agent = NULL;
	char enc_user_agent[256] = {0};

	// Encoded querystring could be bigger than the unencoded version
	char enc_query[QUERYMAXLEN + QUERYMAXLEN/2] = {0};

	int rc;
	int ret;
	struct MHD_Response *response;

	MHD_get_connection_values(connection, MHD_HEADER_KIND, get_user_agent_callback, &user_agent);

	debug(LOG_INFO, "PreAuth: User Agent is [ %s ]", user_agent);

	uh_urlencode(enc_user_agent, sizeof(enc_user_agent), user_agent, strlen(user_agent));

	if (query) {
		uh_urlencode(enc_query, sizeof(enc_query), query, strlen(query));
		debug(LOG_INFO, "PreAuth: query: %s", query);
	}

	rc = execute_ret(msg, HTMLMAXSIZE - 1, "%s '%s' '%s'", config->preauth, enc_query, enc_user_agent);

	if (rc != 0) {
		debug(LOG_WARNING, "Preauth script: %s '%s' - failed to execute", config->preauth, query);
		return -1;
	}

	// serve the script output (in msg)
	response = MHD_create_response_from_buffer(strlen(msg), (char *)msg, MHD_RESPMEM_MUST_COPY);

	if (!response) {
		return send_error(connection, 503);
	}

	MHD_add_response_header(response, "Content-Type", "text/html; charset=utf-8");
	ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
	MHD_destroy_response(response);
	return ret;
}

/**
 * @brief preauthenticated - called for all request of a client in this state.
 * @param connection
 * @param ip_addr
 * @param mac
 * @return
 */
static int preauthenticated(struct MHD_Connection *connection,
							const char *url,
							t_client *client)
{
	const char *host = NULL;
	const char *redirect_url;
	char query_str[QUERYMAXLEN] = {0};
	char *query = query_str;
	char *querystr = query_str;
	char portstr[MAX_HOSTPORTLEN] = {0};
	char originurl[QUERYMAXLEN] = {0};

	int ret;
	s_config *config = config_get_config();

	debug(LOG_DEBUG, "url: %s", url);

	/* Check for preauthdir */
	if (check_authdir_match(url, config->preauthdir)) {

		debug(LOG_DEBUG, "preauthdir url detected: %s", url);

		get_query(connection, &query, QUERYSEPARATOR);

		ret = show_preauthpage(connection, query);
		return ret;
	}

	ret = MHD_get_connection_values(connection, MHD_HEADER_KIND, get_host_value_callback, &host);

	if (ret < 1) {
		debug(LOG_ERR, "preauthenticated: Error getting host");
		return ret;
	}

	debug(LOG_DEBUG, "preauthenticated: Requested Host is [ %s ]", host);
	debug(LOG_DEBUG, "preauthenticated: Requested url is [ %s ]", url);
	debug(LOG_DEBUG, "preauthenticated: Gateway Address is [ %s ]", config->gw_address);
	debug(LOG_DEBUG, "preauthenticated: Gateway Port is [ %u ]", config->gw_port);

	/* check if this is an attempt to directly access the basic splash page when FAS is enabled  */
	if (config->fas_port) {
		snprintf(portstr, MAX_HOSTPORTLEN, ":%u", config->gw_port);

		debug(LOG_DEBUG, "preauthenticated: FAS is enabled");
		debug(LOG_DEBUG, "preauthenticated: NDS port ID is [ %s ]", portstr);
		debug(LOG_DEBUG, "preauthenticated: NDS port ID search result is [ %s ]", strstr(host, portstr));

		if (check_authdir_match(url, config->authdir) || strstr(host, "/splash.css") == NULL) {
			debug(LOG_DEBUG, "preauthenticated: splash.css or authdir detected");
		} else {
			if (strstr(host, portstr) != NULL) {
				debug(LOG_DEBUG, "preauthenticated:  403 Direct Access Forbidden");
				ret = send_error(connection, 403);
				return ret;
			}
		}
	}

	/* check if this is a redirect query with a foreign host as target */
	if (is_foreign_hosts(connection, host)) {
		return redirect_to_splashpage(connection, client, host, url);
	}

	/* request is directed to us */
	/* check if client wants to be authenticated */
	if (check_authdir_match(url, config->authdir)) {

		/* Only the first request will redirected to config->redirectURL.
		 * TODO: Deprecate redirectURL

			redirectURL is now redundant as most CPD implementations immediately close the "splash" page
			as soon as NDS authenticates, thus redirectURL will not be shown.

			This functionality, ie displaying a particular web page as a final "Landing Page"
			can be achieved reliably using FAS, with NDS calling the previous "redirectURL" as the FAS page.

		 * When the client reloads a page when it's authenticated, it should be redirected
		 * to their origin url
		 */
		debug(LOG_DEBUG, "authdir url detected: %s", url);

		if (config->redirectURL) {
			redirect_url = config->redirectURL;
		} else {
			redirect_url = get_redirect_url(connection);
		}

		if (!try_to_authenticate(connection, client, host, url)) {
			/* user used an invalid token, redirect to splashpage but hold query "redir" intact */
			uh_urlencode(originurl, sizeof(originurl), redirect_url, strlen(redirect_url));
			querystr=construct_querystring(client, originurl, querystr);
			return encode_and_redirect_to_splashpage(connection, client, originurl, querystr);
		}

		return authenticate_client(connection, redirect_url, client);
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
static int encode_and_redirect_to_splashpage(struct MHD_Connection *connection, t_client *client, const char *originurl, const char *querystr)
{
	char msg[QUERYMAXLEN] = {0};
	char *splashpageurl = NULL;
	char *phpcmd = NULL;
	s_config *config;
	int ret;

	config = config_get_config();

	if (config->fas_port) {
		// Generate secure query string or authaction url
		// Note: config->fas_path contains a leading / as it is the path from the FAS web root.
		if (config->fas_secure_enabled == 0) {
			safe_asprintf(&splashpageurl, "%s?authaction=http://%s/%s/%s&redir=%s",
				config->fas_url, config->gw_address, config->authdir, querystr, originurl);
		} else if (config->fas_secure_enabled == 1) {
				safe_asprintf(&splashpageurl, "%s%s&redir=%s",
					config->fas_url, querystr, originurl);
		} else if (config->fas_secure_enabled == 2) {
			safe_asprintf(&phpcmd,
				"echo '<?php \n"
				"$key=\"%s\";\n"
				"$string=\"%s\";\n"
				"$cipher=\"aes-256-cbc\";\n"

				"if (in_array($cipher, openssl_get_cipher_methods())) {\n"
					"$secret_iv = base64_encode(openssl_random_pseudo_bytes(\"8\"));\n"
					"$iv = substr(openssl_digest($secret_iv, \"sha256\"), 0, 16 );\n"
					"$string = base64_encode( openssl_encrypt( $string, $cipher, $key, 0, $iv ) );\n"
					"echo \"?fas=\".$string.\"&iv=\".$iv;\n"
				"}\n"
				" ?>' "
				" | %s\n",
				config->fas_key, querystr, config->fas_ssl);

			debug(LOG_DEBUG, "phpcmd: %s", phpcmd);

			if (execute_ret_url_encoded(msg, sizeof(msg) - 1, phpcmd) == 0) {
				safe_asprintf(&splashpageurl, "%s%s",
					config->fas_url, msg);
				debug(LOG_DEBUG, "Encrypted query string=%s\n", msg);
			} else {
				safe_asprintf(&splashpageurl, "%s?redir=%s",
					config->fas_url, originurl);
				debug(LOG_ERR, "Error encrypting query string. %s", msg);
			}
			free(phpcmd);
		} else {
			safe_asprintf(&splashpageurl, "%s%s&redir=%s",
				config->fas_url, querystr, originurl);
		}
	} else {
		safe_asprintf(&splashpageurl, "http://%s/%s?redir=%s",
			config->gw_address, config->splashpage, originurl);
	}

	debug(LOG_INFO, "splashpageurl: %s", splashpageurl);

	ret = send_redirect_temp(connection, client, splashpageurl);
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
	char *originurl_raw = NULL;
	char originurl[QUERYMAXLEN] = {0};
	char query_str[QUERYMAXLEN] = {0};
	char *query = query_str;
	int ret = 0;
	const char *separator = "&";
	char *querystr = query_str;

	get_query(connection, &query, separator);
	if (!query) {
		debug(LOG_DEBUG, "Unable to get query string - error 503");
		/* no mem */
		return send_error(connection, 503);
	}

	debug(LOG_DEBUG, "Query string is [ %s ]", query);
	safe_asprintf(&originurl_raw, "http://%s%s%s", host, url, query);
	uh_urlencode(originurl, sizeof(originurl), originurl_raw, strlen(originurl_raw));

	debug(LOG_DEBUG, "originurl: %s", originurl);

	querystr=construct_querystring(client, originurl, querystr);
	ret = encode_and_redirect_to_splashpage(connection, client, originurl, querystr);
	free(originurl_raw);
	return ret;
}

/////
/**
 * @brief construct_querystring
 * @return the querystring
 */
static char *construct_querystring(t_client *client, char *originurl, char *querystr ) {

	char hash[128] = {0};
	char clientif[64] = {0};

	s_config *config = config_get_config();

	if (config->fas_secure_enabled == 0) {
		snprintf(querystr, QUERYMAXLEN, "?clientip=%s&gatewayname=%s&tok=%s", client->ip, config->gw_name, client->token);

	} else if (config->fas_secure_enabled == 1) {

			if (config->fas_hid) {
				hash_str(hash, sizeof(hash), client->token);
				debug(LOG_INFO, "hid=%s", hash);
				snprintf(querystr, QUERYMAXLEN, "?clientip=%s&gatewayname=%s&hid=%s&gatewayaddress=%s",
					client->ip, config->gw_name, hash, config->gw_address);
			} else {
				snprintf(querystr, QUERYMAXLEN, "?clientip=%s&gatewayname=%s", client->ip, config->gw_name);
			}

	} else if (config->fas_secure_enabled == 2) {
		get_client_interface(clientif, sizeof(clientif), client->mac);
		snprintf(querystr, QUERYMAXLEN,
			"clientip=%s%sclientmac=%s%sgatewayname=%s%stok=%s%sgatewayaddress=%s%sauthdir=%s%soriginurl=%s%sclientif=%s",
			client->ip, QUERYSEPARATOR,
			client->mac, QUERYSEPARATOR,
			config->gw_name, QUERYSEPARATOR,
			client->token, QUERYSEPARATOR,
			config->gw_address, QUERYSEPARATOR,
			config->authdir, QUERYSEPARATOR,
			originurl, QUERYSEPARATOR,
			clientif);

	} else {
		snprintf(querystr, QUERYMAXLEN, "?clientip=%s&gatewayname=%s", client->ip, config->gw_name);
	}

	return querystr;
}

/////

/**
 *	Add client making a request to client list.
 *	Return pointer to the client list entry for this client.
 *
 *	N.B.: This does not authenticate the client; it only makes
 *	their information available on the client list.
 */
static t_client *
add_client(const char *mac, const char *ip)
{
	t_client *client;

	LOCK_CLIENT_LIST();
	client = client_list_add_client(mac, ip);
	UNLOCK_CLIENT_LIST();

	return client;
}

int send_redirect_temp(struct MHD_Connection *connection, t_client *client, const char *url)
{
	struct MHD_Response *response;
	int ret;
	char *redirect = NULL;

	const char *redirect_body = "<html><head></head><body><a href='%s'>Click here to continue to<br>%s</a></body></html>";

	safe_asprintf(&redirect, redirect_body, url, url);

	debug(LOG_DEBUG, "send_redirect_temp: MHD_create_response_from_buffer");

	response = MHD_create_response_from_buffer(strlen(redirect), redirect, MHD_RESPMEM_MUST_FREE);

	if (!response) {
		return send_error(connection, 503);
	}

	// MHD_set_response_options(response, MHD_RF_HTTP_VERSION_1_0_ONLY, MHD_RO_END);
	ret = MHD_add_response_header(response, "Location", url);

	if (ret == MHD_NO) {
		debug(LOG_ERR, "send_redirect_temp: Error adding Location header to redirection page");
	}

	ret = MHD_add_response_header(response, "Connection", "close");

	if (ret == MHD_NO) {
		debug(LOG_ERR, "send_redirect_temp: Error adding Connection header to redirection page");
	}

	debug(LOG_INFO, "send_redirect_temp: Queueing response for %s, %s", client->ip, client->mac);

	ret = MHD_queue_response(connection, MHD_HTTP_TEMPORARY_REDIRECT, response);

	if (ret == MHD_NO) {
		debug(LOG_ERR, "send_redirect_temp: Error queueing response for %s, %s", client->ip, client->mac);
	} else {
		debug(LOG_DEBUG, "send_redirect_temp: Response is Queued");
	}

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
	return MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "redir");
}

/* save the query or empty string into **query.*/
static int get_query(struct MHD_Connection *connection, char **query, const char *separator)
{
	int element_counter;
	char **elements;
	char query_str[QUERYMAXLEN] = {0};
	struct collect_query collect_query;
	int i;
	int j;
	int length = 0;

	debug(LOG_DEBUG, " Separator is [%s].", separator);

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

	// Collect the arguments of the query string from MHD
	MHD_get_connection_values(connection, MHD_GET_ARGUMENT_KIND, collect_query_string, &collect_query);

	for (i = 0; i < element_counter; i++) {
		if (!elements[i])
			continue;
		length += strlen(elements[i]);

		if (i > 0) /* q=foo&o=bar the '&' need also some space */
			length++;
	}

	/* don't miss the zero terminator */
	if (*query == NULL) {
		for (i = 0; i < element_counter; i++) {
			free(elements[i]);
		}
		free(elements);
		return 0;
	}

	for (i = 0, j = 0; i < element_counter; i++) {
		if (!elements[i]) {
			continue;
		}
		strncpy(*query + j, elements[i], length - j);
		if (i == 0) {
			// query_str is empty when i = 0 so safe to copy a single char into it
			strcpy(query_str, "?");
		} else {
			if (QUERYMAXLEN - strlen(query_str) > length - j + 1) {
				strncat(query_str, separator, QUERYMAXLEN - strlen(query_str));
			}
		}

		// note: query string will be truncated if too long
		if (QUERYMAXLEN - strlen(query_str) > length - j) {
			strncat(query_str, *query, QUERYMAXLEN - strlen(query_str));
		} else {
			debug(LOG_WARNING, " Query string exceeds the maximum of %d bytes so has been truncated.", QUERYMAXLEN);
		}

		free(elements[i]);
	}

	strncpy(*query, query_str, QUERYMAXLEN);
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
	// cannot automate since cannot translate automagically between error number and MHD's status codes
	// -- and cannot rely on MHD_HTTP_ values to provide an upper bound for an array
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
 * @brief get_user_agent_callback save User-Agent into cls which is a char**
 * @param cls - a char ** pointer to our target buffer. This buffer will be alloc in this function.
 * @param kind - see doc of	MHD_KeyValueIterator's
 * @param key
 * @param value
 * @return MHD_YES or MHD_NO. MHD_NO means we found our item and this callback will not called again.
 */
static int get_user_agent_callback(void *cls, enum MHD_ValueKind kind, const char *key, const char *value)
{
	const char **user_agent = (const char **)cls;
	if (MHD_HEADER_KIND != kind) {
		*user_agent = NULL;
		return MHD_NO;
	}

	if (!strcmp("User-Agent", key)) {
		*user_agent = value;
		return MHD_NO;
	}

	return MHD_YES;
}

/**
 * Replace variables in src and copy result to dst
 */
static void replace_variables(
	struct MHD_Connection *connection, t_client *client,
	char *dst, size_t dst_len, const char *src, size_t src_len)
{
	s_config *config = config_get_config();

	char nclients[12];
	char maxclients[12];
	char clientupload[20];
	char clientdownload[20];
	char uptime[64];

	const char *redirect_url = NULL;
	char *denyaction = NULL;
	char *authaction = NULL;
	char *authtarget = NULL;

	sprintf(clientupload, "%llu", client->counters.outgoing);
	sprintf(clientdownload, "%llu", client->counters.incoming);

	get_uptime_string(uptime);
	redirect_url = get_redirect_url(connection);

	sprintf(nclients, "%d", get_client_list_length());
	sprintf(maxclients, "%d", config->maxclients);
	safe_asprintf(&denyaction, "http://%s/%s/", config->gw_address, config->denydir);
	safe_asprintf(&authaction, "http://%s/%s/", config->gw_address, config->authdir);
	safe_asprintf(&authtarget, "http://%s/%s/?tok=%s&amp;redir=%s",
		config->gw_address, config->authdir, client->token, redirect_url);

	struct template vars[] = {
		{"authaction", authaction},
		{"denyaction", denyaction},
		{"authtarget", authtarget},
		{"clientip", client->ip},
		{"clientmac", client->mac},
		{"clientupload", clientupload},
		{"clientdownload", clientdownload},
		{"gatewaymac", config->gw_mac},
		{"gatewayname", config->gw_name},
		{"maxclients", maxclients},
		{"nclients", nclients},
		{"redir", redirect_url},
		{"tok", client->token},
		{"token", client->token},
		{"uptime", uptime},
		{"version", VERSION},
		{NULL, NULL}
	};

	tmpl_parse(vars, dst, dst_len, src, src_len);

	free(denyaction);
	free(authaction);
	free(authtarget);
}

static int show_templated_page(struct MHD_Connection *connection, t_client *client, const char *page)
{
	struct MHD_Response *response;
	s_config *config = config_get_config();
	int ret = -1;
	char filename[PATH_MAX];
	const char *mimetype;
	int size = 0, bytes = 0;
	int page_fd;
	char *page_result;
	char *page_tmpl;

	snprintf(filename, PATH_MAX, "%s/%s", config->webroot, page);

	page_fd = open(filename, O_RDONLY);
	if (page_fd < 0) {
		return send_error(connection, 404);
	}

	mimetype = lookup_mimetype(filename);

	/* input size */
	size = lseek(page_fd, 0, SEEK_END);
	lseek(page_fd, 0, SEEK_SET);

	/* we TMPLVAR_SIZE for template variables */
	page_tmpl = calloc(size, 1);
	if (page_tmpl == NULL) {
		close(page_fd);
		return send_error(connection, 503);
	}

	page_result = calloc(size + TMPLVAR_SIZE, 1);
	if (page_result == NULL) {
		close(page_fd);
		free(page_tmpl);
		return send_error(connection, 503);
	}

	while (bytes < size) {
		ret = read(page_fd, page_tmpl + bytes, size - bytes);
		if (ret < 0) {
			free(page_result);
			free(page_tmpl);
			close(page_fd);
			return send_error(connection, 503);
		}
		bytes += ret;
	}

	replace_variables(connection, client, page_result, size + TMPLVAR_SIZE, page_tmpl, size);

	response = MHD_create_response_from_buffer(strlen(page_result), (void *)page_result, MHD_RESPMEM_MUST_FREE);
	if (!response) {
		close(page_fd);
		return send_error(connection, 503);
	}

	MHD_add_response_header(response, "Content-Type", mimetype);
	ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
	MHD_destroy_response(response);

	free(page_tmpl);
	close(page_fd);

	return ret;
}

/**
 * @brief show_splashpage is called when the client clicked on Ok as well when the client doesn't know us yet.
 * @param connection
 * @param client
 * @return
 */
static int show_splashpage(struct MHD_Connection *connection, t_client *client)
{
	s_config *config = config_get_config();
	return show_templated_page(connection, client, config->splashpage);
}

/**
 * @brief show_statuspage is called when the client is already authenticated but still accesses the captive portal
 * @param connection
 * @param client
 * @return
 */
static int show_statuspage(struct MHD_Connection *connection, t_client *client)
{
	s_config *config = config_get_config();
	return show_templated_page(connection, client, config->statuspage);
}

/**
 * @brief return an extension like `csv` if file = '/bar/foobar.csv'.
 * @param filename
 * @return a pointer within file is returned. NULL can be returned as well as
 */
const char *get_extension(const char *filename)
{
	int pos = strlen(filename);
	while (pos > 0) {
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

	for (i = 0; i< ARRAY_SIZE(uh_mime_types); i++) {
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

size_t unescape(void * cls, struct MHD_Connection *c, char *src)
{
	char unescapecmd[QUERYMAXLEN] = {0};
	char msg[QUERYMAXLEN] = {0};

	debug(LOG_INFO, "Escaped string=%s\n", src);
	snprintf(unescapecmd, QUERYMAXLEN, "/usr/lib/nodogsplash/unescape.sh -url \"%s\"", src);
	debug(LOG_DEBUG, "unescapecmd=%s\n", unescapecmd);

	if (execute_ret_url_encoded(msg, sizeof(msg) - 1, unescapecmd) == 0) {
		debug(LOG_INFO, "Unescaped string=%s\n", msg);
		strcpy(src, msg);
	}

	return strlen(src);
}
