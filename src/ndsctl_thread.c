/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free Software Foundation; either version 2 of   *
 * the License, or (at your option) any later version.              *
 *                                                                  *
 * This program is distributed in the hope that it will be useful,  *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of   *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the    *
 * GNU General Public License for more details.                     *
 *                                                                  *
 * You should have received a copy of the GNU General Public License*
 * along with this program; if not, contact:                        *
 *                                                                  *
 * Free Software Foundation           Voice:  +1-617-542-5942       *
 * 59 Temple Place - Suite 330        Fax:    +1-617-542-2652       *
 * Boston, MA  02111-1307,  USA       gnu@gnu.org                   *
 *                                                                  *
\********************************************************************/

/** @file ndsctl_thread.c
    @brief Monitoring and control of nodogsplash, server part
    @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@acv.ca>
    trivially modified for nodogsplash
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>
#include <sys/epoll.h>
#include <fcntl.h>

#include "common.h"
#include "util.h"
#include "conf.h"
#include "debug.h"
#include "auth.h"
#include "safe.h"
#include "client_list.h"
#include "fw_iptables.h"
#include "firewall.h"
#include "gateway.h"

#include "ndsctl_thread.h"

#define MAX_EVENT_SIZE 30

/* Defined in clientlist.c */
extern pthread_mutex_t client_list_mutex;
extern pthread_mutex_t config_mutex;

static void ndsctl_handler(int fd);
static void ndsctl_stop();
static void ndsctl_block(int, char *);
static void ndsctl_unblock(int, char *);
static void ndsctl_allow(int, char *);
static void ndsctl_unallow(int, char *);
static void ndsctl_trust(int, char *);
static void ndsctl_untrust(int, char *);
static void ndsctl_auth(int, char *);
static void ndsctl_deauth(int, char *);
static void ndsctl_loglevel(int, char *);
static void ndsctl_password(int, char *);
static void ndsctl_username(int, char *);

static int socket_set_non_blocking(int sockfd);

/** Launches a thread that monitors the control socket for request
@param arg Must contain a pointer to a string containing the Unix domain socket to open
@todo This thread loops infinitely, need a watchdog to verify that it is still running?
*/
void*
thread_ndsctl(void *arg)
{
	int sock, fd, epoll_fd;
	const char *sock_name;
	struct sockaddr_un sa_un;
	socklen_t len;
	struct epoll_event ev;
	struct epoll_event *events;
	int current_fd_count;
	int number_of_count;
	int i;

	debug(LOG_DEBUG, "Starting ndsctl.");

	memset(&sa_un, 0, sizeof(sa_un));
	sock_name = (char *)arg;
	debug(LOG_DEBUG, "Socket name: %s", sock_name);

	if (strlen(sock_name) > (sizeof(sa_un.sun_path) - 1)) {
		/* TODO: Die handler with logging.... */
		debug(LOG_ERR, "NDSCTL socket name too long");
		exit(1);
	}

	debug(LOG_DEBUG, "Creating socket");
	sock = socket(PF_UNIX, SOCK_STREAM, 0);

	debug(LOG_DEBUG, "Got server socket %d", sock);

	/* If it exists, delete... Not the cleanest way to deal. */
	unlink(sock_name);

	debug(LOG_DEBUG, "Filling sockaddr_un");
	strcpy(sa_un.sun_path, sock_name); /* XXX No size check because we check a few lines before. */
	sa_un.sun_family = AF_UNIX;

	debug(LOG_DEBUG, "Binding socket (%s) (%d)", sa_un.sun_path, strlen(sock_name));

	/* Which to use, AF_UNIX, PF_UNIX, AF_LOCAL, PF_LOCAL? */
	if (bind(sock, (struct sockaddr *)&sa_un, strlen(sock_name) + sizeof(sa_un.sun_family))) {
		debug(LOG_ERR, "Could not bind control socket: %s", strerror(errno));
		pthread_exit(NULL);
	}

	if (listen(sock, 5)) {
		debug(LOG_ERR, "Could not listen on control socket: %s", strerror(errno));
		pthread_exit(NULL);
	}

	memset(&ev, 0, sizeof(struct epoll_event));
	epoll_fd = epoll_create(MAX_EVENT_SIZE);

	ev.events = EPOLLIN|EPOLLET;
	ev.data.fd = sock;

	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock, &ev) < 0) {
		debug(LOG_ERR, "Could not insert socket fd to epoll set: %s", strerror(errno));
		pthread_exit(NULL);
	}

	events = (struct epoll_event*)calloc(MAX_EVENT_SIZE, sizeof(struct epoll_event));

	if (!events) {
		close(sock);
		pthread_exit(NULL);
	}

	current_fd_count = 1;

	while (1) {
		memset(&sa_un, 0, sizeof(sa_un));
		len = (socklen_t) sizeof(sa_un);

		number_of_count = epoll_wait(epoll_fd, events, current_fd_count, -1);

		if (number_of_count == -1) {
			debug(LOG_ERR, "Failed to wait epoll events: %s", strerror(errno));
			free(events);
			pthread_exit(NULL);
		}

		for (i = 0; i < number_of_count; i++) {

			if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP) ||
				(!(events[i].events & EPOLLIN))) {
				debug(LOG_ERR, "Socket is not ready for communication : %s", strerror(errno));

				if (events[i].data.fd > 0) {
					shutdown(events[i].data.fd, 2);
					close(events[i].data.fd);
					events[i].data.fd = 0;
				}
				continue;
			}

			if (events[i].data.fd == sock) {
				if ((fd = accept(events[i].data.fd, (struct sockaddr *)&sa_un, &len)) == -1) {
					debug(LOG_ERR, "Accept failed on control socket: %s", strerror(errno));
					free(events);
					pthread_exit(NULL);
				} else {
					socket_set_non_blocking(fd);
					ev.events = EPOLLIN|EPOLLET;
					ev.data.fd = fd;

					if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
						debug(LOG_ERR, "Could not insert socket fd to epoll set: %s", strerror(errno));
						free(events);
						pthread_exit(NULL);
					}

					current_fd_count += 1;
				}

			} else {
				ndsctl_handler(fd);
				epoll_ctl(epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, &ev);
				current_fd_count -= 1;

				/* socket was closed on 'ndsctl_handler' */
				if (events[i].data.fd > 0) {
					events[i].data.fd = 0;
				}

			}
		}
	}

	free(events);

	return NULL;
}

static void
ndsctl_handler(int fd)
{
	int done, i;
	char request[MAX_BUF];
	ssize_t read_bytes, len;

	debug(LOG_DEBUG, "Entering thread_ndsctl_handler....");
	debug(LOG_DEBUG, "Read bytes and stuff from %d", fd);

	/* Init variables */
	read_bytes = 0;
	done = 0;
	memset(request, 0, sizeof(request));

	/* Read.... */
	while (!done && read_bytes < (sizeof(request) - 1)) {
		len = read(fd, request + read_bytes, sizeof(request) - read_bytes);

		/* Have we gotten a command yet? */
		for (i = read_bytes; i < (read_bytes + len); i++) {
			if (request[i] == '\r' || request[i] == '\n') {
				request[i] = '\0';
				done = 1;
			}
		}

		/* Increment position */
		read_bytes += len;
	}

	debug(LOG_DEBUG, "ndsctl request received: [%s]", request);

	if (strncmp(request, "status", 6) == 0) {
		ndsctl_status(fd);
	} else if (strncmp(request, "clients", 7) == 0) {
		ndsctl_clients(fd);
	} else if (strncmp(request, "json", 4) == 0) {
		ndsctl_json(fd);
	} else if (strncmp(request, "stop", 4) == 0) {
		ndsctl_stop();
	} else if (strncmp(request, "block", 5) == 0) {
		ndsctl_block(fd, (request + 6));
	} else if (strncmp(request, "unblock", 7) == 0) {
		ndsctl_unblock(fd, (request + 8));
	} else if (strncmp(request, "allow", 5) == 0) {
		ndsctl_allow(fd, (request + 6));
	} else if (strncmp(request, "unallow", 7) == 0) {
		ndsctl_unallow(fd, (request + 8));
	} else if (strncmp(request, "trust", 5) == 0) {
		ndsctl_trust(fd, (request + 6));
	} else if (strncmp(request, "untrust", 7) == 0) {
		ndsctl_untrust(fd, (request + 8));
	} else if (strncmp(request, "auth", 4) == 0) {
		ndsctl_auth(fd, (request + 5));
	} else if (strncmp(request, "deauth", 6) == 0) {
		ndsctl_deauth(fd, (request + 7));
	} else if (strncmp(request, "loglevel", 8) == 0) {
		ndsctl_loglevel(fd, (request + 9));
	} else if (strncmp(request, "password", 8) == 0) {
		ndsctl_password(fd, (request + 9));
	} else if (strncmp(request, "username", 8) == 0) {
		ndsctl_username(fd, (request + 9));
	}

	if (!done) {
		debug(LOG_ERR, "Invalid ndsctl request.");
	}

	debug(LOG_DEBUG, "ndsctl request processed: [%s]", request);
	debug(LOG_DEBUG, "Exiting thread_ndsctl_handler....");

	if (fd > 0) {
		shutdown(fd, 2);
		close(fd);
	}
}

/** A bit of an hack, self kills.... */
static void
ndsctl_stop()
{
	pthread_exit(NULL);
}

static void
ndsctl_auth(int fd, char *arg)
{
	t_client *client;
	char *ip, *mac;
	debug(LOG_DEBUG, "Entering ndsctl_auth...");

	LOCK_CLIENT_LIST();
	/* arg can be IP or MAC address of client */
	debug(LOG_DEBUG, "Argument: %s (@%x)", arg, arg);

	/* We get the client or return... */
	if ((client = client_list_find_by_ip(arg)) != NULL);
	else if ((client = client_list_find_by_mac(arg)) != NULL);
	else if ((client = client_list_find_by_token(arg)) != NULL);
	else {
		debug(LOG_DEBUG, "Client not found.");
		UNLOCK_CLIENT_LIST();
		write(fd, "No", 2);
		return;
	}

	/* We have a client.  Get both ip and mac address and authenticate */
	ip = safe_strdup(client->ip);
	mac = safe_strdup(client->mac);
	UNLOCK_CLIENT_LIST();

	auth_client_action(ip, mac, AUTH_MAKE_AUTHENTICATED);

	free(ip);
	free(mac);
	write(fd, "Yes", 3);

	debug(LOG_DEBUG, "Exiting ndsctl_auth...");
}

static void
ndsctl_deauth(int fd, char *arg)
{
	t_client *client;
	char *ip, *mac;
	debug(LOG_DEBUG, "Entering ndsctl_deauth...");

	LOCK_CLIENT_LIST();
	/* arg can be IP or MAC address of client */
	debug(LOG_DEBUG, "Argument: %s (@%x)", arg, arg);

	/* We get the client or return... */
	if ((client = client_list_find_by_ip(arg)) != NULL);
	else if ((client = client_list_find_by_mac(arg)) != NULL);
	else if ((client = client_list_find_by_token(arg)) != NULL);
	else {
		debug(LOG_DEBUG, "Client not found.");
		UNLOCK_CLIENT_LIST();
		write(fd, "No", 2);
		return;
	}

	/* We have the client.  Get both ip and mac address and deauthenticate */
	ip = safe_strdup(client->ip);
	mac = safe_strdup(client->mac);
	UNLOCK_CLIENT_LIST();

	auth_client_action(ip, mac, AUTH_MAKE_DEAUTHENTICATED);

	free(ip);
	free(mac);
	write(fd, "Yes", 3);

	debug(LOG_DEBUG, "Exiting ndsctl_deauth...");
}

static void
ndsctl_block(int fd, char *arg)
{
	debug(LOG_DEBUG, "Entering ndsctl_block...");

	LOCK_CONFIG();
	debug(LOG_DEBUG, "Argument: [%s]", arg);

	if (!add_to_blocked_mac_list(arg) && !iptables_block_mac(arg)) {
		write(fd, "Yes", 3);
	} else {
		write(fd, "No", 2);
	}

	UNLOCK_CONFIG();

	debug(LOG_DEBUG, "Exiting ndsctl_block.");
}

static void
ndsctl_unblock(int fd, char *arg)
{
	debug(LOG_DEBUG, "Entering ndsctl_unblock...");

	LOCK_CONFIG();
	debug(LOG_DEBUG, "Argument: [%s]", arg);

	if (!remove_from_blocked_mac_list(arg) && !iptables_unblock_mac(arg)) {
		write(fd, "Yes", 3);
	} else {
		write(fd, "No", 2);
	}

	UNLOCK_CONFIG();

	debug(LOG_DEBUG, "Exiting ndsctl_unblock.");
}

static void
ndsctl_allow(int fd, char *arg)
{
	debug(LOG_DEBUG, "Entering ndsctl_allow...");

	LOCK_CONFIG();
	debug(LOG_DEBUG, "Argument: [%s]", arg);

	if (!add_to_allowed_mac_list(arg) && !iptables_allow_mac(arg)) {
		write(fd, "Yes", 3);
	} else {
		write(fd, "No", 2);
	}

	UNLOCK_CONFIG();

	debug(LOG_DEBUG, "Exiting ndsctl_allow.");
}

static void
ndsctl_unallow(int fd, char *arg)
{
	debug(LOG_DEBUG, "Entering ndsctl_unallow...");

	LOCK_CONFIG();
	debug(LOG_DEBUG, "Argument: [%s]", arg);

	if (!remove_from_allowed_mac_list(arg) && !iptables_unallow_mac(arg)) {
		write(fd, "Yes", 3);
	} else {
		write(fd, "No", 2);
	}

	UNLOCK_CONFIG();

	debug(LOG_DEBUG, "Exiting ndsctl_unallow.");
}

static void
ndsctl_trust(int fd, char *arg)
{
	debug(LOG_DEBUG, "Entering ndsctl_trust...");

	LOCK_CONFIG();
	debug(LOG_DEBUG, "Argument: [%s]", arg);

	if (!add_to_trusted_mac_list(arg) && !iptables_trust_mac(arg)) {
		write(fd, "Yes", 3);
	} else {
		write(fd, "No", 2);
	}

	UNLOCK_CONFIG();

	debug(LOG_DEBUG, "Exiting ndsctl_trust.");
}

static void
ndsctl_untrust(int fd, char *arg)
{
	debug(LOG_DEBUG, "Entering ndsctl_untrust...");

	LOCK_CONFIG();
	debug(LOG_DEBUG, "Argument: [%s]", arg);

	if (!remove_from_trusted_mac_list(arg) && !iptables_untrust_mac(arg)) {
		write(fd, "Yes", 3);
	} else {
		write(fd, "No", 2);
	}

	UNLOCK_CONFIG();

	debug(LOG_DEBUG, "Exiting ndsctl_untrust.");
}

static void
ndsctl_loglevel(int fd, char *arg)
{
	int level = atoi(arg);

	debug(LOG_DEBUG, "Entering ndsctl_loglevel...");

	LOCK_CONFIG();
	debug(LOG_DEBUG, "Argument: [%s]", arg);


	if (!set_log_level(level)) {
		write(fd, "Yes", 3);
		debug(LOG_NOTICE, "Set debug loglevel to %d.", level);
	} else {
		write(fd, "No", 2);
	}

	UNLOCK_CONFIG();

	debug(LOG_DEBUG, "Exiting ndsctl_loglevel.");
}

static void
ndsctl_password(int fd, char *arg)
{
	debug(LOG_DEBUG, "Entering ndsctl_password...");

	LOCK_CONFIG();
	debug(LOG_DEBUG, "Argument: [%s]", arg);


	if (!set_password(arg)) {
		write(fd, "Yes", 3);
		debug(LOG_NOTICE, "Set password to %s.", arg);
	} else {
		write(fd, "No", 2);
	}

	UNLOCK_CONFIG();

	debug(LOG_DEBUG, "Exiting ndsctl_password.");
}

static void
ndsctl_username(int fd, char *arg)
{
	debug(LOG_DEBUG, "Entering ndsctl_username...");

	LOCK_CONFIG();
	debug(LOG_DEBUG, "Argument: [%s]", arg);


	if (!set_username(arg)) {
		write(fd, "Yes", 3);
		debug(LOG_NOTICE, "Set username to %s.", arg);
	} else {
		write(fd, "No", 2);
	}

	UNLOCK_CONFIG();

	debug(LOG_DEBUG, "Exiting ndsctl_username.");
}

static int
socket_set_non_blocking(int sockfd)
{
	int rc;

	rc = fcntl(sockfd, F_GETFL, 0);

	if (rc) {
		rc |= O_NONBLOCK;
		rc = fcntl(sockfd, F_SETFL, rc);
	}

	return rc;
}
