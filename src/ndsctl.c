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

/** @file ndsctl.c
    @brief Monitoring and control of nodogsplash, client part
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
#include <errno.h>

#include "ndsctl.h"


struct argument {
	const char *cmd;
	const char *ifyes;
	const char *ifno;
};

/** @internal
 * @brief Print usage
 *
 * Prints usage, called when ndsctl is run with -h or with an unknown option
 */
static void
usage(void)
{
	printf(
		"Usage: ndsctl [options] command [arguments]\n"
		"\n"
		"options:\n"
		"  -s <path>           Path to the socket\n"
		"  -h                  Print usage\n"
		"\n"
		"commands:\n"
		"  status              View the status of nodogsplash\n"
		"  clients             Display machine-readable client list\n"
		"  json [mac|ip|token] Display client list in json format\n"
		"  stop                Stop the running nodogsplash\n"
		"  auth mac|ip|token   Authenticate user with specified mac, ip or token\n"
		"  deauth mac|ip|token Deauthenticate user with specified mac, ip or token\n"
		"  block mac           Block the given MAC address\n"
		"  unblock mac         Unblock the given MAC address\n"
		"  allow mac           Allow the given MAC address\n"
		"  unallow mac         Unallow the given MAC address\n"
		"  trust mac           Trust the given MAC address\n"
		"  untrust mac         Untrust the given MAC address\n"
		"  debuglevel n        Set debug level to n\n"
		"\n"
	);
}

static struct argument arguments[] = {
	{"clients", NULL, NULL},
	{"json", NULL, NULL},
	{"status", NULL, NULL},
	{"stop", NULL, NULL},
	{"debuglevel", "Debug level set to %s.\n", "Failed to set debug level to %s.\n"},
	{"deauth", "Client %s deauthenticated.\n", "Client %s not found.\n"},
	{"auth", "Client %s authenticated.\n", "Failed to authenticate client %s.\n"},
	{"block", "MAC %s blocked.\n", "Failed to block MAC %s.\n"},
	{"unblock", "MAC %s unblocked.\n", "Failed to unblock MAC %s.\n"},
	{"allow", "MAC %s allowed.\n", "Failed to allow MAC %s.\n"},
	{"unallow", "MAC %s unallowed.\n", "Failed to unallow MAC %s.\n"},
	{"trust", "MAC %s trusted.\n", "Failed to trust MAC %s.\n"},
	{"untrust", "MAC %s untrusted.\n", "Failed to untrust MAC %s.\n"},
	{NULL, NULL, NULL}
};

static const struct argument*
find_argument(const char *cmd) {
	int i;

	for (i = 0; arguments[i].cmd; i++) {
		if (strcmp(arguments[i].cmd, cmd) == 0) {
			return &arguments[i];
		}
	}

	return NULL;
}

static int
connect_to_server(const char sock_name[])
{
	int sock;
	struct sockaddr_un sa_un;

	/* Connect to socket */
	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	memset(&sa_un, 0, sizeof(sa_un));
	sa_un.sun_family = AF_UNIX;
	strncpy(sa_un.sun_path, sock_name, (sizeof(sa_un.sun_path) - 1));

	if (connect(sock, (struct sockaddr *)&sa_un, strlen(sa_un.sun_path) + sizeof(sa_un.sun_family))) {
		fprintf(stderr, "ndsctl: nodogsplash probably not started (Error: %s)\n", strerror(errno));
		return -1;
	}

	return sock;
}

static int
send_request(int sock, const char request[])
{
	ssize_t len, written;

	len = 0;
	while (len != strlen(request)) {
		written = write(sock, (request + len), strlen(request) - len);
		if (written == -1) {
			fprintf(stderr, "Write to nodogsplash failed: %s\n", strerror(errno));
			exit(1);
		}
		len += written;
	}

	return((int)len);
}

/* Perform a ndsctl action, with server response Yes or No.
 * Action given by cmd, followed by config.param.
 * Responses printed to stdout, as formatted by ifyes or ifno.
 * config.param interpolated in format with %s directive if desired.
 */
static int
ndsctl_do(const char *socket, const struct argument *arg, const char *param)
{
	int sock;
	char buffer[4096];
	char request[128];
	int len, rlen;
	int ret;

	sock = connect_to_server(socket);
	if (sock < 0) {
		return 3;
	}

	if (param) {
		snprintf(request, sizeof(request), "%s %s\r\n\r\n", arg->cmd, param);
	} else {
		snprintf(request, sizeof(request), "%s\r\n\r\n", arg->cmd);
	}

	len = send_request(sock, request);

	if (arg->ifyes && arg->ifno) {
		len = 0;
		memset(buffer, 0, sizeof(buffer));
		while ((len < sizeof(buffer)) && ((rlen = read(sock, (buffer + len),
			(sizeof(buffer) - len))) > 0)) {
			len += rlen;
		}

		if (rlen < 0) {
			fprintf(stderr, "ndsctl: Error reading socket: %s\n", strerror(errno));
			ret = 3;
		} else if (strcmp(buffer, "Yes") == 0) {
			printf(arg->ifyes, param);
			ret = 0;
		} else if (strcmp(buffer, "No") == 0) {
			printf(arg->ifno, param);
			ret = 1;
		} else {
			fprintf(stderr, "ndsctl: Error: nodogsplash sent an abnormal reply.\n");
			ret = 2;
		}
	} else {
		while ((len = read(sock, buffer, sizeof(buffer) - 1)) > 0) {
			buffer[len] = '\0';
			printf("%s", buffer);
		}
		ret = 0;
	}

	shutdown(sock, 2);
	close(sock);

	return ret;
}

int
main(int argc, char **argv)
{
	const struct argument* arg;
	const char *socket;
	int i = 1;

	socket = strdup(DEFAULT_SOCK);

	if (argc <= i) {
		usage();
		return 0;
	}

	if (strcmp(argv[1], "-h") == 0) {
		usage();
		return 1;
	}

	if (strcmp(argv[1], "-s") == 0) {
		if (argc >= 2) {
			socket = strdup(argv[2]);
			i = 3;
		} else {
			usage();
			return 1;
		}
	}

	// Too many arguments
	if (argc > (i+2)) {
		usage();
		return 1;
	}

	arg = find_argument(argv[i]);

	if (arg == NULL) {
		fprintf(stderr, "Unknown command: %s\n", argv[i]);
		return 1;
	}

	// Send command, argv[i+1] may be NULL.
	return ndsctl_do(socket, arg, argv[i+1]);
}
