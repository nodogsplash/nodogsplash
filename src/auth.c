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

/** @file auth.c
    @brief Authentication handling thread
    @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@miniguru.ca>
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <syslog.h>

#include "safe.h"
#include "conf.h"
#include "debug.h"
#include "auth.h"
#include "fw_iptables.h"
#include "client_list.h"
#include "util.h"


/* Defined in clientlist.c */
extern pthread_mutex_t client_list_mutex;

/* Count number of authentications */
unsigned int authenticated_since_start = 0;


/** See if they are still active,
 *  refresh their traffic counters,
 *  remove and deny them if timed out
 */
static void
fw_refresh_client_list(void)
{
	t_client *cp1, *cp2;
	s_config *config = config_get_config();
	const int preauth_idle_timeout = config->preauth_idle_timeout;
	const int authed_idle_timeout = config->authed_idle_timeout;
	const time_t now = time(NULL);

	/* Update all the counters */
	if (-1 == iptables_fw_counters_update()) {
		debug(LOG_ERR, "Could not get counters from firewall!");
		return;
	}

	LOCK_CLIENT_LIST();

	for (cp1 = cp2 = client_get_first_client(); NULL != cp1; cp1 = cp2) {
		cp2 = cp1->next;

		if (!(cp1 = client_list_find(cp1->ip, cp1->mac))) {
			debug(LOG_ERR, "Client was freed while being re-validated!");
			continue;
		}

		int conn_state = cp1->fw_connection_state;
		int last_updated = cp1->counters.last_updated;

		if (cp1->session_end > 0 && cp1->session_end <= now) {
			/* Session ended (only > 0 for FW_MARK_AUTHENTICATED by binauth) */
			debug(LOG_NOTICE, "Force out user: %s %s, connected: %ds, in: %llukB, out: %llukB",
				cp1->ip, cp1->mac, now - cp1->session_end,
				cp1->counters.incoming / 1000, cp1->counters.outgoing / 1000);

			/* All client here should be authenticated anyway */
			if (conn_state == FW_MARK_AUTHENTICATED) {
				if (config->bin_auth) {
					// Client will be deauthenticated...
					execute("%s session_end %s %llu %llu %llu %llu",
						config->bin_auth,
						cp1->mac,
						cp1->counters.incoming,
						cp1->counters.outgoing,
						cp1->session_start,
						cp1->session_end
					);
				}
				iptables_fw_deauthenticate(cp1);
			}
			client_list_delete(cp1);
		} else if (preauth_idle_timeout > 0
				&& conn_state == FW_MARK_PREAUTHENTICATED
				&& (last_updated + preauth_idle_timeout) <= now) {
			/* Timeout inactive user */
			debug(LOG_NOTICE, "Timeout preauthenticated idle user: %s %s, inactive: %ds, in: %llukB, out: %llukB",
				cp1->ip, cp1->mac, now - last_updated,
				cp1->counters.incoming / 1000, cp1->counters.outgoing / 1000);

			client_list_delete(cp1);
		} else if (authed_idle_timeout > 0
				&& conn_state == FW_MARK_AUTHENTICATED
				&& (last_updated + authed_idle_timeout) <= now) {
			/* Timeout inactive user */
			debug(LOG_NOTICE, "Timeout authenticated idle user: %s %s, inactive: %ds, in: %llukB, out: %llukB",
				cp1->ip, cp1->mac, now - last_updated,
				cp1->counters.incoming / 1000, cp1->counters.outgoing / 1000);

			/* All clients here should be authenticated for sure */
			if (conn_state == FW_MARK_AUTHENTICATED) {
				if (config->bin_auth) {
					// Client will be deauthenticated...
					execute("%s idle_timeout %s %llu %llu %llu %llu",
						config->bin_auth,
						cp1->mac,
						cp1->counters.incoming,
						cp1->counters.outgoing,
						cp1->session_start,
						cp1->session_end
					);
				}
				iptables_fw_deauthenticate(cp1);
			}
			client_list_delete(cp1);
		}
	}
	UNLOCK_CLIENT_LIST();
}

/** Launched in its own thread.
 *  This just wakes up every config.checkinterval seconds, and calls fw_refresh_client_list()
@todo This thread loops infinitely, need a watchdog to verify that it is still running?
*/
void *
thread_client_timeout_check(void *arg)
{
	pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
	pthread_mutex_t cond_mutex = PTHREAD_MUTEX_INITIALIZER;
	struct timespec timeout;

	while (1) {
		debug(LOG_DEBUG, "Running fw_refresh_client_list()");

		fw_refresh_client_list();

		/* Sleep for config.checkinterval seconds... */
		timeout.tv_sec = time(NULL) + config_get_config()->checkinterval;
		timeout.tv_nsec = 0;

		/* Mutex must be locked for pthread_cond_timedwait... */
		pthread_mutex_lock(&cond_mutex);

		/* Thread safe "sleep" */
		pthread_cond_timedwait(&cond, &cond_mutex, &timeout);

		/* No longer needs to be locked */
		pthread_mutex_unlock(&cond_mutex);
	}

	return NULL;
}

/** Take action on a client.
 * Alter the firewall rules and client list accordingly.
*/
void
auth_client_deauthenticate(const char ip[], const char mac[])
{
	t_client *client;

printf("auth_client_deauthenticate\n");

	LOCK_CLIENT_LIST();

	client = client_list_find(ip, mac);

	/* Client should already have hit the server and be on the client list */
	if (client == NULL) {
		debug(LOG_ERR, "Client %s %s to deauthenticate is not on client list", ip, mac);
		goto end;
	}

	if (client->fw_connection_state != FW_MARK_AUTHENTICATED) {
		debug(LOG_INFO, "Nothing to do, %s %s not authenticated", client->ip, client->mac);
		goto end;
	}
	iptables_fw_deauthenticate(client);

	client_list_delete(client);

end:
	UNLOCK_CLIENT_LIST();
}

void
auth_client_authenticate(const char ip[], const char mac[])
{
	t_client *client;

printf("auth_client_authenticate\n");

	LOCK_CLIENT_LIST();

	client = client_list_find(ip, mac);

	/* Client should already have hit the server and be on the client list */
	if (client == NULL) {
		debug(LOG_ERR, "Client %s %s to authenticate is not on client list", ip, mac);
		goto end;
	}

	if (client->fw_connection_state == FW_MARK_AUTHENTICATED) {
		debug(LOG_INFO, "Nothing to do, %s %s already authenticated", client->ip, client->mac);
		goto end;
	}

	client->fw_connection_state = FW_MARK_AUTHENTICATED;

	iptables_fw_authenticate(client);
	authenticated_since_start++;

end:
	UNLOCK_CLIENT_LIST();
}

void
auth_client_deauth_all()
{
	t_client *cp1, *cp2;
	s_config *config;
	time_t now;

	LOCK_CLIENT_LIST();

	now = time(NULL);
	config = config_get_config();

	for (cp1 = cp2 = client_get_first_client(); NULL != cp1; cp1 = cp2) {
		cp2 = cp1->next;

		if (!(cp1 = client_list_find(cp1->ip, cp1->mac))) {
			debug(LOG_ERR, "Client was freed while being re-validated!");
			continue;
		}

		if (cp1->fw_connection_state == FW_MARK_AUTHENTICATED) {
			iptables_fw_deauthenticate(cp1);

			if (config->bin_auth) {
				// Client will be deauthenticated...
				execute("%s manual_deauth %s %llu %llu %d",
					config->bin_auth,
					cp1->mac,
					cp1->counters.incoming,
					cp1->counters.outgoing,
					now - cp1->session_start
				);
			}

			client_list_delete(cp1);
		}
	}

	UNLOCK_CLIENT_LIST();
}
