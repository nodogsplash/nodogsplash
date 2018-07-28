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

/** @internal
  @file firewall.c
  @brief Firewall update functions
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
  2006 Benoit Grégoire, Technologies Coeus inc. <bock@step.polymtl.ca>
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <errno.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/types.h>

#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/time.h>

#ifdef __linux__
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netpacket/packet.h>
#endif

#if defined(__NetBSD__)
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#endif

#include "safe.h"
#include "debug.h"
#include "conf.h"
#include "client_list.h"
#include "firewall.h"
#include "fw_iptables.h"
#include "auth.h"
#include "util.h"


extern pthread_mutex_t client_list_mutex;

/** Used to mark packets, and characterize client state.  Unmarked packets are considered 'preauthenticated' */
unsigned int FW_MARK_PREAUTHENTICATED; /**< @brief 0: Actually not used as a packet mark */
unsigned int FW_MARK_AUTHENTICATED;    /**< @brief The client is authenticated */
unsigned int FW_MARK_BLOCKED;          /**< @brief The client is blocked */
unsigned int FW_MARK_TRUSTED;          /**< @brief The client is trusted */
unsigned int FW_MARK_MASK;             /**< @brief Iptables mask: bitwise or of the others */

/**
 * Get an IP's MAC address from the ARP cache.
 * Go through all the entries in /proc/net/arp until we find the requested
 * IP address and return the MAC address bound to it.
 * @todo Make this function portable (using shell scripts?)
 */
char *
arp_get(const char req_ip[])
{
	FILE *proc;
	char ip[INET6_ADDRSTRLEN];
	char mac[18];
	char *reply = NULL;

	if (!(proc = fopen("/proc/net/arp", "r"))) {
		return NULL;
	}

	/* Skip first line */
	while (!feof(proc) && fgetc(proc) != '\n');

	/* Find ip, copy mac in reply */
	reply = NULL;
	while (!feof(proc) && (fscanf(proc, " %15[0-9.] %*s %*s %17[A-Fa-f0-9:] %*s %*s", ip, mac) == 2)) {
		if (strcmp(ip, req_ip) == 0) {
			reply = safe_strdup(mac);
			break;
		}
	}

	fclose(proc);

	return reply;
}

/** Initialize the firewall rules
 */
int
fw_init(void)
{
	debug(LOG_INFO, "Initializing Firewall");
	return iptables_fw_init();
}


/** Remove the firewall rules
 * This is used when we do a clean shutdown of nodogsplash.
 * @return Return code of iptables_fw_destroy()
 */
int
fw_destroy(void)
{
	debug(LOG_INFO, "Removing Firewall rules");
	return iptables_fw_destroy();
}

/** Ping clients to see if they are still active,
 *  refresh their traffic counters,
 *  remove and deny them if timed out
 */
void
fw_refresh_client_list(void)
{
	t_client *cp1, *cp2;
	s_config *config = config_get_config();
	const int checkinterval = config->checkinterval;
	const int clienttimeout = config->clienttimeout;
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

		if ((clienttimeout > 0) && (cp1->counters.last_updated + (checkinterval * clienttimeout) <= now)) {
			/* Timeout inactive user */
			debug(LOG_NOTICE, "Timeout inactive user: %s %s inactive %d secs. kB in: %llu  kB out: %llu",
				cp1->ip, cp1->mac, checkinterval * clienttimeout,
				cp1->counters.incoming / 1000, cp1->counters.outgoing / 1000);

			if (cp1->fw_connection_state == FW_MARK_AUTHENTICATED) {
				if (config->bin_voucher) {
					// client will be deauthenticated...
					execute("%s timeout_deauth %s %d %s",
						config->bin_voucher,
						cp1->mac,
						cp1->voucher,
						now - (cp1->counters.last_updated + (checkinterval * clienttimeout))
					);
				}
				iptables_fw_access(AUTH_MAKE_DEAUTHENTICATED, cp1);
			}
			client_list_delete(cp1);
		} else if (cp1->until_time > 0 && cp1->until_time <= now) {
			/* Force session timeout */
			debug(LOG_NOTICE, "Force out user: %s %s connected %d secs. kB in: %llu kB out: %llu",
				cp1->ip, cp1->mac, now - cp1->until_time,
				cp1->counters.incoming / 1000, cp1->counters.outgoing / 1000);

			if (cp1->fw_connection_state == FW_MARK_AUTHENTICATED) {
				if (config->bin_voucher) {
					// client will be deauthenticated...
					execute("%s session_deauth %s %d %s",
						config->bin_voucher,
						cp1->mac,
						cp1->voucher,
						now - cp1->until_time
					);
				}
				iptables_fw_access(AUTH_MAKE_DEAUTHENTICATED, cp1);
			}
			client_list_delete(cp1);
		}
	}
	UNLOCK_CLIENT_LIST();
}

/** Return a string representing a connection state */
const char *
fw_connection_state_as_string(int mark)
{
	if (mark == FW_MARK_PREAUTHENTICATED)
		return "Preauthenticated";
	if (mark == FW_MARK_AUTHENTICATED)
		return "Authenticated";
	if (mark == FW_MARK_TRUSTED)
		return "Trusted";
	if (mark == FW_MARK_BLOCKED)
		return "Blocked";
	return "ERROR: unrecognized mark";
}
