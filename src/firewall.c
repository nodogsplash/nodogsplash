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

/*
 * $Id: firewall.c 1162 2007-01-06 23:51:02Z benoitg $
 */
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
#include <sys/unistd.h>

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

#include "httpd.h"
#include "safe.h"
#include "debug.h"
#include "conf.h"
#include "client_list.h"
#include "firewall.h"
#include "fw_iptables.h"
#include "auth.h"


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
	char *ip, *mac;
	t_client *cp1, *cp2;
	time_t now, added_time, last_updated;
	s_config *config = config_get_config();

	/* Update all the counters */
	if (-1 == iptables_fw_counters_update()) {
		debug(LOG_ERR, "Could not get counters from firewall!");
		return;
	}

	LOCK_CLIENT_LIST();

	for (cp1 = cp2 = client_get_first_client(); NULL != cp1; cp1 = cp2) {
		cp2 = cp1->next;

		ip = safe_strdup(cp1->ip);
		mac = safe_strdup(cp1->mac);

		if (!(cp1 = client_list_find(ip, mac))) {
			debug(LOG_ERR, "Node %s was freed while being re-validated!", ip);
		} else {
			now = time(NULL);
			last_updated = cp1->counters.last_updated;
			added_time = cp1->added_time;
			if (last_updated +  (config->checkinterval * config->clienttimeout) <= now) {
				/* Timing out inactive user */
				debug(LOG_NOTICE, "%s %s inactive %d secs. kB in: %llu  kB out: %llu",
					  cp1->ip, cp1->mac, config->checkinterval * config->clienttimeout,
					  cp1->counters.incoming/1000, cp1->counters.outgoing/1000);
				if(cp1->fw_connection_state == FW_MARK_AUTHENTICATED) {
					iptables_fw_access(AUTH_MAKE_DEAUTHENTICATED, cp1);
				}
				client_list_delete(cp1);
			} else if (added_time +  (config->checkinterval * config->clientforceout) <= now) {
				/* Forcing out user */
				debug(LOG_NOTICE, "%s %s connected %d secs. kB in: %llu kB out: %llu",
					  cp1->ip, cp1->mac, config->checkinterval * config->clientforceout,
					  cp1->counters.incoming/1000, cp1->counters.outgoing/1000);
				if(cp1->fw_connection_state == FW_MARK_AUTHENTICATED) {
					iptables_fw_access(AUTH_MAKE_DEAUTHENTICATED, cp1);
				}
				client_list_delete(cp1);
			}
		}

		free(ip);
		free(mac);
	}
	UNLOCK_CLIENT_LIST();
}

/** Return a string representing a connection state */
const char *
fw_connection_state_as_string(int mark)
{
	if(mark == FW_MARK_PREAUTHENTICATED) return "Preauthenticated";
	if(mark == FW_MARK_AUTHENTICATED) return "Authenticated";
	if(mark == FW_MARK_TRUSTED) return "Trusted";
	if(mark == FW_MARK_BLOCKED) return "Blocked";
	return "ERROR: unrecognized mark";
}

