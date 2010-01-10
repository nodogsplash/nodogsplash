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

#include "httpd.h"
#include "safe.h"
#include "debug.h"
#include "conf.h"
#include "firewall.h"
#include "fw_iptables.h"
#include "auth.h"
#include "client_list.h"

extern pthread_mutex_t client_list_mutex;

int icmp_fd = 0;

/** Used to mark packets, and characterize client state.  Unmarked packets are considered 'preauthenticated' */
unsigned int  FW_MARK_PREAUTHENTICATED; /**< @brief 0: Actually not used as a packet mark */ 
unsigned int  FW_MARK_AUTHENTICATED;    /**< @brief The client is authenticated */ 
unsigned int  FW_MARK_BLOCKED;          /**< @brief The client is blocked */
unsigned int  FW_MARK_TRUSTED;          /**< @brief The client is trusted */
unsigned int  FW_MARK_MASK;             /**< @brief Iptables mask: bitwise or of the others */


/**
 * Get an IP's MAC address from the ARP cache.
 * Go through all the entries in /proc/net/arp until we find the requested
 * IP address and return the MAC address bound to it.
 * @todo Make this function portable (using shell scripts?)
 */
char           *
arp_get(char *req_ip) {
  FILE           *proc;
  char ip[16];
  char mac[18];
  char * reply = NULL;

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
fw_init(void) {
  int flags, oneopt = 1, zeroopt = 0;
  int result = 0;
  t_client * client = NULL;

  debug(LOG_INFO, "Creating ICMP socket");
  if ((icmp_fd = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1 ||
      (flags = fcntl(icmp_fd, F_GETFL, 0)) == -1 ||
      fcntl(icmp_fd, F_SETFL, flags | O_NONBLOCK) == -1 ||
      setsockopt(icmp_fd, SOL_SOCKET, SO_RCVBUF, &oneopt, sizeof(oneopt)) ||
      setsockopt(icmp_fd, SOL_SOCKET, SO_DONTROUTE, &zeroopt, sizeof(zeroopt)) == -1) {
    debug(LOG_ERR, "Cannot create ICMP raw socket.");
    return;
  }

  debug(LOG_INFO, "Initializing Firewall");
  result = iptables_fw_init();

  return result;
}


/** Remove the firewall rules
 * This is used when we do a clean shutdown of nodogsplash.
 * @return Return code of iptables_fw_destroy()
 */
int
fw_destroy(void) {
  if (icmp_fd != 0) {
    debug(LOG_INFO, "Closing ICMP socket");
    close(icmp_fd);
  }

  debug(LOG_INFO, "Removing Firewall rules");
  return iptables_fw_destroy();
}

/** Ping clients to see if they are still active,
 *  refresh their traffic counters,
 *  remove and deny them if timed out
 */
void
fw_refresh_client_list(void) {
  char            *ip, *mac;
  t_client        *cp1, *cp2;
  time_t now, added_time, last_updated;
  unsigned long long	    incoming, outgoing;
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
    outgoing = cp1->counters.outgoing;
    incoming = cp1->counters.incoming;

    UNLOCK_CLIENT_LIST();
    
    /* If the client is authenticated, ping him.
     * If he responds it'll keep activity on the link.
     * However, if the firewall blocks it, it will not help.  The suggested
     * way to deal with this is to keep the DHCP lease time extremely 
     * short:  Shorter than config->checkinterval * config->clienttimeout */
    /*** removed as useless ***
    if(FW_MARK_AUTHENTICATED == cp1->fw_connection_state) {
      icmp_ping(ip);
    }
    */
    
    LOCK_CLIENT_LIST();
	
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
	  iptables_fw_access(AUTH_MAKE_DEAUTHENTICATED, cp1->ip, cp1->mac);
	}
	client_list_delete(cp1);
      } else if (added_time +  (config->checkinterval * config->clientforceout) <= now) {
	/* Forcing out user */
	debug(LOG_NOTICE, "%s %s connected %d secs. kB in: %llu kB out: %llu",
	      cp1->ip, cp1->mac, config->checkinterval * config->clientforceout,
	      cp1->counters.incoming/1000, cp1->counters.outgoing/1000);
	if(cp1->fw_connection_state == FW_MARK_AUTHENTICATED) {
	  iptables_fw_access(AUTH_MAKE_DEAUTHENTICATED, cp1->ip, cp1->mac);
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
char *
fw_connection_state_as_string(int mark) {

  if(mark == FW_MARK_PREAUTHENTICATED) return "Preauthenticated";
  if(mark == FW_MARK_AUTHENTICATED) return "Authenticated";
  if(mark == FW_MARK_TRUSTED) return "Trusted";
  if(mark == FW_MARK_BLOCKED) return "Blocked";
  return "ERROR: unrecognized mark";

}


void 
icmp_ping(char *host) {
  struct sockaddr_in saddr;
#ifdef __linux__
  struct { 
    struct ip ip;
    struct icmp icmp;
  } packet;
#endif
  unsigned int i, j;
  int opt = 2000;
  unsigned short id = rand16();

  saddr.sin_family = AF_INET;
  saddr.sin_port = 0;
  inet_aton(host, &saddr.sin_addr);
#ifdef HAVE_SOCKADDR_SA_LEN
  saddr.sin_len = sizeof(struct sockaddr_in);
#endif

  memset(&(saddr.sin_zero), '\0', sizeof(saddr.sin_zero));

#ifdef __linux__
  memset(&packet.icmp, 0, sizeof(packet.icmp));
  packet.icmp.icmp_type = ICMP_ECHO;
  packet.icmp.icmp_id = id;
  for (j = 0, i = 0; i < sizeof(struct icmp) / 2; i++)
    j += ((unsigned short *)&packet.icmp)[i];
  while (j>>16)
    j = (j & 0xffff) + (j >> 16);  
  packet.icmp.icmp_cksum = (j == 0xffff) ? j : ~j;

  if (setsockopt(icmp_fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt)) == -1) {
      debug(LOG_ERR, "setsockopt(): %s", strerror(errno));
  }
  if (sendto(icmp_fd, (char *)&packet.icmp, sizeof(struct icmp), 0, (struct sockaddr *)&saddr, sizeof(saddr)) == -1) {
      debug(LOG_ERR, "sendto(): %s", strerror(errno));
  }
  opt = 1;
  if (setsockopt(icmp_fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt)) == -1) {
      debug(LOG_ERR, "setsockopt(): %s", strerror(errno));
  }
#endif

  return;
}

unsigned short rand16(void) {
  static int been_seeded = 0;

  if (!been_seeded) {
    int fd, n = 0;
    unsigned int c = 0, seed = 0;
    char sbuf[sizeof(seed)];
    char *s;
    struct timeval now;

    /* not a very good seed but what the heck, it needs to be quickly acquired */
    gettimeofday(&now, NULL);
    seed = now.tv_sec ^ now.tv_usec ^ (getpid() << 16);

    srand(seed);
    been_seeded = 1;
  }

  /* Some rand() implementations have less randomness in low bits
   * than in high bits, so we only pay attention to the high ones.
   * But most implementations don't touch the high bit, so we 
   * ignore that one.
   **/
  return( (unsigned short) (rand() >> 15) );
}
