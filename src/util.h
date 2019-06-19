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

/** @file util.h
    @brief Misc utility functions
    @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
*/

#ifndef _UTIL_H_
#define _UTIL_H_

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))
#define MAX(X, Y) (((X) > (Y)) ? (X) : (Y))

/* @brief Execute a shell command */
int execute(const char fmt[], ...);
int execute_ret(char* msg, int msg_len, const char fmt[], ...);

/* @brief Get IP address of an interface */
char *get_iface_ip(const char ifname[], int ip6);

/* @brief Get MAC address of an interface */
char *get_iface_mac(const char ifname[]);

/* @brief Get interface name of default gateway */
char *get_ext_iface (void);

/* @brief Sets hint that an online action (dns/connect/etc using WAN) succeeded */
void mark_online();
/* @brief Sets hint that an online action (dns/connect/etc using WAN) failed */
void mark_offline();
/* @brief Returns a guess (true or false) on whether we're online or not based on previous calls to mark_online and mark_offline */
int is_online();

/* @brief Sets hint that an auth server online action succeeded */
void mark_auth_online();
/* @brief Sets hint that an auth server online action failed */
void mark_auth_offline();
/* @brief Returns a guess (true or false) on whether we're an auth server is online or not based on previous calls to mark_auth_online and mark_auth_offline */
int is_auth_online();

/* @brief Format a time_t value to 'Fri Jul 27 18:52:22 2018' */
char *format_time(time_t time, char buf[64]);

/* @brief Check if the address is a valid IPv4 or IPv6 address */
int is_addr(const char* addr);

/*
 * @brief Mallocs and returns nodogsplash uptime string
 */
char *get_uptime_string(char buf[64]);
/*
 * @brief Writes a human-readable paragraph of the status of the nodogsplash process
 */
void ndsctl_status(FILE *fp);
/*
 * @brief Writes a machine-readable dump of currently connected clients
 */
void ndsctl_clients(FILE *fp);

/*
 * @brief Writes a machine-readable json of currently connected clients
 */
void ndsctl_json(FILE *fp, const char *arg);

/** @brief cheap random */
unsigned short rand16(void);

/*
 * @brief Maximum <host>:<port> length (IPv6)
 * - INET6_ADDRSTRLEN: 46 (45 chars + term. Null byte)
 * - square brackets around IPv6 address: 2 ('[' and ']')
 * - port separator character: 1 (':')
 * - max port number: 5 (2^16 = 65536)
 * Total: 54 chars
 **/
#define MAX_HOSTPORTLEN ( INET6_ADDRSTRLEN + sizeof("[]:65536")-1 )

#endif /* _UTIL_H_ */
