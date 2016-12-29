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

/* $Id: firewall.h 935 2006-02-01 03:22:04Z benoitg $ */
/** @file firewall.h
    @brief Firewall update functions
    @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
*/

#ifndef _FIREWALL_H_
#define _FIREWALL_H_


/** Used to mark packets, and characterize client state.  Unmarked packets are considered 'preauthenticated' */
extern unsigned int  FW_MARK_PREAUTHENTICATED; /**< @brief 0: Actually not used as a packet mark */
extern unsigned int  FW_MARK_AUTHENTICATED;    /**< @brief The client is authenticated */
extern unsigned int  FW_MARK_BLOCKED;          /**< @brief The client is blocked */
extern unsigned int  FW_MARK_TRUSTED;          /**< @brief The client is trusted */
extern unsigned int  FW_MARK_MASK;             /**< @brief Iptables mask: bitwise or of the others */


/** @brief Initialize the firewall */
int fw_init(void);

/** @brief Destroy the firewall */
int fw_destroy(void);

/** @brief Refreshes the entire client list */
void fw_refresh_client_list(void);

/** @brief Get an IP's MAC address from the ARP cache.*/
char *arp_get(const char req_ip[]);

/** @brief Return a string representing a connection state */
const char *fw_connection_state_as_string(int mark);

#endif /* _FIREWALL_H_ */
