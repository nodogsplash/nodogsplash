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

/* $Id: fw_iptables.h 901 2006-01-17 18:58:13Z mina $ */
/** @file fw_iptables.h
    @brief Firewall iptables functions
    @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
*/

#ifndef _FW_IPTABLES_H_
#define _FW_IPTABLES_H_

#include "firewall.h"
#include "auth.h"

/*@{*/ 
/**Iptable chain names used by nodogsplash */
#define CHAIN_TO_INTERNET "nodogsplash_toInternet"
#define CHAIN_TO_ROUTER "nodogsplash_toRouter"
#define CHAIN_OUTGOING  "nodogsplash_Outgoing"
#define CHAIN_INCOMING  "nodogsplash_Incoming"
#define CHAIN_AUTHENTICATED     "nodogsplash_Authenticated"
#define CHAIN_UNKNOWN   "nodogsplash_Unknown"
#define CHAIN_BLOCKED    "nodogsplash_Blocked"
#define CHAIN_TRUSTED    "nodogsplash_Trusted"
/*@}*/ 

/** @brief Initialize the firewall */
int iptables_fw_init(void);

/** @brief Initializes the authservers table */
void iptables_fw_set_authservers(void);

/** @brief Clears the authservers table */
void iptables_fw_clear_authservers(void);

/** @brief Destroy the firewall */
int iptables_fw_destroy(void);

/** @brief Helper function for iptables_fw_destroy */
int iptables_fw_destroy_mention( char * table, char * chain, char * mention);

/** @brief Define the access of a specific client */
int iptables_fw_access(t_authaction action, char *ip, char *mac);

/** @brief All counters in the client list */
int iptables_fw_counters_update(void);

#endif /* _IPTABLES_H_ */
