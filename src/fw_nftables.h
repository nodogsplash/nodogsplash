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

/** @file fw_iptables.h
    @brief Firewall iptables functions
    @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
    @author Copyright (C) 2007 Paul Kube <nodogsplash@kokoro.ucsd.edu>
*/

#ifndef _FW_NFTABLES_H_
#define _FW_NFTABLES_H_

#include <ctype.h>

#include "client_list.h"
#include "fw_common.h"

void nftables_initialize_nft_context();

/** @brief Initialize the firewall */
int nftables_fw_init(void);

/** @brief Destroy the firewall */
int nftables_fw_destroy(void);

/** @brief Define the access of a specific client */
int nftables_fw_authenticate(t_client *client);
int nftables_fw_deauthenticate(t_client *client);

/** @brief Return the total download usage in bytes */
unsigned long long int nftables_fw_total_download();

/** @brief Return the total upload usage in bytes */
unsigned long long int nftables_fw_total_upload();

/** @brief All counters in the client list */
int nftables_fw_counters_update(void);

/** @brief Fork an nftables command */
int nftables_do_command(const char format[], ...);

int nftables_block_mac(const char mac[]);
int nftables_unblock_mac(const char mac[]);

int nftables_allow_mac(const char mac[]);
int nftables_unallow_mac(const char mac[]);

int nftables_trust_mac(const char mac[]);
int nftables_untrust_mac(const char mac[]);

#endif /* _FW_NFTABLES_H_ */
