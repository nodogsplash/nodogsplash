/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free Software Foundation; either version 2 of   *
 * the License, or (at your option) any later version.              *
 * *
 * This program is distributed in the hope that it will be useful,  *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of   *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the    *
 * GNU General Public License for more details.                     *
 * *
 * You should have received a copy of the GNU General Public License*
 * along with this program; if not, contact:                        *
 * *
 * Free Software Foundation           Voice:  +1-617-542-5942       *
 * 59 Temple Place - Suite 330        Fax:    +1-617-542-2652       *
 * Boston, MA  02111-1307,  USA       gnu@gnu.org                   *
 * *
 \********************************************************************/

/** @internal
  @file fw_nftables.c
  @brief Firewall nftables functions using libjansson
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
  @author Copyright (C) 2007 Paul Kube <nodogsplash@kokoro.ucsd.edu>
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <nftables/libnftables.h>
#include <jansson.h>

#include "common.h"
#include "safe.h"
#include "conf.h"
#include "client_list.h"
#include "fw_common.h"
#include "fw_nftables.h"
#include "debug.h"

extern pthread_mutex_t client_list_mutex;
extern pthread_mutex_t config_mutex;

int _nftables_setup_table(const char *nftable_name, char *gw_interface, char *gw_iprange, char *gw_address, int gw_port, int macmechanism);

static char *cached_nftable_name = NULL;

static const char *
_get_nftable_name()
{
	if (!cached_nftable_name) {
		LOCK_CONFIG();
		cached_nftable_name = safe_strdup(config_get_config()->nftable_name);
		UNLOCK_CONFIG();
	}
	return cached_nftable_name;
}

/** @internal */
int
nftables_do_command(const char *format, ...)
{
    struct nft_ctx *ctx;
    va_list vlist;
    char *fmt_cmd = NULL;
    int rc;

    ctx = nft_ctx_new(NFT_CTX_DEFAULT);
    if (!ctx) {
		debug(LOG_ERR, "creating nft context failed");
        return -1;
    }

    va_start(vlist, format);
    safe_vasprintf(&fmt_cmd, format, vlist);
    va_end(vlist);

    nft_ctx_output_set_flags(ctx, 0);

    rc = nft_run_cmd_from_buffer(ctx, fmt_cmd);
    if (rc != 0) {
        debug(LOG_INFO, "NFT Error %i: %s", rc, fmt_cmd);
    }

    nft_ctx_free(ctx);
    free(fmt_cmd);

    return rc;
}

/** @internal - Executes command and returns JSON output string (caller must free *output) */
int
nftables_do_json_command(char **output, const char *format, ...)
{
    struct nft_ctx *ctx;
    va_list vlist;
    char *fmt_cmd = NULL;
    int rc;
    const char *raw_buf;

	ctx = nft_ctx_new(NFT_CTX_DEFAULT);
    if (!ctx) {
		debug(LOG_ERR, "creating nft context failed");
        return -1;
    }

    va_start(vlist, format);
    safe_vasprintf(&fmt_cmd, format, vlist);
    va_end(vlist);

    nft_ctx_output_set_flags(ctx, NFT_CTX_OUTPUT_JSON);
    nft_ctx_buffer_output(ctx);

    rc = nft_run_cmd_from_buffer(ctx, fmt_cmd);
    if (rc != 0) {
        debug(LOG_INFO, "NFT Error %i: %s", rc, fmt_cmd);
    }

    raw_buf = nft_ctx_get_output_buffer(ctx);
	*output = safe_strdup(raw_buf);

    nft_ctx_free(ctx);
    free(fmt_cmd);
    
    return rc;
}

/**
 * @internal
 * Compiles a struct definition of a firewall rule into a valid iptables
 * command.
 * @arg table Table containing the chain.
 * @arg chain Chain that the command will be (-A)ppended to.
 * @arg rule Definition of a rule into a struct, from conf.c.
 */
static char *
_nftables_compile(const char table[], const char chain[], t_firewall_rule *rule)
{
	char command[MAX_BUF];
	char *mode;

	mode = NULL;
	memset(command, 0, MAX_BUF);

	switch (rule->target) {
	case TARGET_DROP:
		mode = "drop";
		break;
	case TARGET_REJECT:
		mode = "reject";
		break;
	case TARGET_ACCEPT:
		mode = "accept";
		break;
	case TARGET_LOG:
		mode = "log";
		break;
	case TARGET_ULOG:
		mode = "log";
		break;
	}

	snprintf(command, sizeof(command),  "add rule ip %s %s ", table, chain);
	if ((rule->mask != NULL) && (strcmp(rule->mask, "0.0.0.0/0") != 0)) {
		snprintf((command + strlen(command)),
				 (sizeof(command) - strlen(command)),
				 "ip daddr %s ", rule->mask);
	}
	if (rule->protocol != NULL) {
		/* if protocol != "all" and != "icmp" */
		if ((strcmp(rule->protocol, "all") != 0) && (strcmp(rule->protocol, "icmp") != 0)) {
			snprintf((command + strlen(command)),
					 (sizeof(command) - strlen(command)),
					 "%s ", rule->protocol);
		}
		/* if protocol == "icmp" */
		if (strcmp(rule->protocol, "icmp") == 0) {
			snprintf((command + strlen(command)),
					 (sizeof(command) - strlen(command)),
					 "meta l4proto icmp ");
		}
	}
	if (rule->port != NULL) {
		snprintf((command + strlen(command)),
				 (sizeof(command) - strlen(command)),
				 "dport %s ", rule->port);
	}
	if (rule->ipset != NULL) {
		return safe_strdup("ipset not implemented");
	}
	snprintf((command + strlen(command)),
			 (sizeof(command) - strlen(command)),
			 " %s", mode);
	return(safe_strdup(command));
}

/**
 * @internal
 * append all the rules in a rule set.
 * @arg ruleset Name of the ruleset
 * @arg table Table containing the chain
 * @arg chain nftables chain the rules go into
 */
static int
_nftables_append_ruleset(const char table[], const char ruleset[], const char chain[])
{
	t_firewall_rule *rule;
	char *cmd;
	int ret = 0;

	debug(LOG_DEBUG, "Loading ruleset %s into table %s, chain %s", ruleset, table, chain);

	for (rule = get_ruleset_list(ruleset); rule != NULL; rule = rule->next) {
		cmd = _nftables_compile(table, chain, rule);
		debug(LOG_DEBUG, "Loading rule \"%s\" ", cmd);
		ret |= nftables_do_command(cmd);
		free(cmd);
	}

	debug(LOG_DEBUG, "Ruleset %s loaded into table %s, chain %s", ruleset, table, chain);
	return ret;
}

int
_nftables_put_mac_on_list(const char list[], const char mac[])
{
	int rc = 0;

	/* put mac on list */
	rc = nftables_do_command("add element ip %s %s { %s }", _get_nftable_name(), list, mac);

	return rc;
}

int
_nftables_remove_mac_from_list(const char list[], const char mac[])
{
	int rc = 0;

	/* put mac on list */
	rc = nftables_do_command("delete element ip %s %s { %s }", _get_nftable_name(), list, mac);

	return rc;
}

int
nftables_block_mac(const char mac[])
{
	return _nftables_put_mac_on_list("blocklist", mac);
}

int
nftables_unblock_mac(const char mac[])
{
	return _nftables_remove_mac_from_list("blocklist", mac);
}

int
nftables_allow_mac(const char mac[])
{
	return _nftables_put_mac_on_list("allowlist", mac);
}

int
nftables_unallow_mac(const char mac[])
{
	return _nftables_remove_mac_from_list("allowlist", mac);
}

int
nftables_trust_mac(const char mac[])
{
	return _nftables_put_mac_on_list("trustlist", mac);
}

int
nftables_untrust_mac(const char mac[])
{
	return _nftables_remove_mac_from_list("trustlist", mac);
}

/** Initialize the firewall rules.
 */
int
nftables_fw_init(void)
{
	s_config *config;
	char *gw_interface = NULL;
	char *gw_address = NULL;
	char *gw_iprange = NULL;
	int gw_port = 0;
	int traffic_control;
	int set_mss, mss_value;
	t_MAC *pt; /* trustedmaclist */
	t_MAC *pb; /* blockedmaclist */
	t_MAC *pa; /* allowedmaclist */
	int rc = 0;
	int macmechanism;
	char *nftable_name = NULL;

	debug(LOG_NOTICE, "Initializing firewall rules");
	
	LOCK_CONFIG();
	config = config_get_config();
	gw_interface = safe_strdup(config->gw_interface); /* must free */
	
	gw_address = safe_strdup(config->gw_address);    /* must free */
	gw_iprange = safe_strdup(config->gw_iprange);    /* must free */
	gw_port = config->gw_port;
	pt = config->trustedmaclist;
	pb = config->blockedmaclist;
	pa = config->allowedmaclist;
	macmechanism = config->macmechanism;
	set_mss = config->set_mss;
	mss_value = config->mss_value;
	traffic_control = config->traffic_control;
	FW_MARK_BLOCKED = config->fw_mark_blocked;
	FW_MARK_TRUSTED = config->fw_mark_trusted;
	FW_MARK_AUTHENTICATED = config->fw_mark_authenticated;
	UNLOCK_CONFIG();

	/* Set up packet marking */
	rc |= fw_common_init_marks();

	/* create table, chains and standard rules */
	rc |= _nftables_setup_table(_get_nftable_name(), gw_interface, gw_iprange, gw_address, gw_port, macmechanism);

	/* put trusted macs in trustlist */
	for (; pt != NULL; pt = pt->next) {
		rc |= nftables_trust_mac(pt->mac);
	}

	/* Rules to mark as blocked MAC address packets in mangle PREROUTING */
	if (MAC_BLOCK == macmechanism) {
		/* with the MAC_BLOCK mechanism,
		 * MAC's on the block list are marked as blocked;
		 * everything else passes */
		for (; pb != NULL; pb = pb->next) {
			rc |= nftables_block_mac(pb->mac);
		}
	} else if (MAC_ALLOW == macmechanism) {
		/* with the MAC_ALLOW mechanism,
		 * MAC's on the allow list pass;
		 * everything else is to be marked as blocked */

		/* populate allowlist with clients that are allowed to authenticate */
		for (; pa != NULL; pa = pa->next) {
			rc |= nftables_allow_mac(pa->mac);
		}
	} else {
		debug(LOG_ERR, "Unknown MAC mechanism: %d", macmechanism);
		rc = -1;
	}

	free(gw_interface);
	free(gw_iprange);
	free(gw_address);

	return rc;
}

/**
 * @internal
 * create standard table, chains and rules
 */
int
_nftables_setup_table(const char *nftable_name, char *gw_interface, char *gw_iprange, char *gw_address, int gw_port, int macmechanism)
{
	int rc = 0;

	/* create (single) nodogsplash table */
	nftables_do_command("destroy table ip %s", nftable_name);
	nftables_do_command("add table ip %s", nftable_name);

	/* TODO:
	 *		- TrafficControl not implemented
	 *		- Timeouts should probably be implemented by setting a timeout in the nftables set
	 *		- FirewallRuleSets not implemented
	 */

	/* rules to access NDS the webIF */
	rc |= nftables_do_command("add chain ip %s " CHAIN_TO_ROUTER " { type filter hook input priority 0; }", nftable_name);
	/* filtering packets routed to internet */
	rc |= nftables_do_command("add chain ip %s " CHAIN_TO_INTERNET " { type filter hook forward priority 0; }", nftable_name);
	/* for marking authenticated packets */
	rc |= nftables_do_command("add chain ip %s " CHAIN_AUTHENTICATED, nftable_name);
	/* for early packet marking */
	rc |= nftables_do_command("add chain ip %s " CHAIN_MARK " { type filter hook prerouting priority raw; }", nftable_name);
	/* for marking authenticated packets, and for counting outgoing packets */
	/* priority -125 is right after mangle (-150) */
	rc |= nftables_do_command("add chain ip %s " CHAIN_OUTGOING " { type filter hook forward priority -125; }", nftable_name);
	/* for filtering packets for NAT_OUTGOING */
	rc |= nftables_do_command("add chain ip %s " CHAIN_FILTER_NAT_OUTGOING " { type nat hook prerouting priority -100; }", nftable_name);
	/* for DNAT towards webinterface */
	rc |= nftables_do_command("add chain ip %s " CHAIN_NAT_OUTGOING, nftable_name);

	rc |= nftables_do_command("add chain ip %s " CHAIN_TRUSTED, nftable_name);
	rc |= nftables_do_command("add chain ip %s " CHAIN_TRUSTED_TO_ROUTER, nftable_name);

	/* setup nftables sets */
	rc |= nftables_do_command("add set ip %s blocklist { type ether_addr; counter; }", nftable_name); /* blocked MAC addresses */
	rc |= nftables_do_command("add set ip %s allowlist { type ether_addr; counter; }", nftable_name); /* allowed MAC addresses */
	rc |= nftables_do_command("add set ip %s trustlist { type ether_addr; counter; }", nftable_name); /* trusted MAC addresses */
	rc |= nftables_do_command("add set ip %s authlist_ip { type ipv4_addr ; counter; }", nftable_name); /* authenticated IP addresses */
	rc |= nftables_do_command("add set ip %s authlist { type ipv4_addr . ether_addr ; counter; }", nftable_name); /* authenticated MAC and IP addresses */

	/* create rules for CHAIN_TO_ROUTER */
	/* drop packets marked blocked */
	rc |= nftables_do_command("add rule ip %s " CHAIN_TO_ROUTER " meta mark and 0x%x == 0x%x drop", nftable_name, FW_MARK_MASK, FW_MARK_BLOCKED);
	/* drop invalid packets */
	rc |= nftables_do_command("add rule ip %s " CHAIN_TO_ROUTER " ct state invalid counter drop", nftable_name);
	rc |= nftables_do_command("add rule ip %s " CHAIN_TO_ROUTER " ct state related,established counter accept", nftable_name);
	/* accept packets on the HTTP listening port */
	rc |= nftables_do_command("add rule ip %s " CHAIN_TO_ROUTER " tcp dport %d counter accept", nftable_name, gw_port);

	/* packets marked TRUSTED: */

	/* if trusted-users-to-router ruleset is empty:
	 *    use empty ruleset policy
	 * else:
	 *    jump to CHAIN_TRUSTED_TO_ROUTER
	 */
	if (is_empty_ruleset("trusted-users-to-router")) {
		rc |= nftables_do_command("add rule ip %s " CHAIN_TO_ROUTER " mark and 0x%x == 0x%x %s", nftable_name, FW_MARK_MASK, FW_MARK_TRUSTED, get_empty_ruleset_policy("trusted-users-to-router"));
	} else {
		rc |= nftables_do_command("add rule ip %s " CHAIN_TO_ROUTER " mark and 0x%x == 0x%x jump " CHAIN_TRUSTED_TO_ROUTER, nftable_name, FW_MARK_MASK, FW_MARK_TRUSTED);
		/* CHAIN_TRUSTED_TO_ROUTER, related and established packets ACCEPT */
		rc |= nftables_do_command("add rule ip %s " CHAIN_TRUSTED_TO_ROUTER " ct state related,established counter accept", nftable_name);
		/* CHAIN_TRUSTED_TO_ROUTER, append the "trusted-users-to-router" ruleset */
		rc |= _nftables_append_ruleset(nftable_name, "trusted-users-to-router", CHAIN_TRUSTED_TO_ROUTER);
		/* CHAIN_TRUSTED_TO_ROUTER, any packets not matching that ruleset REJECT */
		rc |= nftables_do_command("add rule ip %s " CHAIN_TRUSTED_TO_ROUTER " reject", nftable_name);
	}

	/* CHAIN_TO_ROUTER, other packets: */

	/* if users-to-router ruleset is empty:
	 *    use empty ruleset policy
	 * else:
	 *    load and use users-to-router ruleset
	 */
	if (is_empty_ruleset("users-to-router")) {
		rc |= nftables_do_command("add rule ip %s " CHAIN_TO_ROUTER " %s", nftable_name, get_empty_ruleset_policy("users-to-router"));
	} else {
		/* CHAIN_TO_ROUTER, append the "users-to-router" ruleset */
		rc |= _nftables_append_ruleset(nftable_name, "users-to-router", CHAIN_TO_ROUTER);
		/* everything else, REJECT */
		rc |= nftables_do_command("add rule ip %s " CHAIN_TO_ROUTER " reject", nftable_name);
	}

	/* create rules for CHAIN_TO_INTERNET */
	/* global download counters for up- and download */
	rc |= nftables_do_command("add counter ip %s global_upload_counter", nftable_name);
	rc |= nftables_do_command("add counter ip %s global_download_counter", nftable_name);
	rc |= nftables_do_command("insert rule ip %s " CHAIN_TO_INTERNET " iifname %s counter name global_upload_counter", nftable_name, gw_interface);
	rc |= nftables_do_command("insert rule ip %s " CHAIN_OUTGOING " oifname %s counter name global_download_counter", nftable_name, gw_interface);
	/* CHAIN_TO_INTERNET packets marked BLOCKED DROP */
	rc |= nftables_do_command("add rule ip %s " CHAIN_TO_INTERNET " mark and 0x%x == 0x%x counter drop", nftable_name, FW_MARK_MASK, FW_MARK_BLOCKED);
	/* DROP invalid packets */
	rc |= nftables_do_command("add rule ip %s " CHAIN_TO_INTERNET " ct state invalid counter drop", nftable_name);
	/* Accept established traffic. Required for TrustList clients (missing tc connmark). */
	rc |= nftables_do_command("add rule ip %s " CHAIN_TO_INTERNET " ct state related,established counter accept", nftable_name);
	rc |= nftables_do_command("add rule ip %s " CHAIN_TO_INTERNET " tcp flags syn / syn,rst counter tcp option maxseg size set rt mtu", nftable_name);

	/* CHAIN_TO_INTERNET, packets marked TRUSTED: */

	/* if trusted-users ruleset is empty:
	 *    use empty ruleset policy
	 * else:
	 *    jump to CHAIN_TRUSTED, and load and use trusted-users ruleset
	 */
	if (is_empty_ruleset("trusted-users")) {
		rc |= nftables_do_command("add rule ip %s " CHAIN_TO_INTERNET " mark and 0x%x == 0x%x %s", nftable_name, FW_MARK_MASK, FW_MARK_TRUSTED, get_empty_ruleset_policy("trusted-users"));
	} else {
		rc |= nftables_do_command("add rule ip %s " CHAIN_TO_INTERNET " mark and 0x%x == 0x%x jump " CHAIN_TRUSTED, nftable_name, FW_MARK_MASK, FW_MARK_TRUSTED);
		/* CHAIN_TRUSTED, related and established packets ACCEPT */
		rc |= nftables_do_command("add rule ip %s " CHAIN_TRUSTED " ct state related,established counter accept", nftable_name);
		/* CHAIN_TRUSTED, append the "trusted-users" ruleset */
		rc |= _nftables_append_ruleset(nftable_name, "trusted-users", CHAIN_TRUSTED);
		/* CHAIN_TRUSTED, any packets not matching that ruleset REJECT */
		rc |= nftables_do_command("add rule ip %s " CHAIN_TRUSTED " reject", nftable_name);
	}

	/* CHAIN_TO_INTERNET, packets marked AUTHENTICATED: */

	/* if authenticated-users ruleset is empty:
	 *    use empty ruleset policy
	 * else:
	 *    jump to CHAIN_AUTHENTICATED, and load and use authenticated-users ruleset
	 */
	if (is_empty_ruleset("authenticated-users")) {
		rc |= nftables_do_command("add rule ip %s " CHAIN_TO_INTERNET " mark and 0x%x == 0x%x %s", nftable_name, FW_MARK_MASK, FW_MARK_AUTHENTICATED, get_empty_ruleset_policy("authenticated-users"));
	} else {
		rc |= nftables_do_command("add rule ip %s " CHAIN_TO_INTERNET " mark and 0x%x == 0x%x jump " CHAIN_AUTHENTICATED, nftable_name, FW_MARK_MASK, FW_MARK_AUTHENTICATED);
		/* CHAIN_AUTHENTICATED, related and established packets ACCEPT */
		rc |= nftables_do_command("add rule ip %s " CHAIN_AUTHENTICATED " ct state related,established counter accept", nftable_name);
		/* CHAIN_AUTHENTICATED, append the "authenticated-users" ruleset */
		rc |= _nftables_append_ruleset(nftable_name, "authenticated-users", CHAIN_AUTHENTICATED);
		/* CHAIN_AUTHENTICATED, any packets not matching that ruleset REJECT */
		rc |= nftables_do_command("add rule ip %s " CHAIN_AUTHENTICATED " reject", nftable_name);
	}

	/* CHAIN_TO_INTERNET, other packets: */

	/* if preauthenticated-users ruleset is empty:
	 *    use empty ruleset policy
	 * else:
	 *    load and use authenticated-users ruleset
	 */
	if (is_empty_ruleset("preauthenticated-users")) {
		rc |= nftables_do_command("add rule ip %s " CHAIN_TO_INTERNET " %s", nftable_name, get_empty_ruleset_policy("preauthenticated-users"));
	} else {
		rc |= _nftables_append_ruleset(nftable_name, "preauthenticated-users", CHAIN_TO_INTERNET);
	}
	/* CHAIN_TO_INTERNET, all other packets REJECT */
	rc |= nftables_do_command("add rule ip %s " CHAIN_TO_INTERNET " counter reject", nftable_name);

	/* create rules for CHAIN_MARK */
	rc |= nftables_do_command("add rule ip %s " CHAIN_MARK " iifname %s ip saddr %s ether saddr @blocklist mark set mark or 0x%x", nftable_name, gw_interface, gw_iprange, FW_MARK_BLOCKED);
	rc |= nftables_do_command("add rule ip %s " CHAIN_MARK " iifname %s ip saddr %s ether saddr @trustlist mark set mark or 0x%x", nftable_name, gw_interface, gw_iprange, FW_MARK_TRUSTED);
	rc |= nftables_do_command("add rule ip %s " CHAIN_MARK " iifname %s ip saddr . ether saddr @authlist mark set mark or 0x%x", nftable_name, gw_interface, FW_MARK_AUTHENTICATED);
	if (MAC_ALLOW == macmechanism) {
		rc |= nftables_do_command("add rule ip %s " CHAIN_MARK " iifname %s ip saddr %s ether saddr @allowlist return", nftable_name, gw_interface, gw_iprange);
		/* rule to mark everything blocked if config macmechanism is allow
			this MUST be the last rule in the chain */
		rc |= nftables_do_command("add rule ip %s " CHAIN_MARK " iifname %s mark set mark or 0x%x", nftable_name, gw_interface, FW_MARK_BLOCKED);
	}

	/* create rules for CHAIN_OUTGOING */
	rc |= nftables_do_command("add rule ip %s " CHAIN_OUTGOING " oifname %s ip daddr @authlist_ip mark set mark or 0x%x accept", nftable_name, gw_interface, FW_MARK_AUTHENTICATED);

	/* create rules for CHAIN_FILTER_NAT_OUTGOING */
	rc |= nftables_do_command("add rule ip %s " CHAIN_FILTER_NAT_OUTGOING " iifname %s ip saddr %s jump " CHAIN_NAT_OUTGOING, nftable_name, gw_interface, gw_iprange);

	/* create rules for CHAIN_NAT_OUTGOING */
	/* CHAIN_OUTGOING, packets marked TRUSTED  ACCEPT */
	rc |= nftables_do_command("add rule ip %s " CHAIN_NAT_OUTGOING " mark and 0x%x == 0x%x counter return", nftable_name, FW_MARK_MASK, FW_MARK_TRUSTED);
	/* CHAIN_OUTGOING, packets marked AUTHENTICATED  ACCEPT */
	rc |= nftables_do_command("add rule ip %s " CHAIN_NAT_OUTGOING " mark and 0x%x == 0x%x counter return", nftable_name, FW_MARK_MASK, FW_MARK_AUTHENTICATED);
	/* CHAIN_OUTGOING, append the "preauthenticated-users" ruleset */
	rc |= _nftables_append_ruleset(nftable_name, "preauthenticated-users", CHAIN_NAT_OUTGOING);
	/* CHAIN_OUTGOING, packets for tcp port 80, redirect to gw_port on primary address for the iface */
	rc |= nftables_do_command("add rule ip %s " CHAIN_NAT_OUTGOING " tcp dport 80 counter dnat to %s", nftable_name, gw_address);
	/* CHAIN_OUTGOING, other packets ACCEPT */
	rc |= nftables_do_command("add rule ip %s " CHAIN_NAT_OUTGOING " counter accept", nftable_name);
	return rc;
}

/** Remove the firewall rules
 * This is used when we do a clean shutdown of nodogsplash,
 * and when it starts, to make sure there are no rules left over from a crash
 */

int
nftables_fw_destroy(void)
{
	debug(LOG_DEBUG, "Destroying our nftables entries");

	/* just destroy the whole table */
	nftables_do_command("destroy table ip %s", _get_nftable_name());
	return 0;
}

/** Insert or delete firewall mangle rules marking a client's packets.
 */
int
nftables_fw_authenticate(t_client *client)
{
	int rc = 0, download_limit, upload_limit, traffic_control;
	s_config *config;
	char upload_ifbname[16];
	
	LOCK_CONFIG();
	config = config_get_config();
	sprintf(upload_ifbname, "ifb%d", config->upload_ifb);
	traffic_control = config->traffic_control;
	download_limit = config->download_limit;
	upload_limit = config->upload_limit;
	UNLOCK_CONFIG();

	if ((client->download_limit > 0) && (client->upload_limit > 0)) {
		download_limit = client->download_limit;
		upload_limit = client->upload_limit;
	}

	debug(LOG_NOTICE, "Authenticating %s %s", client->ip, client->mac);

	/* write client IP + MAC in the nftables authlist set: */
	nftables_do_command("add element ip %s authlist { %s . %s }", _get_nftable_name(), client->ip, client->mac);
	/* write client IP in the nftables authlist_ip set: */
	nftables_do_command("add element ip %s authlist_ip { %s }", _get_nftable_name(), client->ip);

	return rc;
}

int
nftables_fw_deauthenticate(t_client *client)
{
	int rc = 0, download_limit, upload_limit, traffic_control;
	s_config *config;
	char upload_ifbname[16];

	LOCK_CONFIG();
	config = config_get_config();
	sprintf(upload_ifbname, "ifb%d", config->upload_ifb);
	traffic_control = config->traffic_control;
	download_limit = config->download_limit;
	upload_limit = config->upload_limit;
	UNLOCK_CONFIG();

	if ((client->download_limit > 0) && (client->upload_limit > 0)) {
		download_limit = client->download_limit;
		upload_limit = client->upload_limit;
	}

	/* Remove client from authlist and authlist_ip */
	nftables_do_command("delete element ip %s authlist { %s . %s }", _get_nftable_name(), client->ip, client->mac);
	nftables_do_command("delete element ip %s authlist_ip { %s }", _get_nftable_name(), client->ip);

	return rc;
}

static uint64_t
_nft_get_named_counter(const char *counter_name)
{
    char *output = NULL;
    uint64_t bytes = 0;
    int rc;

    rc = nftables_do_json_command(&output, "list counter ip %s %s", _get_nftable_name(), counter_name);

    if (rc == 0 && output) {
		json_error_t error;
		json_t *root = json_loads(output, 0, &error);
		if (root) {
			json_t *nftables_arr = json_object_get(root, "nftables");
			if (json_is_array(nftables_arr)) {
				size_t index;
				json_t *entry;
				json_array_foreach(nftables_arr, index, entry) {
					json_t *counter_obj = json_object_get(entry, "counter");
					if (counter_obj) {
						json_t *bytes_obj = json_object_get(counter_obj, "bytes");
						if (json_is_integer(bytes_obj)) {
							bytes = json_integer_value(bytes_obj);
							break;
						}
					}
				}
			}
		}
		json_decref(root);
	}

	free(output);
	return bytes;
}

unsigned long long int nftables_fw_total_upload() { 
    return _nft_get_named_counter("global_upload_counter"); 
}

unsigned long long int nftables_fw_total_download() { 
    return _nft_get_named_counter("global_download_counter"); 
}

int
nftables_fw_counters_update(void)
{
	char *output = NULL;
	int rc;
	json_error_t jerror;
	json_t *jroot;

	rc = nftables_do_json_command(&output, "list table ip %s", _get_nftable_name());

	if (rc != 0) {
		free(output);
		return -1;
	}

	jroot = json_loads(output, 0, &jerror);
	free(output);

	if (!jroot) {
		debug(LOG_ERR, "JSON load error: %s (line %d)", jerror.text, jerror.line);
		return -1;
	}

	json_t *nftables_arr = json_object_get(jroot, "nftables");
	if (json_is_array(nftables_arr)) {
		size_t index;
		json_t *entry;
		t_client *client;

		LOCK_CLIENT_LIST();
		debug(LOG_DEBUG, "nftables_fw_counters_update");
		json_array_foreach(nftables_arr, index, entry) {
			json_t *set_wrapper = json_object_get(entry, "set");
			if (set_wrapper) {
				const char *sname = json_string_value(json_object_get(set_wrapper, "name"));
				json_t *elem_arr = json_object_get(set_wrapper, "elem");
				if (sname && elem_arr && json_is_array(elem_arr)) {
					if (strcmp(sname, "authlist") == 0) {
						/* parse authlist as outgoing traffic (upload) */
						size_t index_elem = 0;
						json_t *wrapper_elem;
						json_array_foreach(elem_arr, index_elem, wrapper_elem)  {
							json_t *elem_obj = json_object_get(wrapper_elem, "elem");
							json_t *val_obj = json_object_get(elem_obj, "val");
							json_t *counter_obj = json_object_get(elem_obj, "counter");
							uint64_t bytes = 0;
							const char *ip = NULL;
							const char *mac = NULL;
							if (counter_obj) {
								json_t *b = json_object_get(counter_obj, "bytes");
								if (json_is_integer(b)) bytes = json_integer_value(b);
							}
							if (val_obj && json_is_object(val_obj)) {
								/* in authlist, IP and MAC are in a concatenation */
								json_t *concat_arr = json_object_get(val_obj, "concat");
								if (json_is_array(concat_arr) && json_array_size(concat_arr) >= 2) {
									ip = json_string_value(json_array_get(concat_arr, 0));
									mac = json_string_value(json_array_get(concat_arr, 1));

									if (ip && mac) {
										client = client_list_find(mac, ip);
										if (client) {
											uint64_t total = bytes;
											if (total > client->counters.outgoing) {
												client->counters.outgoing = total;
												client->counters.last_updated = time(NULL);
											}
										} else {
											debug(LOG_DEBUG, "Upload: Client not found for IP %s MAC %s", ip, mac);
										}
									}										
								}
							}
						}
					} else if (strcmp(sname, "authlist_ip") == 0) {
						/* parse authlist_ip as incoming traffic (download) */
						size_t index_elem = 0;
						json_t *wrapper_elem;
						json_array_foreach(elem_arr, index_elem, wrapper_elem)  {
							json_t *elem_obj = json_object_get(wrapper_elem, "elem");
								json_t *val_obj = json_object_get(elem_obj, "val");
								json_t *counter_obj = json_object_get(elem_obj, "counter");
								uint64_t bytes = 0;
								const char *ip = NULL;
								if (counter_obj) {
									json_t *b = json_object_get(counter_obj, "bytes");
									if (json_is_integer(b)) bytes = json_integer_value(b);
								}
								if (val_obj && json_is_string(val_obj)) {
									/* in authlist_ip, IP is a string without a concatenation */
									ip = json_string_value(val_obj);
									if (ip) {
										client = client_list_find_by_ip(ip);
										if (client) {
											uint64_t total = bytes;
											if (total > client->counters.incoming) {
												client->counters.incoming = total;
												client->counters.last_updated = time(NULL);
											}
										} else {
											debug(LOG_DEBUG, "Download: Client not found for IP %s", ip);
										}
									}
								}
							}
					}
				}
			}
		}
		UNLOCK_CLIENT_LIST();
	}

	json_decref(jroot);
	return 0;
}

