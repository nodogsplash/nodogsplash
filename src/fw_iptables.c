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

/* $Id: fw_iptables.c 1162 2007-01-06 23:51:02Z benoitg $ */
/** @internal
  @file fw_iptables.c
  @brief Firewall iptables functions
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
  @author Copyright (C) 2007 Paul Kube <nodogsplash@kokoro.ucsd.edu>
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/inet.h>

#include "common.h"

#include "safe.h"
#include "conf.h"
#include "auth.h"
#include "client_list.h"
#include "fw_iptables.h"
#include "firewall.h"
#include "debug.h"
#include "util.h"
#include "tc.h"

static char * _iptables_compile(const char[], const char[], t_firewall_rule *);
static int _iptables_append_ruleset(const char[], const char[], const char[]);
static int _iptables_init_marks(void);

extern pthread_mutex_t	client_list_mutex;
extern pthread_mutex_t	config_mutex;

/**
 * Make nonzero to supress the error output of the firewall during destruction.
 */
static int fw_quiet = 0;

/**
 * Used to configure use of --or-mark vs. --set-mark
 */
static const char* markop = "--set-mark";

/**
 * Used to configure use of mark mask, or not
 */
static const char* markmask = "";


/** @internal */
int
_iptables_init_marks()
{
	/* Check FW_MARK values are distinct.  */
	if (FW_MARK_BLOCKED == FW_MARK_TRUSTED ||
			FW_MARK_TRUSTED == FW_MARK_AUTHENTICATED ||
			FW_MARK_AUTHENTICATED == FW_MARK_BLOCKED) {
		debug(LOG_ERR, "FW_MARK_BLOCKED, FW_MARK_TRUSTED, FW_MARK_AUTHENTICATED not distinct values.");
		return -1;
	}

	/* Check FW_MARK values nonzero.  */
	if (FW_MARK_BLOCKED == 0 ||
			FW_MARK_TRUSTED == 0 ||
			FW_MARK_AUTHENTICATED == 0) {
		debug(LOG_ERR, "FW_MARK_BLOCKED, FW_MARK_TRUSTED, FW_MARK_AUTHENTICATED not all nonzero.");
		return -1;
	}

	FW_MARK_PREAUTHENTICATED = 0;  /* always 0 */
	/* FW_MARK_MASK is bitwise OR of other marks */
	FW_MARK_MASK = FW_MARK_BLOCKED | FW_MARK_TRUSTED | FW_MARK_AUTHENTICATED;

	debug(LOG_INFO,"Iptables mark %s: 0x%x",
		  fw_connection_state_as_string(FW_MARK_PREAUTHENTICATED),
		  FW_MARK_PREAUTHENTICATED);
	debug(LOG_INFO,"Iptables mark %s: 0x%x",
		  fw_connection_state_as_string(FW_MARK_AUTHENTICATED),
		  FW_MARK_AUTHENTICATED);
	debug(LOG_INFO,"Iptables mark %s: 0x%x",
		  fw_connection_state_as_string(FW_MARK_TRUSTED),
		  FW_MARK_TRUSTED);
	debug(LOG_INFO,"Iptables mark %s: 0x%x",
		  fw_connection_state_as_string(FW_MARK_BLOCKED),
		  FW_MARK_BLOCKED);

	return 0;
}

/** @internal */
int
_iptables_check_mark_masking()
{
	/* See if kernel supports mark or-ing */
	fw_quiet = 1; /* do it quietly */
	if (0 == iptables_do_command("-t mangle -I PREROUTING 1 -j MARK --or-mark 0x%x", FW_MARK_BLOCKED)) {
		iptables_do_command("-t mangle -D PREROUTING 1"); /* delete test rule we just inserted */
		debug(LOG_DEBUG, "Kernel supports --or-mark.");
		markop = "--or-mark";
	} else {
		debug(LOG_INFO,"Kernel does not support iptables --or-mark.  Using --set-mark instead.");
		markop = "--set-mark";
	}

	/* See if kernel supports mark masking */
	if(0 == iptables_do_command("-t filter -I FORWARD 1 -m mark --mark 0x%x/0x%x -j REJECT", FW_MARK_BLOCKED, FW_MARK_MASK)) {
		iptables_do_command("-t filter -D FORWARD 1"); /* delete test rule we just inserted */
		debug(LOG_DEBUG,"Kernel supports mark masking.");
		char *tmp = NULL;
		safe_asprintf(&tmp,"/0x%x",FW_MARK_MASK);
		markmask = tmp;
	} else {
		debug(LOG_INFO,"Kernel does not support iptables mark masking.  Using empty mask.");
		markmask = "";
	}

	debug(LOG_INFO,"Iptables mark op \"%s\" and mark mask \"%s\".", markop, markmask);

	fw_quiet = 0; /* restore verbosity */

	return 0;
}

/** @internal */
int
iptables_do_command(const char *format, ...)
{
	va_list vlist;
	char *fmt_cmd, *cmd;
	s_config *config;
	int rc;
	int i;

	va_start(vlist, format);
	safe_vasprintf(&fmt_cmd, format, vlist);
	va_end(vlist);

	config = config_get_config();

	if(config->ip6) {
		safe_asprintf(&cmd, "ip6tables %s", fmt_cmd);
	} else {
		safe_asprintf(&cmd, "iptables %s", fmt_cmd);
	}

	free(fmt_cmd);

	debug(LOG_DEBUG, "Executing command: %s", cmd);

	for (i = 0; i < 5; i++) {
		rc = execute(cmd, fw_quiet);
		if (rc == 4) {
			/* iptables error code 4 indicates a resource problem that might
			 * be temporary. So we retry to insert the rule a few times. (Mitar) */
			sleep(1);
		} else {
			break;
		}
	}
	if(!fw_quiet && rc != 0) {
		debug(LOG_ERR, "Nonzero exit status %d from command: %s", rc, cmd);
	}

	free(cmd);

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
_iptables_compile(const char table[], const char chain[], t_firewall_rule *rule)
{
	char command[MAX_BUF];
	char *mode;

	mode = NULL;
	memset(command, 0, MAX_BUF);

	switch (rule->target) {
	case TARGET_DROP:
		mode = safe_strdup("DROP");
		break;
	case TARGET_REJECT:
		mode = safe_strdup("REJECT");
		break;
	case TARGET_ACCEPT:
		mode = safe_strdup("ACCEPT");
		break;
	case TARGET_LOG:
		mode = safe_strdup("LOG");
		break;
	case TARGET_ULOG:
		mode = safe_strdup("ULOG");
		break;
	}

	snprintf(command, sizeof(command),  "-t %s -A %s ",table, chain);
	if (rule->mask != NULL) {
		snprintf((command + strlen(command)),
				 (sizeof(command) - strlen(command)),
				 "-d %s ", rule->mask);
	}
	if (rule->protocol != NULL) {
		snprintf((command + strlen(command)),
				 (sizeof(command) - strlen(command)),
				 "-p %s ", rule->protocol);
	}
	if (rule->port != NULL) {
		snprintf((command + strlen(command)),
				 (sizeof(command) - strlen(command)),
				 "--dport %s ", rule->port);
	}
	snprintf((command + strlen(command)),
			 (sizeof(command) - strlen(command)),
			 "-j %s", mode);

	free(mode);

	/* XXX The buffer command, an automatic variable, will get cleaned
	 * off of the stack when we return, so we strdup() it. */
	return(safe_strdup(command));
}

/**
 * @internal
 * append all the rules in a rule set.
 * @arg ruleset Name of the ruleset
 * @arg table Table containing the chain.
 * @arg chain IPTables chain the rules go into
 */
static int
_iptables_append_ruleset(const char table[], const char ruleset[], const char chain[])
{
	t_firewall_rule *rule;
	char *cmd;
	int ret = 0;

	debug(LOG_DEBUG, "Loading ruleset %s into table %s, chain %s", ruleset, table, chain);

	for (rule = get_ruleset_list(ruleset); rule != NULL; rule = rule->next) {
		cmd = _iptables_compile(table, chain, rule);
		debug(LOG_DEBUG, "Loading rule \"%s\" into table %s, chain %s", cmd, table, chain);
		ret |= iptables_do_command(cmd);
		free(cmd);
	}

	debug(LOG_DEBUG, "Ruleset %s loaded into table %s, chain %s", ruleset, table, chain);
	return ret;
}

int
iptables_block_mac(const char mac[])
{
	return iptables_do_command("-t mangle -A " CHAIN_BLOCKED " -m mac --mac-source %s -j MARK %s 0x%x", mac, markop, FW_MARK_BLOCKED);
}

int
iptables_unblock_mac(const char mac[])
{
	return iptables_do_command("-t mangle -D " CHAIN_BLOCKED " -m mac --mac-source %s -j MARK %s 0x%x", mac, markop, FW_MARK_BLOCKED);
}

int
iptables_allow_mac(const char mac[])
{
	return iptables_do_command("-t mangle -I " CHAIN_BLOCKED " -m mac --mac-source %s -j RETURN", mac);
}

int
iptables_unallow_mac(const char mac[])
{
	return iptables_do_command("-t mangle -D " CHAIN_BLOCKED " -m mac --mac-source %s -j RETURN", mac);
}

int
iptables_trust_mac(const char mac[])
{
	return iptables_do_command("-t mangle -A " CHAIN_TRUSTED " -m mac --mac-source %s -j MARK %s 0x%x", mac, markop, FW_MARK_TRUSTED);
}

int
iptables_untrust_mac(const char mac[])
{
	return iptables_do_command("-t mangle -D " CHAIN_TRUSTED " -m mac --mac-source %s -j MARK %s 0x%x", mac, markop, FW_MARK_TRUSTED);
}

/** Initialize the firewall rules.
 */
int
iptables_fw_init(void)
{
	s_config *config;
	char * gw_interface = NULL;
	char * gw_address = NULL;
	char * gw_iprange = NULL;
	int gw_port = 0;
	int traffic_control;
	int set_mss, mss_value;
	t_MAC *pt;
	t_MAC *pb;
	t_MAC *pa;
	int rc = 0;
	int macmechanism;

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
	FW_MARK_BLOCKED = config->FW_MARK_BLOCKED;
	FW_MARK_TRUSTED = config->FW_MARK_TRUSTED;
	FW_MARK_AUTHENTICATED = config->FW_MARK_AUTHENTICATED;
	UNLOCK_CONFIG();


	/* Set up packet marking methods */
	rc |= _iptables_init_marks();
	rc |= _iptables_check_mark_masking();

	/*
	 *
	 **************************************
	 * Set up mangle table chains and rules
	 *
	 */

	/* Create new chains in the mangle table */
	rc |= iptables_do_command("-t mangle -N " CHAIN_TRUSTED); /* for marking trusted packets */
	rc |= iptables_do_command("-t mangle -N " CHAIN_BLOCKED); /* for marking blocked packets */
	rc |= iptables_do_command("-t mangle -N " CHAIN_INCOMING); /* for counting incoming packets */
	rc |= iptables_do_command("-t mangle -N " CHAIN_OUTGOING); /* for marking authenticated packets, and for counting outgoing packets */

	/* Assign jumps to these new chains */
	rc |= iptables_do_command("-t mangle -I PREROUTING 1 -i %s -s %s -j " CHAIN_OUTGOING, gw_interface, gw_iprange);
	rc |= iptables_do_command("-t mangle -I PREROUTING 2 -i %s -s %s -j " CHAIN_BLOCKED, gw_interface, gw_iprange);
	rc |= iptables_do_command("-t mangle -I PREROUTING 3 -i %s -s %s -j " CHAIN_TRUSTED, gw_interface, gw_iprange);
	rc |= iptables_do_command("-t mangle -I POSTROUTING 1 -o %s -d %s -j " CHAIN_INCOMING, gw_interface, gw_iprange);

	/* Rules to mark as trusted MAC address packets in mangle PREROUTING */
	for (; pt != NULL; pt = pt->next) {
		rc |= iptables_trust_mac(pt->mac);
	}

	/* Rules to mark as blocked MAC address packets in mangle PREROUTING */
	if(MAC_BLOCK == macmechanism) {
		/* with the MAC_BLOCK mechanism,
		 * MAC's on the block list are marked as blocked;
		 * everything else passes */
		for (; pb != NULL; pb = pb->next) {
			rc |= iptables_block_mac(pb->mac);
		}
	} else if(MAC_ALLOW == macmechanism) {
		/* with the MAC_ALLOW mechanism,
		 * MAC's on the allow list pass;
		 * everything else is to be marked as blocked */
		/* So, append at end of chain a rule to mark everything blocked */
		rc |= iptables_do_command("-t mangle -A " CHAIN_BLOCKED " -j MARK %s 0x%x", markop, FW_MARK_BLOCKED);
		/* But insert at beginning of chain rules to pass allowed MAC's */
		for (; pa != NULL; pa = pa->next) {
			rc |= iptables_allow_mac(pa->mac);
		}
	} else {
		debug(LOG_ERR, "Unknown MAC mechanism: %d",
			  macmechanism);
		rc = -1;
	}

	/* Set up for traffic control */
	if(traffic_control) {
		rc |= tc_init_tc();
	}

	/*
	 * End of mangle table chains and rules
	 **************************************
	 */

	/*
	 *
	 **************************************
	 * Set up nat table chains and rules
	 *
	 */

	/* Create new chains in nat table */
	rc |= iptables_do_command("-t nat -N " CHAIN_OUTGOING);

	/*
	 * nat PREROUTING chain
	 */

	/* packets coming in on gw_interface jump to CHAIN_OUTGOING */
	rc |= iptables_do_command("-t nat -I PREROUTING -i %s -s %s -j " CHAIN_OUTGOING, gw_interface, gw_iprange);
	/* CHAIN_OUTGOING, packets marked TRUSTED  ACCEPT */
	rc |= iptables_do_command("-t nat -A " CHAIN_OUTGOING " -m mark --mark 0x%x%s -j ACCEPT", FW_MARK_TRUSTED, markmask);
	/* CHAIN_OUTGOING, packets marked AUTHENTICATED  ACCEPT */
	rc |= iptables_do_command("-t nat -A " CHAIN_OUTGOING " -m mark --mark 0x%x%s -j ACCEPT",FW_MARK_AUTHENTICATED, markmask);
	/* CHAIN_OUTGOING, append the "preauthenticated-users" ruleset */
	rc |= _iptables_append_ruleset("nat", "preauthenticated-users", CHAIN_OUTGOING);

	/* CHAIN_OUTGOING, packets for tcp port 80, redirect to gw_port on primary address for the iface */
	rc |= iptables_do_command("-t nat -A " CHAIN_OUTGOING " -p tcp --dport 80 -j DNAT --to-destination %s:%d", gw_address, gw_port);
	/* CHAIN_OUTGOING, other packets  ACCEPT */
	rc |= iptables_do_command("-t nat -A " CHAIN_OUTGOING " -j ACCEPT");

	/*
	 * End of nat table chains and rules
	 **************************************
	 */

	/*
	 *
	 **************************************
	 * Set up filter table chains and rules
	 *
	 */

	/* Create new chains in the filter table */
	rc |= iptables_do_command("-t filter -N " CHAIN_TO_INTERNET);
	rc |= iptables_do_command("-t filter -N " CHAIN_TO_ROUTER);
	rc |= iptables_do_command("-t filter -N " CHAIN_AUTHENTICATED);
	rc |= iptables_do_command("-t filter -N " CHAIN_TRUSTED);
	rc |= iptables_do_command("-t filter -N " CHAIN_TRUSTED_TO_ROUTER);

	/*
	 * filter INPUT chain
	 */

	/* packets coming in on gw_interface jump to CHAIN_TO_ROUTER */
	rc |= iptables_do_command("-t filter -I INPUT -i %s -s %s -j " CHAIN_TO_ROUTER, gw_interface, gw_iprange);
	/* CHAIN_TO_ROUTER packets marked BLOCKED  DROP */
	rc |= iptables_do_command("-t filter -A " CHAIN_TO_ROUTER " -m mark --mark 0x%x%s -j DROP", FW_MARK_BLOCKED, markmask);
	/* CHAIN_TO_ROUTER, invalid packets  DROP */
	rc |= iptables_do_command("-t filter -A " CHAIN_TO_ROUTER " -m state --state INVALID -j DROP");
	/* CHAIN_TO_ROUTER, related and established packets  ACCEPT */
	rc |= iptables_do_command("-t filter -A " CHAIN_TO_ROUTER " -m state --state RELATED,ESTABLISHED -j ACCEPT");
	/* CHAIN_TO_ROUTER, bogus SYN packets  DROP */
	rc |= iptables_do_command("-t filter -A " CHAIN_TO_ROUTER " -p tcp --tcp-flags SYN SYN \\! --tcp-option 2 -j  DROP");

	/* CHAIN_TO_ROUTER, packets to HTTP listening on gw_port on router ACCEPT */
	rc |= iptables_do_command("-t filter -A " CHAIN_TO_ROUTER " -p tcp --dport %d -j ACCEPT", gw_port);

	/* CHAIN_TO_ROUTER, packets marked TRUSTED: */

	/* if trusted-users-to-router ruleset is empty:
	 *    use empty ruleset policy
	 * else:
	 *    jump to CHAIN_TRUSTED_TO_ROUTER, and load and use users-to-router ruleset
	 */
	if(is_empty_ruleset("trusted-users-to-router")) {
		rc |= iptables_do_command("-t filter -A " CHAIN_TO_ROUTER " -m mark --mark 0x%x%s -j %s", FW_MARK_TRUSTED, markmask, get_empty_ruleset_policy("trusted-users-to-router"));
	} else {
		rc |= iptables_do_command("-t filter -A " CHAIN_TO_ROUTER " -m mark --mark 0x%x%s -j " CHAIN_TRUSTED_TO_ROUTER, FW_MARK_TRUSTED, markmask);
		/* CHAIN_TRUSTED_TO_ROUTER, related and established packets  ACCEPT */
		rc |= iptables_do_command("-t filter -A " CHAIN_TRUSTED_TO_ROUTER " -m state --state RELATED,ESTABLISHED -j ACCEPT");
		/* CHAIN_TRUSTED_TO_ROUTER, append the "trusted-users-to-router" ruleset */
		rc |= _iptables_append_ruleset("filter", "trusted-users-to-router", CHAIN_TRUSTED_TO_ROUTER);
		/* CHAIN_TRUSTED_TO_ROUTER, any packets not matching that ruleset  REJECT */
		rc |= iptables_do_command("-t filter -A " CHAIN_TRUSTED_TO_ROUTER " -j REJECT --reject-with icmp-port-unreachable");
	}

	/* CHAIN_TO_ROUTER, other packets: */

	/* if users-to-router ruleset is empty:
	 *    use empty ruleset policy
	 * else:
	 *    load and use users-to-router ruleset
	 */
	if(is_empty_ruleset("users-to-router")) {
		rc |= iptables_do_command("-t filter -A " CHAIN_TO_ROUTER " -j %s", get_empty_ruleset_policy("users-to-router"));
	} else {
		/* CHAIN_TO_ROUTER, append the "users-to-router" ruleset */
		rc |= _iptables_append_ruleset("filter", "users-to-router", CHAIN_TO_ROUTER);
		/* everything else, REJECT */
		rc |= iptables_do_command("-t filter -A " CHAIN_TO_ROUTER " -j REJECT --reject-with icmp-port-unreachable");

	}

	/*
	 * filter FORWARD chain
	 */

	/* packets coming in on gw_interface jump to CHAIN_TO_INTERNET */
	rc |= iptables_do_command("-t filter -I FORWARD -i %s -s %s -j " CHAIN_TO_INTERNET, gw_interface, gw_iprange);
	/* CHAIN_TO_INTERNET packets marked BLOCKED  DROP */
	rc |= iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -m mark --mark 0x%x%s -j DROP", FW_MARK_BLOCKED, markmask);
	/* CHAIN_TO_INTERNET, invalid packets  DROP */
	rc |= iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -m state --state INVALID -j DROP");
	/* CHAIN_TO_INTERNET, deal with MSS */
	if (set_mss) {
		/* XXX this mangles, so 'should' be done in the mangle POSTROUTING chain.
		 * However OpenWRT standard S35firewall does it in filter FORWARD,
		 * and since we are pre-empting that chain here, we put it in */
		if (mss_value > 0) { /* set specific MSS value */
			rc |= iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss %d", mss_value);
		} else { /* allow MSS as large as possible */
			rc |= iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu");
		}
	}

	/* CHAIN_TO_INTERNET, packets marked TRUSTED: */

	/* if trusted-users ruleset is empty:
	 *    use empty ruleset policy
	 * else:
	 *    jump to CHAIN_TRUSTED, and load and use trusted-users ruleset
	 */
	if(is_empty_ruleset("trusted-users")) {
		rc |= iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -m mark --mark 0x%x%s -j %s", FW_MARK_TRUSTED, markmask, get_empty_ruleset_policy("trusted-users"));
	} else {
		rc |= iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -m mark --mark 0x%x%s -j " CHAIN_TRUSTED, FW_MARK_TRUSTED, markmask);
		/* CHAIN_TRUSTED, related and established packets  ACCEPT */
		rc |= iptables_do_command("-t filter -A " CHAIN_TRUSTED " -m state --state RELATED,ESTABLISHED -j ACCEPT");
		/* CHAIN_TRUSTED, append the "trusted-users" ruleset */
		rc |= _iptables_append_ruleset("filter", "trusted-users", CHAIN_TRUSTED);
		/* CHAIN_TRUSTED, any packets not matching that ruleset  REJECT */
		rc |= iptables_do_command("-t filter -A " CHAIN_TRUSTED " -j REJECT --reject-with icmp-port-unreachable");
	}


	/* CHAIN_TO_INTERNET, packets marked AUTHENTICATED: */

	/* if authenticated-users ruleset is empty:
	 *    use empty ruleset policy
	 * else:
	 *    jump to CHAIN_AUTHENTICATED, and load and use authenticated-users ruleset
	 */
	if(is_empty_ruleset("authenticated-users")) {
		rc |= iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -m mark --mark 0x%x%s -j %s", FW_MARK_AUTHENTICATED, markmask, get_empty_ruleset_policy("authenticated-users"));
	} else {
		rc |= iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -m mark --mark 0x%x%s -j " CHAIN_AUTHENTICATED, FW_MARK_AUTHENTICATED, markmask);
		/* CHAIN_AUTHENTICATED, related and established packets  ACCEPT */
		rc |= iptables_do_command("-t filter -A " CHAIN_AUTHENTICATED " -m state --state RELATED,ESTABLISHED -j ACCEPT");
		/* CHAIN_AUTHENTICATED, append the "authenticated-users" ruleset */
		rc |= _iptables_append_ruleset("filter", "authenticated-users", CHAIN_AUTHENTICATED);
		/* CHAIN_AUTHENTICATED, any packets not matching that ruleset  REJECT */
		rc |= iptables_do_command("-t filter -A " CHAIN_AUTHENTICATED " -j REJECT --reject-with icmp-port-unreachable");
	}

	/* CHAIN_TO_INTERNET, other packets: */

	/* if preauthenticated-users ruleset is empty:
	 *    use empty ruleset policy
	 * else:
	 *    load and use authenticated-users ruleset
	 */
	if(is_empty_ruleset("preauthenticated-users")) {
		rc |= iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -j %s ",  get_empty_ruleset_policy("preauthenticated-users"));
	} else {
		rc |= _iptables_append_ruleset("filter", "preauthenticated-users", CHAIN_TO_INTERNET);
	}
	/* CHAIN_TO_INTERNET, all other packets REJECT */
	rc |= iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -j REJECT --reject-with icmp-port-unreachable");

	/*
	 * End of filter table chains and rules
	 **************************************
	 */

	free(gw_interface);
	free(gw_iprange);
	free(gw_address);

	return rc;
}

/** Remove the firewall rules
 * This is used when we do a clean shutdown of nodogsplash,
 * and when it starts, to make sure there are no rules left over from a crash
 */
int
iptables_fw_destroy(void)
{
	fw_quiet = 1;
	s_config *config;
	int traffic_control;

	LOCK_CONFIG();
	config = config_get_config();
	traffic_control = config->traffic_control;
	UNLOCK_CONFIG();

	if(traffic_control) {
		debug(LOG_DEBUG, "Destroying our tc hooks");
		tc_destroy_tc();
	}

	debug(LOG_DEBUG, "Destroying our iptables entries");

	/*
	 *
	 * Everything in the mangle table
	 *
	 */
	debug(LOG_DEBUG, "Destroying chains in the MANGLE table");
	iptables_fw_destroy_mention("mangle", "PREROUTING", CHAIN_TRUSTED);
	iptables_fw_destroy_mention("mangle", "PREROUTING", CHAIN_BLOCKED);
	iptables_fw_destroy_mention("mangle", "PREROUTING", CHAIN_ALLOWED);
	iptables_fw_destroy_mention("mangle", "PREROUTING", CHAIN_OUTGOING);
	iptables_fw_destroy_mention("mangle", "POSTROUTING", CHAIN_INCOMING);
	iptables_do_command("-t mangle -F " CHAIN_TRUSTED);
	iptables_do_command("-t mangle -F " CHAIN_BLOCKED);
	iptables_do_command("-t mangle -F " CHAIN_ALLOWED);
	iptables_do_command("-t mangle -F " CHAIN_OUTGOING);
	iptables_do_command("-t mangle -F " CHAIN_INCOMING);
	iptables_do_command("-t mangle -X " CHAIN_TRUSTED);
	iptables_do_command("-t mangle -X " CHAIN_BLOCKED);
	iptables_do_command("-t mangle -X " CHAIN_ALLOWED);
	iptables_do_command("-t mangle -X " CHAIN_OUTGOING);
	iptables_do_command("-t mangle -X " CHAIN_INCOMING);

	/*
	 *
	 * Everything in the nat table
	 *
	 */

	debug(LOG_DEBUG, "Destroying chains in the NAT table");
	iptables_fw_destroy_mention("nat", "PREROUTING", CHAIN_OUTGOING);
	iptables_do_command("-t nat -F " CHAIN_OUTGOING);
	iptables_do_command("-t nat -X " CHAIN_OUTGOING);

	/*
	 *
	 * Everything in the filter table
	 *
	 */

	debug(LOG_DEBUG, "Destroying chains in the FILTER table");
	iptables_fw_destroy_mention("filter", "INPUT", CHAIN_TO_ROUTER);
	iptables_fw_destroy_mention("filter", "FORWARD", CHAIN_TO_INTERNET);
	iptables_do_command("-t filter -F " CHAIN_TO_ROUTER);
	iptables_do_command("-t filter -F " CHAIN_TO_INTERNET);
	iptables_do_command("-t filter -F " CHAIN_AUTHENTICATED);
	iptables_do_command("-t filter -F " CHAIN_TRUSTED);
	iptables_do_command("-t filter -F " CHAIN_TRUSTED_TO_ROUTER);
	iptables_do_command("-t filter -X " CHAIN_TO_ROUTER);
	iptables_do_command("-t filter -X " CHAIN_TO_INTERNET);
	iptables_do_command("-t filter -X " CHAIN_AUTHENTICATED);
	iptables_do_command("-t filter -X " CHAIN_TRUSTED);
	iptables_do_command("-t filter -X " CHAIN_TRUSTED_TO_ROUTER);

	return 0;
}

/*
 * Helper for iptables_fw_destroy
 * @param table The table to search
 * @param chain The chain in that table to search
 * @param mention A word to find and delete in rules in the given table+chain
 */
int
iptables_fw_destroy_mention(
	const char * table,
	const char * chain,
	const char * mention
)
{
	FILE *p = NULL;
	char *command = NULL;
	char *command2 = NULL;
	char line[MAX_BUF];
	char rulenum[10];
	int retval = -1;

	debug(LOG_DEBUG, "Checking all mention of %s from %s.%s", mention, table, chain);

	safe_asprintf(&command, "iptables -t %s -L %s -n --line-numbers -v", table, chain);

	if ((p = popen(command, "r"))) {
		/* Skip first 2 lines */
		while (!feof(p) && fgetc(p) != '\n');
		while (!feof(p) && fgetc(p) != '\n');
		/* Loop over entries */
		while (fgets(line, sizeof(line), p)) {
			/* Look for mention */
			if (strstr(line, mention)) {
				/* Found mention - Get the rule number into rulenum*/
				if (sscanf(line, "%9[0-9]", rulenum) == 1) {
					/* Delete the rule: */
					debug(LOG_DEBUG, "Deleting rule %s from %s.%s because it mentions %s", rulenum, table, chain, mention);
					safe_asprintf(&command2, "-t %s -D %s %s", table, chain, rulenum);
					iptables_do_command(command2);
					free(command2);
					retval = 0;
					/* Do not keep looping - the captured rulenums will no longer be accurate */
					break;
				}
			}
		}
		pclose(p);
	}

	free(command);

	if (retval == 0) {
		/* Recurse just in case there are more in the same table+chain */
		iptables_fw_destroy_mention(table, chain, mention);
	}

	return (retval);
}

/** Insert or delete firewall mangle rules marking a client's packets.
 */
int
iptables_fw_access(t_authaction action, t_client *client)
{
	int rc = 0, download_limit, upload_limit, traffic_control;
	s_config *config;
	char *download_imqname, *upload_imqname;

	fw_quiet = 0;

	config = config_get_config();
	safe_asprintf(&download_imqname,"imq%d",config->download_imq); /* must free */
	safe_asprintf(&upload_imqname,"imq%d",config->upload_imq);  /* must free */

	LOCK_CONFIG();
	traffic_control = config->traffic_control;
	download_limit = config->download_limit;
	upload_limit = config->upload_limit;
	UNLOCK_CONFIG();

	if ((client->download_limit > 0) && (client->upload_limit > 0)) {
		download_limit = client->download_limit;
		upload_limit = client->upload_limit;
	}

	switch(action) {
	case AUTH_MAKE_AUTHENTICATED:
		debug(LOG_NOTICE, "Authenticating %s %s", client->ip, client->mac);
		/* This rule is for marking upload (outgoing) packets, and for upload byte counting */
		rc |= iptables_do_command("-t mangle -A " CHAIN_OUTGOING " -s %s -m mac --mac-source %s -j MARK %s 0x%x%x", client->ip, client->mac, markop, client->idx + 10, FW_MARK_AUTHENTICATED);
		rc |= iptables_do_command("-t mangle -A " CHAIN_INCOMING " -d %s -j MARK %s 0x%x%x", client->ip, markop, client->idx + 10, FW_MARK_AUTHENTICATED);
		/* This rule is just for download (incoming) byte counting, see iptables_fw_counters_update() */
		rc |= iptables_do_command("-t mangle -A " CHAIN_INCOMING " -d %s -j ACCEPT", client->ip);
		if(traffic_control) {
			rc |= tc_attach_client(download_imqname, download_limit, upload_imqname, upload_limit, client->idx, FW_MARK_AUTHENTICATED);
		}
		break;
	case AUTH_MAKE_DEAUTHENTICATED:
		/* Remove the authentication rules. */
		debug(LOG_NOTICE, "Deauthenticating %s %s", client->ip, client->mac);
		rc |= iptables_do_command("-t mangle -D " CHAIN_OUTGOING " -s %s -m mac --mac-source %s -j MARK %s 0x%x%x", client->ip, client->mac, markop, client->idx + 10, FW_MARK_AUTHENTICATED);
		rc |= iptables_do_command("-t mangle -D " CHAIN_INCOMING " -d %s -j MARK %s 0x%x%x", client->ip, markop, client->idx + 10, FW_MARK_AUTHENTICATED);
		rc |= iptables_do_command("-t mangle -D " CHAIN_INCOMING " -d %s -j ACCEPT", client->ip);
		if(traffic_control) {
			rc |= tc_detach_client(download_imqname, upload_imqname, client->idx);
		}
		break;
	default:
		rc = -1;
		break;
	}

	free(upload_imqname);
	free(download_imqname);
	return rc;
}

/** Return the total upload usage in bytes */
unsigned long long int
iptables_fw_total_upload()
{
	FILE *output;
	const char *script;
	char target[MAX_BUF];
	int rc;
	unsigned long long int counter;

	/* Look for outgoing traffic */
	script =  "iptables -v -n -x -t mangle -L PREROUTING";
	output = popen(script, "r");
	if (!output) {
		debug(LOG_ERR, "popen(): %s", strerror(errno));
		return 0;
	}

	/* skip the first two lines */
	while (('\n' != fgetc(output)) && !feof(output)) {}
	while (('\n' != fgetc(output)) && !feof(output)) {}

	while ( !(feof(output) )) {
		rc = fscanf(output, "%*d %llu %s ", &counter, target);
		if (2 == rc && !strcmp(target,CHAIN_OUTGOING)) {
			debug(LOG_DEBUG, "Total outgoing Bytes=%llu", counter);
			pclose(output);
			return counter;
		}
		/* eat rest of line */
		while (('\n' != fgetc(output)) && !feof(output)) {}
	}

	pclose(output);
	debug(LOG_ERR, "Can't find target %s in mangle table",CHAIN_OUTGOING);
	return 0;
}

/** Return the total download usage in bytes */
unsigned long long int
iptables_fw_total_download()
{
	FILE *output;
	const char *script;
	char target[MAX_BUF];
	int rc;
	unsigned long long int counter;

	/* Look for incoming traffic */
	script =  "iptables -v -n -x -t mangle -L POSTROUTING";
	output = popen(script, "r");
	if (!output) {
		debug(LOG_ERR, "popen(): %s", strerror(errno));
		return 0;
	}

	/* skip the first two lines */
	while (('\n' != fgetc(output)) && !feof(output)) {}
	while (('\n' != fgetc(output)) && !feof(output)) {}

	while ( !(feof(output) )) {
		rc = fscanf(output, "%*s %llu %s ", &counter, target);
		if (2 == rc && !strcmp(target,CHAIN_INCOMING)) {
			debug(LOG_DEBUG, "Total incoming Bytes=%llu", counter);
			pclose(output);
			return counter;
		}
		/* eat rest of line */
		while (('\n' != fgetc(output)) && !feof(output)) {}
	}

	pclose(output);
	debug(LOG_ERR, "Can't find target %s in mangle table",CHAIN_INCOMING);
	return 0;
}

/** Update the counters of all the clients in the client list */
int
iptables_fw_counters_update(void)
{
	FILE *output;
	char *script,
		 ip[INET6_ADDRSTRLEN],
		 target[MAX_BUF];
	int rc;
	int af;
	s_config *config;
	unsigned long long int counter;
	t_client *p1;
	struct sockaddr_storage tempaddr;

	config = config_get_config();
	af = config->ip6 ? AF_INET6 : AF_INET;

	/* Look for outgoing traffic */
	safe_asprintf(&script, "%s %s", "iptables", "-v -n -x -t mangle -L " CHAIN_OUTGOING);
	output = popen(script, "r");
	free(script);
	if (!output) {
		debug(LOG_ERR, "popen(): %s", strerror(errno));
		return -1;
	}

	/* skip the first two lines */
	while (('\n' != fgetc(output)) && !feof(output)) {}
	while (('\n' != fgetc(output)) && !feof(output)) {}

	while ( !(feof(output) )) {
		rc = fscanf(output, "%*s %llu %s %*s %*s %*s %*s %15[0-9.]", &counter,target,ip);
		/* eat rest of line */
		while (('\n' != fgetc(output)) && !feof(output)) {}
		if (3 == rc && !strcmp(target,"MARK")) {
			/* Sanity*/
			if (!inet_pton(af, ip, &tempaddr)) {
				debug(LOG_WARNING, "I was supposed to read an IP address but instead got [%s] - ignoring it", ip);
				continue;
			}
			debug(LOG_DEBUG, "Read outgoing traffic for %s: Bytes=%llu", ip, counter);
			LOCK_CLIENT_LIST();
			if ((p1 = client_list_find_by_ip(ip))) {
				if ((p1->counters.outgoing - p1->counters.outgoing_history) < counter) {
					p1->counters.outgoing = p1->counters.outgoing_history + counter;
					p1->counters.last_updated = time(NULL);
					debug(LOG_DEBUG, "%s - Updated counter.outgoing to %llu bytes.  Updated last_updated to %d", ip, counter, p1->counters.last_updated);
				}
			} else {
				debug(LOG_WARNING, "Could not find %s in client list", ip);
			}
			UNLOCK_CLIENT_LIST();
		}
	}
	pclose(output);

	/* Look for incoming traffic */
	safe_asprintf(&script, "%s %s", "iptables", "-v -n -x -t mangle -L " CHAIN_INCOMING);
	output = popen(script, "r");
	free(script);
	if (!output) {
		debug(LOG_ERR, "popen(): %s", strerror(errno));
		return -1;
	}

	/* skip the first two lines */
	while (('\n' != fgetc(output)) && !feof(output)) {}
	while (('\n' != fgetc(output)) && !feof(output)) {}

	while ( !(feof(output) )) {
		rc = fscanf(output, "%*s %llu %s %*s %*s %*s %*s %*s %15[0-9.]", &counter,target,ip);
		/* eat rest of line */
		while (('\n' != fgetc(output)) && !feof(output)) {}
		if (3 == rc && !strcmp(target,"ACCEPT")) {
			/* Sanity*/
			if (!inet_pton(af, ip, &tempaddr)) {
				debug(LOG_WARNING, "I was supposed to read an IP address but instead got [%s] - ignoring it", ip);
				continue;
			}
			debug(LOG_DEBUG, "Read incoming traffic for %s: Bytes=%llu", ip, counter);
			LOCK_CLIENT_LIST();
			if ((p1 = client_list_find_by_ip(ip))) {
				if ((p1->counters.incoming - p1->counters.incoming_history) < counter) {
					p1->counters.incoming = p1->counters.incoming_history + counter;
					debug(LOG_DEBUG, "%s - Updated counter.incoming to %llu bytes", ip, counter);
				}
			} else {
				debug(LOG_WARNING, "Could not find %s in client list", ip);
			}
			UNLOCK_CLIENT_LIST();
		}
	}
	pclose(output);

	return 0;
}
