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

#include "common.h"

#include "safe.h"
#include "conf.h"
#include "auth.h"
#include "fw_iptables.h"
#include "firewall.h"
#include "debug.h"
#include "util.h"
#include "client_list.h"
#include "tc.h"

static int iptables_do_command(char *format, ...);
static char *iptables_compile(char *, char *, t_firewall_rule *);
static int iptables_load_ruleset(char *, char *, char *);

extern pthread_mutex_t	client_list_mutex;
extern pthread_mutex_t	config_mutex;

/**
 * Make nonzero to supress the error output of the firewall during destruction.
 */ 
static int fw_quiet = 0;

/** @internal */
static int
iptables_do_command(char *format, ...) {
  va_list vlist;
  char *fmt_cmd,
    *cmd;
  int rc;

  va_start(vlist, format);
  safe_vasprintf(&fmt_cmd, format, vlist);
  va_end(vlist);

  safe_asprintf(&cmd, "iptables %s", fmt_cmd);

  free(fmt_cmd);

  debug(LOG_DEBUG, "Executing command: %s", cmd);
	
  rc = execute(cmd, fw_quiet);
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
iptables_compile(char * table, char *chain, t_firewall_rule *rule)
{
    char	command[MAX_BUF],
    		*mode;
    
    memset(command, 0, MAX_BUF);
    
    if (rule->block_allow == 1) {
        mode = safe_strdup("ACCEPT");
    } else {
        mode = safe_strdup("REJECT");
    }
    
    snprintf(command, sizeof(command),  "-t %s -A %s ",table, chain);
    if (rule->mask != NULL) {
        snprintf((command + strlen(command)), (sizeof(command) - 
                strlen(command)), "-d %s ", rule->mask);
    }
    if (rule->protocol != NULL) {
        snprintf((command + strlen(command)), (sizeof(command) -
                strlen(command)), "-p %s ", rule->protocol);
    }
    if (rule->port != NULL) {
        snprintf((command + strlen(command)), (sizeof(command) -
                strlen(command)), "--dport %s ", rule->port);
    }
    snprintf((command + strlen(command)), (sizeof(command) - 
            strlen(command)), "-j %s", mode);
    
    free(mode);

    /* XXX The buffer command, an automatic variable, will get cleaned
     * off of the stack when we return, so we strdup() it. */
    return(safe_strdup(command));
}

/**
 * @internal
 * Load all the rules in a rule set.
 * @arg ruleset Name of the ruleset
 * @arg table Table containing the chain.
 * @arg chain IPTables chain the rules go into
 */
static int
iptables_load_ruleset(char * table, char *ruleset, char *chain) {
  t_firewall_rule   *rule;
  char		    *cmd;
  int               ret=0;

  debug(LOG_DEBUG, "Load ruleset %s into table %s, chain %s", ruleset, table, chain);
	
  for (rule = get_ruleset(ruleset); rule != NULL; rule = rule->next) {
    cmd = iptables_compile(table, chain, rule);
    debug(LOG_DEBUG, "Loading rule \"%s\" into table %s, chain %s", cmd, table, chain);
    ret |= iptables_do_command(cmd);
    free(cmd);
  }

  debug(LOG_DEBUG, "Ruleset %s loaded into table %s, chain %s", ruleset, table, chain);
  return ret;
  
}



/** Initialize the firewall rules
 */
int
iptables_fw_init(void) {
  s_config *config;
  char * gw_interface = NULL;
  char * gw_address = NULL;
  int gw_port = 0;
  int traffic_control, upload_limit, download_limit;
  int upload_imq, download_imq;
  char *upload_imqname, *download_imqname;
  char *cmd;
  t_MAC *pt;
  t_MAC *pb;
  int rc=0, ret;
   
  fw_quiet = 0;

  LOCK_CONFIG();
  config = config_get_config();
  gw_interface = safe_strdup(config->gw_interface); /* must free */
  gw_address = safe_strdup(config->gw_address);    /* must free */
  gw_port = config->gw_port;
  pt = config->trustedmaclist;
  pb = config->blockedmaclist;
  traffic_control = config->traffic_control;
  download_limit = config->download_limit;
  upload_limit = config->upload_limit;
  download_imq = config->download_imq;
  upload_imq = config->upload_imq;
  UNLOCK_CONFIG();
    
  safe_asprintf(&download_imqname,"imq%d",download_imq); /* must free */
  safe_asprintf(&upload_imqname,"imq%d",upload_imq);  /* must free */

  /*
   *
   * Everything in the mangle table
   *
   */

  /* Create new chains in the mangle table */
  rc |= iptables_do_command("-t mangle -N " CHAIN_TRUSTED);
  rc |= iptables_do_command("-t mangle -N " CHAIN_BLOCKED);
  rc |= iptables_do_command("-t mangle -N " CHAIN_INCOMING);
  rc |= iptables_do_command("-t mangle -N " CHAIN_OUTGOING);

  /* Assign links and rules to these new chains */
  rc |= iptables_do_command("-t mangle -I PREROUTING 1 -i %s -j " CHAIN_OUTGOING, gw_interface);
  rc |= iptables_do_command("-t mangle -I PREROUTING 2 -i %s -j " CHAIN_TRUSTED, gw_interface);
  rc |= iptables_do_command("-t mangle -I PREROUTING 3 -i %s -j " CHAIN_BLOCKED, gw_interface);
  rc |= iptables_do_command("-t mangle -I POSTROUTING 1 -o %s -j " CHAIN_INCOMING, gw_interface);

  /* Rules to mark trusted MAC address packets in mangle PREROUTING */
  for (; pt != NULL; pt = pt->next)
    rc |= iptables_do_command("-t mangle -A " CHAIN_TRUSTED " -m mac --mac-source %s -j MARK --set-mark 0x%x", pt->mac, FW_MARK_TRUSTED);

  /* Rules to mark blocked MAC address packets in mangle PREROUTING */
  for (; pb != NULL; pb = pb->next)
    rc |= iptables_do_command("-t mangle -A " CHAIN_BLOCKED " -m mac --mac-source %s -j MARK --set-mark 0x%x", pb->mac, FW_MARK_BLOCKED);

  /* Set up for traffic control */
  if(traffic_control) {
    if(download_limit > 0) {
      safe_asprintf(&cmd,"ip link set %s up", download_imqname);
      ret = execute(cmd ,fw_quiet);
      free(cmd);
      if( ret != 0 ) {
	debug(LOG_ERR, "Could not set %s up. Download limiting will not work",
	      download_imqname);
	rc = -1;
      } else {
	/* jump to the imq in mangle CHAIN_INCOMING */
	rc |= iptables_do_command("-t mangle -A " CHAIN_INCOMING " -j IMQ --todev %d ", download_imq);
	/* attach download shaping qdisc to this imq */
	rc |= tc_attach_download_qdisc(download_imqname,download_limit);
      }
    }
     if(upload_limit > 0) {
      safe_asprintf(&cmd,"ip link set %s up", upload_imqname);
      ret = execute(cmd ,fw_quiet);
      free(cmd);
       if( ret != 0 ) {
	 debug(LOG_ERR, "Could not set %s up. Upload limiting will not work",
	       upload_imqname);
	 rc = -1;
       } else {
	 /* jump to the imq in mangle CHAIN_OUTGOING */
	 rc |= iptables_do_command("-t mangle -A " CHAIN_OUTGOING " -j IMQ --todev %d ", upload_imq);
	 /* attach upload shaping qdisc to this imq */
	 rc |= tc_attach_upload_qdisc(upload_imqname,upload_limit);
       }
     }
  }

  /*
   *
   * Everything in the nat table
   *
   */

  /* Create new chains in nat table */
  rc |= iptables_do_command("-t nat -N " CHAIN_OUTGOING);
  /*
   * nat PREROUTING
   */
  /* packets coming in on gw_interface jump to CHAIN_OUTGOING */
  rc |= iptables_do_command("-t nat -I PREROUTING -i %s -j " CHAIN_OUTGOING, gw_interface);
  /* CHAIN_OUTGOING, packets marked TRUSTED  ACCEPT */
  rc |= iptables_do_command("-t nat -A " CHAIN_OUTGOING " -m mark --mark 0x%x -j ACCEPT", FW_MARK_TRUSTED);
  /* CHAIN_OUTGOING, packets marked AUTHENTICATED  ACCEPT */
  rc |= iptables_do_command("-t nat -A " CHAIN_OUTGOING " -m mark --mark 0x%x -j ACCEPT", FW_MARK_AUTHENTICATED);
  /* CHAIN_OUTGOING, packets for tcp port 80, redirect to gw_port on primary address for the iface */
  rc |= iptables_do_command("-t nat -A " CHAIN_OUTGOING " -p tcp --dport 80 -j DNAT --to-destination %s:%d", gw_address, gw_port);
  /* DNAT may be more 'portable' than REDIRECT, so use DNAT
    rc |= iptables_do_command("-t nat -A " CHAIN_OUTGOING " -p tcp --dport 80 -j REDIRECT --to-ports %d", gw_port); */
  /* CHAIN_OUTGOING, other packets  ACCEPT */
  rc |= iptables_do_command("-t nat -A " CHAIN_OUTGOING " -j ACCEPT");


  /*
   *
   * Everything in the filter table
   *
   */

  /* Create new chains in the filter table */
  rc |= iptables_do_command("-t filter -N " CHAIN_TO_INTERNET);
  rc |= iptables_do_command("-t filter -N " CHAIN_TO_ROUTER);
  rc |= iptables_do_command("-t filter -N " CHAIN_AUTHENTICATED);

  /*
   * filter INPUT
   */
  /* packets coming in on gw_interface jump to CHAIN_TO_ROUTER */
  rc |= iptables_do_command("-t filter -I INPUT -i %s -j " CHAIN_TO_ROUTER, gw_interface);
  /* CHAIN_TO_ROUTER packets marked BLOCKED  DROP */
  rc |= iptables_do_command("-t filter -A " CHAIN_TO_ROUTER " -m mark --mark 0x%x -j DROP", FW_MARK_BLOCKED);
  /* CHAIN_TO_ROUTER, invalid packets  DROP */
  rc |= iptables_do_command("-t filter -A " CHAIN_TO_ROUTER " -m state --state INVALID -j DROP");
  /* CHAIN_TO_ROUTER, related and established packets  ACCEPT */
  rc |= iptables_do_command("-t filter -A " CHAIN_TO_ROUTER " -m state --state RELATED,ESTABLISHED -j ACCEPT");
  /* CHAIN_TO_ROUTER, bogus SYN packets  DROP */
  rc |= iptables_do_command("-t filter -A " CHAIN_TO_ROUTER " -p tcp --tcp-flags SYN SYN --tcp-option \\! 2 -j  DROP");
  /* CHAIN_TO_ROUTER, packets marked TRUSTED  ACCEPT */
  rc |= iptables_do_command("-t filter -A " CHAIN_TO_ROUTER " -m mark --mark 0x%x -j ACCEPT", FW_MARK_TRUSTED);
  /* CHAIN_TO_ROUTER, packets to HTTP listening on gw_port on router ACCEPT */
  rc |= iptables_do_command("-t filter -A " CHAIN_TO_ROUTER " -p tcp --dport %d -j ACCEPT", gw_port);
  /* CHAIN_TO_ROUTER, load the "users-to-router" ruleset */
  rc |= iptables_load_ruleset("filter", "users-to-router", CHAIN_TO_ROUTER);
  rc |= iptables_do_command("-t filter -A " CHAIN_TO_ROUTER " -j REJECT --reject-with icmp-port-unreachable");


  /*
   * filter FORWARD
   */
  /* packets coming in on gw_interface jump to CHAIN_TO_INTERNET */
  rc |= iptables_do_command("-t filter -I FORWARD -i %s -j " CHAIN_TO_INTERNET, gw_interface);
  /* CHAIN_TO_INTERNET packets marked BLOCKED  DROP */
  rc |= iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -m mark --mark 0x%x -j DROP", FW_MARK_BLOCKED);
  /* CHAIN_TO_INTERNET, invalid packets  DROP */
  rc |= iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -m state --state INVALID -j DROP");
  /* CHAIN_TO_INTERNET, allow MSS as large as possible */
  /* XXX this mangles, so 'should' be done in the mangle POSTROUTING chain.
   * However OpenWRT standard S35firewall does it in filter FORWARD, and since
   * we are pre-empting that chain here, we put it in */
  rc |= iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu");
  /* CHAIN_TO_INTERNET, packets marked TRUSTED  ACCEPT */
  rc |= iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -m mark --mark 0x%x -j ACCEPT", FW_MARK_TRUSTED);
  /* CHAIN_TO_INTERNET, all packets tcp/udp to DNS (port 53) ACCEPT */
  rc |= iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -p tcp --dport 53 -j ACCEPT");
  rc |= iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -p udp --dport 53 -j ACCEPT");
  /* CHAIN_TO_INTERNET, packets marked AUTHENTICATED jump to CHAIN_AUTHENTICATED */
  rc |= iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -m mark --mark 0x%x -j " CHAIN_AUTHENTICATED, FW_MARK_AUTHENTICATED);
  /* CHAIN_AUTHENTICATED, related and established packets  ACCEPT */
  rc |= iptables_do_command("-t filter -A " CHAIN_AUTHENTICATED " -m state --state RELATED,ESTABLISHED -j ACCEPT");
  /* CHAIN_AUTHENTICATED, load the "authenticated-users" ruleset */
  rc |= iptables_load_ruleset("filter", "authenticated-users", CHAIN_AUTHENTICATED);
  /* CHAIN_AUTHENTICATED, any packets not matching that ruleset  REJECT */
  rc |= iptables_do_command("-t filter -A " CHAIN_AUTHENTICATED " -j REJECT --reject-with icmp-port-unreachable");
  /* CHAIN_TO_INTERNET, all other packets REJECT */
  rc |= iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -j REJECT --reject-with icmp-port-unreachable");

  free(gw_interface);
  free(gw_address);
  free(download_imqname);
  free(upload_imqname);
  return rc;
}

/** Remove the firewall rules
 * This is used when we do a clean shutdown of nodogsplash, and when it starts, to make
 * sure there are no rules left over
 */
int
iptables_fw_destroy(void) {
  fw_quiet = 1;

  debug(LOG_DEBUG, "Destroying our tc hooks");

  tc_destroy_tc();

  debug(LOG_DEBUG, "Destroying our iptables entries");

  /*
   *
   * Everything in the mangle table
   *
   */
  debug(LOG_DEBUG, "Destroying chains in the MANGLE table");
  iptables_fw_destroy_mention("mangle", "PREROUTING", CHAIN_TRUSTED);
  iptables_fw_destroy_mention("mangle", "PREROUTING", CHAIN_BLOCKED);
  iptables_fw_destroy_mention("mangle", "PREROUTING", CHAIN_OUTGOING);
  iptables_fw_destroy_mention("mangle", "POSTROUTING", CHAIN_INCOMING);
  iptables_do_command("-t mangle -F " CHAIN_TRUSTED);
  iptables_do_command("-t mangle -F " CHAIN_BLOCKED);
  iptables_do_command("-t mangle -F " CHAIN_OUTGOING);
  iptables_do_command("-t mangle -F " CHAIN_INCOMING);
  iptables_do_command("-t mangle -X " CHAIN_TRUSTED);
  iptables_do_command("-t mangle -X " CHAIN_BLOCKED);
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
  iptables_do_command("-t filter -X " CHAIN_TO_ROUTER);
  iptables_do_command("-t filter -X " CHAIN_TO_INTERNET);
  iptables_do_command("-t filter -X " CHAIN_AUTHENTICATED);

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
		char * table,
		char * chain,
		char * mention
) {
  FILE *p = NULL;
  char *command = NULL;
  char *command2 = NULL;
  char line[MAX_BUF];
  char rulenum[10];
  int retval = -1;

  debug(LOG_DEBUG, "Attempting to destroy all mention of %s from %s.%s", mention, table, chain);

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
iptables_fw_access(t_authaction action, char *ip, char *mac) {
  int rc;

  fw_quiet = 0;

  switch(action) {
  case AUTH_MAKE_AUTHENTICATED:
    /* This rule is for marking upload packets, and for upload byte counting */
    rc = iptables_do_command("-t mangle -A " CHAIN_OUTGOING " -s %s -m mac --mac-source %s -j MARK --set-mark 0x%x", ip, mac, FW_MARK_AUTHENTICATED);
    /* This rule is just for download byte counting, see iptables_fw_counters_update() */
    rc = iptables_do_command("-t mangle -A " CHAIN_INCOMING " -d %s -j ACCEPT", ip);
    break;
  case AUTH_MAKE_DEAUTHENTICATED:
    /* Remove the authentication rules. */
    rc = iptables_do_command("-t mangle -D " CHAIN_OUTGOING " -s %s -m mac --mac-source %s -j MARK --set-mark 0x%x", ip, mac, FW_MARK_AUTHENTICATED);
    rc = iptables_do_command("-t mangle -D " CHAIN_INCOMING " -d %s -j ACCEPT", ip);
    break;
  default:
    rc = -1;
    break;
  }

  return rc;
}

/** Return the total upload usage in bytes */
unsigned long long int
iptables_fw_total_upload() {
  FILE *output;
  char *script,
    target[MAX_BUF];
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
    rc = fscanf(output, "%*s %llu %s ", &counter,target);
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
iptables_fw_total_download() {
  FILE *output;
  char *script,
    target[MAX_BUF];
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
iptables_fw_counters_update(void) {
  FILE *output;
  char *script,
    ip[16],
    target[MAX_BUF];
  int rc;
  unsigned long long int counter;
  t_client *p1;
  struct in_addr tempaddr;

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
      if (!inet_aton(ip, &tempaddr)) {
	debug(LOG_WARNING, "I was supposed to read an IP address but instead got [%s] - ignoring it", ip);
	continue;
      }
      debug(LOG_DEBUG, "Outgoing %s Bytes=%llu", ip, counter);
      LOCK_CLIENT_LIST();
      if ((p1 = client_list_find_by_ip(ip))) {
	if ((p1->counters.outgoing - p1->counters.outgoing_history) < counter) {
	  p1->counters.outgoing = p1->counters.outgoing_history + counter;
	  p1->counters.last_updated = time(NULL);
	  debug(LOG_DEBUG, "%s - Updated counter.outgoing to %llu bytes", ip, counter);
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
      if (!inet_aton(ip, &tempaddr)) {
	debug(LOG_WARNING, "I was supposed to read an IP address but instead got [%s] - ignoring it", ip);
	continue;
      }
      debug(LOG_DEBUG, "Incoming %s Bytes=%llu", ip, counter);
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
