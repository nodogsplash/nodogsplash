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

/** @file conf.c
  @brief Config file parsing
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
  @author Copyright (C) 2007 Paul Kube <nodogsplash@kokoro.ucsd.edu>
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

#include <pthread.h>

#include <string.h>
#include <ctype.h>

#include "common.h"
#include "safe.h"
#include "debug.h"
#include "conf.h"
#include "auth.h"
#include "firewall.h"

#include "util.h"


/** @internal
 * Holds the current configuration of the gateway */
static s_config config = { 0 };

/**
 * Mutex for the configuration file, used by the auth_servers related
 * functions. */
pthread_mutex_t config_mutex = PTHREAD_MUTEX_INITIALIZER;

/** @internal
 * A flag.  If set to 1, there are missing or empty mandatory parameters in the config
 */
static int missing_parms;

/** @internal
 The different configuration options */
typedef enum {
	oBadOption,
	oDaemon,
	oDebugLevel,
	oMaxClients,
	oGatewayName,
	oGatewayInterface,
	oGatewayIPRange,
	oGatewayAddress,
	oGatewayPort,
	oRemoteAuthenticatorAction,
	oEnablePreAuth,
	oBinVoucher,
	oForceVoucher,
	oPasswordAuthentication,
	oUsernameAuthentication,
	oPasswordAttempts,
	oUsername,
	oPassword,
	oHTTPDMaxConn,
	oWebRoot,
	oSplashPage,
	oImagesDir,
	oPagesDir,
	oRedirectURL,
	oClientIdleTimeout,
	oClientForceTimeout,
	oCheckInterval,
	oSetMSS,
	oMSSValue,
	oTrafficControl,
	oDownloadLimit,
	oUploadLimit,
	oDownloadIMQ,
	oUploadIMQ,
	oNdsctlSocket,
	oDecongestHttpdThreads,
	oHttpdThreadThreshold,
	oHttpdThreadDelayMS,
	oSyslogFacility,
	oFirewallRule,
	oFirewallRuleSet,
	oEmptyRuleSetPolicy,
	oMACmechanism,
	oTrustedMACList,
	oBlockedMACList,
	oAllowedMACList,
	oFWMarkAuthenticated,
	oFWMarkTrusted,
	oFWMarkBlocked
} OpCodes;

/** @internal
 The config file keywords for the different configuration options */
static const struct {
	const char *name;
	OpCodes opcode;
	int required;
} keywords[] = {
	{ "daemon", oDaemon },
	{ "debuglevel", oDebugLevel },
	{ "maxclients", oMaxClients },
	{ "gatewayname", oGatewayName },
	{ "gatewayinterface", oGatewayInterface },
	{ "gatewayiprange", oGatewayIPRange },
	{ "gatewayaddress", oGatewayAddress },
	{ "gatewayport", oGatewayPort },
	{ "remoteauthenticatoraction", oRemoteAuthenticatorAction },
	{ "enablepreauth", oEnablePreAuth },
	{ "binvoucher", oBinVoucher },
	{ "forcevoucher", oForceVoucher },
	{ "passwordauthentication", oPasswordAuthentication },
	{ "usernameauthentication", oUsernameAuthentication },
	{ "passwordattempts", oPasswordAttempts },
	{ "username", oUsername },
	{ "password", oPassword },
	{ "webroot", oWebRoot },
	{ "splashpage", oSplashPage },
	{ "imagesdir", oImagesDir },
	{ "pagesdir", oPagesDir },
	{ "redirectURL", oRedirectURL },
	{ "clientidletimeout", oClientIdleTimeout },
	{ "clientforcetimeout", oClientForceTimeout },
	{ "checkinterval", oCheckInterval },
	{ "setmss", oSetMSS },
	{ "mssvalue", oMSSValue },
	{ "trafficcontrol",	oTrafficControl },
	{ "downloadlimit", oDownloadLimit },
	{ "uploadlimit", oUploadLimit },
	{ "downloadimq", oDownloadIMQ },
	{ "uploadimq", oUploadIMQ },
	{ "syslogfacility", oSyslogFacility },
	{ "ndsctlsocket", oNdsctlSocket },
	{ "decongesthttpdthreads", oDecongestHttpdThreads },
	{ "httpdthreadthreshold", oHttpdThreadThreshold },
	{ "httpdthreaddelayms", oHttpdThreadDelayMS },
	{ "firewallruleset", oFirewallRuleSet },
	{ "firewallrule", oFirewallRule },
	{ "emptyrulesetpolicy", oEmptyRuleSetPolicy },
	{ "trustedmaclist", oTrustedMACList },
	{ "blockedmaclist", oBlockedMACList },
	{ "allowedmaclist", oAllowedMACList },
	{ "MACmechanism", oMACmechanism },
	{ "FW_MARK_AUTHENTICATED", oFWMarkAuthenticated },
	{ "FW_MARK_TRUSTED", oFWMarkTrusted },
	{ "FW_MARK_BLOCKED", oFWMarkBlocked },
	{ NULL, oBadOption },
};

static void config_notnull(const void *parm, const char *parmname);
static int parse_boolean_value(char *);
static int _parse_firewall_rule(t_firewall_ruleset *ruleset, char *leftover);
static void parse_firewall_ruleset(const char *, FILE *, const char *, int *);

static OpCodes config_parse_opcode(const char *cp, const char *filename, int linenum);

/** @internal
Strip comments and leading and trailing whitespace from a string.
Return a pointer to the first nonspace char in the string.
*/
static char* _strip_whitespace(char* p1);

/** Accessor for the current gateway configuration
@return:  A pointer to the current config.  The pointer isn't opaque, but should be treated as READ-ONLY
 */
s_config *
config_get_config(void)
{
	return &config;
}

/** Sets the default config parameters and initialises the configuration system */
void
config_init(void)
{
	t_firewall_ruleset *rs;

	debug(LOG_DEBUG, "Setting default config parameters");
	strncpy(config.configfile, DEFAULT_CONFIGFILE, sizeof(config.configfile)-1);
	config.debuglevel = DEFAULT_DEBUGLEVEL;
	config.maxclients = DEFAULT_MAXCLIENTS;
	config.gw_name = safe_strdup(DEFAULT_GATEWAYNAME);
	config.gw_interface = NULL;
	config.gw_iprange = safe_strdup(DEFAULT_GATEWAY_IPRANGE);
	config.gw_address = NULL;
	config.gw_port = DEFAULT_GATEWAYPORT;
	config.remote_auth_action = NULL;
	config.webroot = safe_strdup(DEFAULT_WEBROOT);
	config.splashpage = safe_strdup(DEFAULT_SPLASHPAGE);
	config.infoskelpage = safe_strdup(DEFAULT_INFOSKELPAGE);
	config.imagesdir = safe_strdup(DEFAULT_IMAGESDIR);
	config.pagesdir = safe_strdup(DEFAULT_PAGESDIR);
	config.authdir = safe_strdup(DEFAULT_AUTHDIR);
	config.denydir = safe_strdup(DEFAULT_DENYDIR);
	config.redirectURL = NULL;
	config.clienttimeout = DEFAULT_CLIENTTIMEOUT;
	config.clientforceout = DEFAULT_CLIENTFORCEOUT;
	config.checkinterval = DEFAULT_CHECKINTERVAL;
	config.daemon = -1;
	config.passwordauth = DEFAULT_PASSWORD_AUTH;
	config.usernameauth = DEFAULT_USERNAME_AUTH;
	config.passwordattempts = DEFAULT_PASSWORD_ATTEMPTS;
	config.username = NULL;
	config.password = NULL;
	config.authenticate_immediately = DEFAULT_AUTHENTICATE_IMMEDIATELY;
	config.set_mss = DEFAULT_SET_MSS;
	config.mss_value = DEFAULT_MSS_VALUE;
	config.traffic_control = DEFAULT_TRAFFIC_CONTROL;
	config.upload_limit =  DEFAULT_UPLOAD_LIMIT;
	config.download_limit = DEFAULT_DOWNLOAD_LIMIT;
	config.upload_imq =  DEFAULT_UPLOAD_IMQ;
	config.download_imq = DEFAULT_DOWNLOAD_IMQ;
	config.syslog_facility = DEFAULT_SYSLOG_FACILITY;
	config.log_syslog = DEFAULT_LOG_SYSLOG;
	config.ndsctl_sock = safe_strdup(DEFAULT_NDSCTL_SOCK);
	config.internal_sock = safe_strdup(DEFAULT_INTERNAL_SOCK);
	config.decongest_httpd_threads = DEFAULT_DECONGEST_HTTPD_THREADS;
	config.httpd_thread_threshold = DEFAULT_HTTPD_THREAD_THRESHOLD;
	config.httpd_thread_delay_ms = DEFAULT_HTTPD_THREAD_DELAY_MS;
	config.rulesets = NULL;
	config.trustedmaclist = NULL;
	config.blockedmaclist = NULL;
	config.allowedmaclist = NULL;
	config.macmechanism = DEFAULT_MACMECHANISM;
	config.FW_MARK_AUTHENTICATED = DEFAULT_FW_MARK_AUTHENTICATED;
	config.FW_MARK_TRUSTED = DEFAULT_FW_MARK_TRUSTED;
	config.FW_MARK_BLOCKED = DEFAULT_FW_MARK_BLOCKED;
	config.ip6 = DEFAULT_IP6;

	/* Set up default FirewallRuleSets, and their empty ruleset policies */
	rs = add_ruleset("trusted-users");
	rs->emptyrulesetpolicy = safe_strdup(DEFAULT_EMPTY_TRUSTED_USERS_POLICY);
	rs = add_ruleset("trusted-users-to-router");
	rs->emptyrulesetpolicy = safe_strdup(DEFAULT_EMPTY_TRUSTED_USERS_TO_ROUTER_POLICY);
	rs = add_ruleset("users-to-router");
	rs->emptyrulesetpolicy = safe_strdup(DEFAULT_EMPTY_USERS_TO_ROUTER_POLICY);
	rs = add_ruleset("authenticated-users");
	rs->emptyrulesetpolicy = safe_strdup(DEFAULT_EMPTY_AUTHENTICATED_USERS_POLICY);
	rs = add_ruleset("preauthenticated-users");
	rs->emptyrulesetpolicy = safe_strdup(DEFAULT_EMPTY_PREAUTHENTICATED_USERS_POLICY);
}

/**
 * If the command-line didn't specify a config, use the default.
 */
void
config_init_override(void)
{
	if (config.daemon == -1) config.daemon = DEFAULT_DAEMON;
}

/** @internal
Attempts to parse an opcode from the config file
*/
static OpCodes
config_parse_opcode(const char *cp, const char *filename, int linenum)
{
	int i;

	for (i = 0; keywords[i].name; i++)
		if (strcasecmp(cp, keywords[i].name) == 0)
			return keywords[i].opcode;

	debug(LOG_ERR, "%s: line %d: Bad configuration option: %s", filename, linenum, cp);
	return oBadOption;
}

/**
Advance to the next word
@param s string to parse, this is the next_word pointer, the value of s
	 when the macro is called is the current word, after the macro
	 completes, s contains the beginning of the NEXT word, so you
	 need to save s to something else before doing TO_NEXT_WORD
@param e should be 0 when calling TO_NEXT_WORD(), it'll be changed to 1
	 if the end of the string is reached.
*/
#define TO_NEXT_WORD(s, e) do { \
	while (*s != '\0' && !isblank(*s)) { \
		s++; \
	} \
	if (*s != '\0') { \
		*s = '\0'; \
		s++; \
		while (isblank(*s)) \
			s++; \
	} else { \
		e = 1; \
	} \
} while (0)

/** Add a firewall ruleset with the given name, and return it.
 *  Do not allow duplicates. */
t_firewall_ruleset *
add_ruleset(const char rulesetname[])
{
	t_firewall_ruleset * ruleset;

	ruleset = get_ruleset(rulesetname);

	if (ruleset != NULL) {
		debug(LOG_DEBUG, "add_ruleset(): FirewallRuleSet %s already exists.", rulesetname);
		return ruleset;
	}

	debug(LOG_DEBUG, "add_ruleset(): Creating FirewallRuleSet %s.", rulesetname);

	/* Create and place at head of config.rulesets */
	ruleset = safe_malloc(sizeof(t_firewall_ruleset));
	memset(ruleset, 0, sizeof(t_firewall_ruleset));
	ruleset->name = safe_strdup(rulesetname);
	ruleset->next = config.rulesets;
	config.rulesets = ruleset;

	return ruleset;
}


/** @internal
Parses an empty ruleset policy directive
*/
static void
parse_empty_ruleset_policy(char *ptr, const char *filename, int lineno)
{
	char *rulesetname, *policy;
	t_firewall_ruleset *ruleset;

	/* find first whitespace delimited word; this is ruleset name */
	while ((*ptr != '\0') && (isblank(*ptr))) ptr++;
	rulesetname = ptr;
	while ((*ptr != '\0') && (!isblank(*ptr))) ptr++;
	*ptr = '\0';


	/* get the ruleset struct with this name; error if it doesn't exist */
	debug(LOG_DEBUG, "Parsing EmptyRuleSetPolicy for %s", rulesetname);
	ruleset = get_ruleset(rulesetname);
	if (ruleset == NULL) {
		debug(LOG_ERR, "Unrecognized FirewallRuleSet name: %s at line %d in %s", rulesetname, lineno, filename);
		debug(LOG_ERR, "Exiting...");
		exit(-1);
	}

	/* find next whitespace delimited word; this is policy name */
	ptr++;
	while ((*ptr != '\0') && (isblank(*ptr))) ptr++;
	policy = ptr;
	while ((*ptr != '\0') && (!isblank(*ptr))) ptr++;
	*ptr = '\0';

	/* make sure policy is one of the possible ones:
	 "passthrough" means iptables RETURN
	 "allow" means iptables ACCEPT
	 "block" means iptables REJECT
	*/
	if (ruleset->emptyrulesetpolicy != NULL) free(ruleset->emptyrulesetpolicy);
	if (!strcasecmp(policy,"passthrough")) {
		ruleset->emptyrulesetpolicy =  safe_strdup("RETURN");
	} else if (!strcasecmp(policy,"allow")) {
		ruleset->emptyrulesetpolicy =  safe_strdup("ACCEPT");
	} else if (!strcasecmp(policy,"block")) {
		ruleset->emptyrulesetpolicy =  safe_strdup("REJECT");
	} else {
		debug(LOG_ERR, "Unknown EmptyRuleSetPolicy directive: %s at line %d in %s", policy, lineno, filename);
		debug(LOG_ERR, "Exiting...");
		exit(-1);
	}

	debug(LOG_DEBUG, "Set EmptyRuleSetPolicy for %s to %s", rulesetname, policy);
}



/** @internal
Parses firewall rule set information
*/
static void
parse_firewall_ruleset(const char *rulesetname, FILE *fd, const char *filename, int *linenum)
{
	char line[MAX_BUF], *p1, *p2;
	int  opcode;
	t_firewall_ruleset *ruleset;

	/* find whitespace delimited word in ruleset string; this is its name */
	p1 = strchr(rulesetname,' ');
	if (p1) *p1 = '\0';
	p1 = strchr(rulesetname,'\t');
	if (p1) *p1 = '\0';

	debug(LOG_DEBUG, "Parsing FirewallRuleSet %s", rulesetname);
	ruleset = get_ruleset(rulesetname);
	if (ruleset == NULL) {
		debug(LOG_ERR, "Unrecognized FirewallRuleSet name: %s", rulesetname);
		debug(LOG_ERR, "Exiting...");
		exit(-1);
	}

	/* Parsing the rules in the set */
	while (fgets(line, MAX_BUF, fd)) {
		(*linenum)++;
		p1 = _strip_whitespace(line);

		/* if nothing left, get next line */
		if (p1[0] == '\0') continue;

		/* if closing brace, we are done */
		if (p1[0] == '}') break;

		/* next, we coopt the parsing of the regular config */

		/* keep going until word boundary is found. */
		p2 = p1;
		while ((*p2 != '\0') && (!isblank(*p2))) p2++;
		/* if this is end of line, it's a problem */
		if (p2[0] == '\0') {
			debug(LOG_ERR, "FirewallRule incomplete on line %d in %s", *linenum, filename);
			debug(LOG_ERR, "Exiting...");
			exit(-1);
		}
		/* terminate first word, point past it */
		*p2 = '\0';
		p2++;

		/* skip whitespace to point at arg */
		while (isblank(*p2)) p2++;

		/* Get opcode */
		opcode = config_parse_opcode(p1, filename, *linenum);

		debug(LOG_DEBUG, "p1 = [%s]; p2 = [%s]", p1, p2);

		switch (opcode) {
		case oFirewallRule:
			_parse_firewall_rule(ruleset, p2);
			break;

		case oBadOption:
		default:
			debug(LOG_ERR, "Bad option %s parsing FirewallRuleSet on line %d in %s", p1, *linenum, filename);
			debug(LOG_ERR, "Exiting...");
			exit(-1);
			break;
		}
	}
	debug(LOG_DEBUG, "FirewallRuleSet %s parsed.", rulesetname);
}

/** @internal
Helper for parse_firewall_ruleset.  Parses a single rule in a ruleset
*/
static int
_parse_firewall_rule(t_firewall_ruleset *ruleset, char *leftover)
{
	int i;
	t_firewall_target target = TARGET_REJECT; /**< firewall target */
	int all_nums = 1; /**< If 0, word contained illegal chars */
	int finished = 0; /**< reached end of line */
	char *token = NULL; /**< First word */
	char *port = NULL; /**< port(s) to allow/block */
	char *protocol = NULL; /**< protocol to allow/block: tcp/udp/icmp/all */
	char *mask = NULL; /**< Netmask */
	char *ipset = NULL; /**< ipset */
	char *other_kw = NULL; /**< other key word */
	t_firewall_rule *tmp;
	t_firewall_rule *tmp2;

	/* debug(LOG_DEBUG, "leftover: %s", leftover); */

	/* lowercase everything */
	for (i = 0; *(leftover + i) != '\0'
			&& (*(leftover + i) = tolower((unsigned char)*(leftover + i))); i++);
	token = leftover;
	TO_NEXT_WORD(leftover, finished);

	/* Parse token */
	if (!strcasecmp(token, "block")) {
		target = TARGET_REJECT;
	} else if (!strcasecmp(token, "drop")) {
		target = TARGET_DROP;
	} else if (!strcasecmp(token, "allow")) {
		target = TARGET_ACCEPT;
	} else if (!strcasecmp(token, "log")) {
		target = TARGET_LOG;
	} else if (!strcasecmp(token, "ulog")) {
		target = TARGET_ULOG;
	} else {
		debug(LOG_ERR, "Invalid rule type %s, expecting "
			  "\"block\",\"drop\",\"allow\",\"log\" or \"ulog\"", token);
		return -1;
	}

	/* Parse the remainder */

	/* Get the optional protocol */
	if (strncmp(leftover, "tcp", 3) == 0
			|| strncmp(leftover, "udp", 3) == 0
			|| strncmp(leftover, "all", 3) == 0
			|| strncmp(leftover, "icmp", 4) == 0) {
		protocol = leftover;
		TO_NEXT_WORD(leftover, finished);
	}

	/* Get the optional port or port range */
	if (strncmp(leftover, "port", 4) == 0) {
		if (protocol == NULL ||
				!(strncmp(protocol, "tcp", 3) == 0 || strncmp(protocol, "udp", 3) == 0)) {
			debug(LOG_ERR, "Port without tcp or udp protocol");
			return -3; /*< Fail */
		}
		TO_NEXT_WORD(leftover, finished);
		/* Get port now */
		port = leftover;
		TO_NEXT_WORD(leftover, finished);
		for (i = 0; *(port + i) != '\0'; i++)
			if (!isdigit((unsigned char)*(port + i)) && ((unsigned char)*(port + i) != ':'))
				all_nums = 0; /*< No longer only digits or : */
		if (!all_nums) {
			debug(LOG_ERR, "Invalid port %s", port);
			return -3; /*< Fail */
		}
	}

	if (strncmp(leftover, "ipset", 5) == 0) {
		TO_NEXT_WORD(leftover, finished);
		/* Get ipset now */
		ipset = leftover;
		TO_NEXT_WORD(leftover, finished);

		/* TODO check if ipset exists */
	}

	/* Now, look for optional IP address/mask */
	if (!finished) {
		/* should be exactly "to" */
		other_kw = leftover;
		TO_NEXT_WORD(leftover, finished);
		if (strcmp(other_kw, "to") || finished) {
			debug(LOG_ERR, "Invalid or unexpected keyword %s, "
				  "expecting \"to\"", other_kw);
			return -4; /*< Fail */
		}

		/* Get IP address/mask now */
		mask = leftover;
		TO_NEXT_WORD(leftover, finished);
		all_nums = 1;
		for (i = 0; *(mask + i) != '\0'; i++)
			if (!isdigit((unsigned char)*(mask + i)) && (*(mask + i) != '.')
					&& (*(mask + i) != '/'))
				all_nums = 0; /*< No longer only digits or . or / */
		if (!all_nums) {
			debug(LOG_ERR, "Invalid mask %s", mask);
			return -5; /*< Fail */
		}
	}

	/* Generate rule record */
	tmp = safe_malloc(sizeof(t_firewall_rule));
	memset((void *)tmp, 0, sizeof(t_firewall_rule));
	tmp->target = target;
	if (protocol != NULL)
		tmp->protocol = safe_strdup(protocol);
	if (port != NULL)
		tmp->port = safe_strdup(port);
	if (ipset != NULL)
		tmp->ipset = safe_strdup(ipset);
	if (mask == NULL)
		tmp->mask = safe_strdup("0.0.0.0/0");
	else
		tmp->mask = safe_strdup(mask);

	debug(LOG_DEBUG, "Adding FirewallRule %s %s port %s to %s to FirewallRuleset %s", token, tmp->protocol, tmp->port, tmp->mask, ruleset->name);

	/* Add the rule record */
	if (ruleset->rules == NULL) {
		/* No rules... */
		ruleset->rules = tmp;
	} else {
		tmp2 = ruleset->rules;
		while (tmp2->next != NULL)
			tmp2 = tmp2->next;
		tmp2->next = tmp;
	}

	return 1;
}

int
is_empty_ruleset (const char *rulesetname)
{
	return get_ruleset_list(rulesetname) == NULL;
}

char *
get_empty_ruleset_policy(const char *rulesetname)
{
	t_firewall_ruleset *rs;
	rs = get_ruleset(rulesetname);
	if (rs == NULL) return NULL;
	return rs->emptyrulesetpolicy;
}


t_firewall_ruleset *
get_ruleset(const char ruleset[])
{
	t_firewall_ruleset	*tmp;

	for (tmp = config.rulesets; tmp != NULL
			&& strcmp(tmp->name, ruleset) != 0; tmp = tmp->next);

	return (tmp);
}

t_firewall_rule *
get_ruleset_list(const char *ruleset)
{
	t_firewall_ruleset	*tmp = get_ruleset(ruleset);

	if (tmp == NULL) return NULL;

	return (tmp->rules);
}

/** @internal
Strip comments and leading and trailing whitespace from a string.
Return a pointer to the first nonspace char in the string.
*/
static char*
_strip_whitespace(char* p1)
{
	char *p2, *p3;

	p3 = p1;
	while ((p2 = strchr(p3,'#')) != 0) {  /* strip the comment */
		/* but allow # to be escaped by \ */
		if (p2 > p1 && (*(p2 - 1) == '\\')) {
			p3 = p2 + 1;
			continue;
		}
		*p2 = '\0';
		break;
	}

	/* strip leading whitespace */
	while(isspace(p1[0])) p1++;
	/* strip trailing whitespace */
	while(p1[0] != '\0' && isspace(p1[strlen(p1)-1]))
		p1[strlen(p1)-1] = '\0';

	return p1;
}

/**
@param filename Full path of the configuration file to be read
*/
void
config_read(const char *filename)
{
	FILE *fd;
	char line[MAX_BUF], *s, *p1, *p2;
	int linenum = 0, opcode, value;

	debug(LOG_INFO, "Reading configuration file '%s'", filename);

	if (!(fd = fopen(filename, "r"))) {
		debug(LOG_ERR, "FATAL: Could not open configuration file '%s', "
			  "exiting...", filename);
		exit(1);
	}

	while (fgets(line, MAX_BUF, fd)) {
		linenum++;
		s = _strip_whitespace(line);

		/* if nothing left, get next line */
		if (s[0] == '\0') continue;

		/* now we require the line must have form: <option><whitespace><arg>
		 * even if <arg> is just a left brace, for example
		 */

		/* find first word (i.e. option) end boundary */
		p1 = s;
		while ((*p1 != '\0') && (!isspace(*p1))) p1++;
		/* if this is end of line, it's a problem */
		if (p1[0] == '\0') {
			debug(LOG_ERR, "Option %s requires argument on line %d in %s", s, linenum, filename);
			debug(LOG_ERR, "Exiting...");
			exit(-1);
		}

		/* terminate option, point past it */
		*p1 = '\0';
		p1++;

		/* skip any additional leading whitespace, make p1 point at start of arg */
		while (isblank(*p1)) p1++;

		debug(LOG_DEBUG, "Parsing option: %s, arg: %s", s, p1);
		opcode = config_parse_opcode(s, filename, linenum);

		switch(opcode) {
		case oDaemon:
			if (config.daemon == -1 && ((value = parse_boolean_value(p1)) != -1)) {
				config.daemon = value;
			}
			break;
		case oDebugLevel:
			if (sscanf(p1, "%d", &config.debuglevel) < 1 || config.debuglevel < LOG_EMERG || config.debuglevel > LOG_DEBUG) {
				debug(LOG_ERR, "Bad arg %s to option %s on line %d in %s. Valid debuglevel %d..%d", p1, s, linenum, filename, LOG_EMERG, LOG_DEBUG);
				debug(LOG_ERR, "Exiting...");
				exit(-1);
			}
			break;
		case oMaxClients:
			if (sscanf(p1, "%d", &config.maxclients) < 1) {
				debug(LOG_ERR, "Bad arg %s to option %s on line %d in %s", p1, s, linenum, filename);
				debug(LOG_ERR, "Exiting...");
				exit(-1);
			}
			break;
		case oGatewayName:
			config.gw_name = safe_strdup(p1);
			break;
		case oGatewayInterface:
			config.gw_interface = safe_strdup(p1);
			break;
		case oGatewayIPRange:
			config.gw_iprange = safe_strdup(p1);
			break;
		case oGatewayAddress:
			config.gw_address = safe_strdup(p1);
			break;
		case oGatewayPort:
			if (sscanf(p1, "%u", &config.gw_port) < 1) {
				debug(LOG_ERR, "Bad arg %s to option %s on line %d in %s", p1, s, linenum, filename);
				debug(LOG_ERR, "Exiting...");
				exit(-1);
			}
			break;
		case oRemoteAuthenticatorAction:
			config.remote_auth_action = safe_strdup(p1);
			break;
		case oEnablePreAuth:
			value = parse_boolean_value(p1);
			if (value != - 1)
				config.enable_preauth = value;
			break;
		case oBinVoucher:
			config.bin_voucher = safe_strdup(p1);
			break;
		case oForceVoucher:
			value = parse_boolean_value(p1);
			if (value != - 1)
				config.force_voucher = value;
			break;
		case oFirewallRuleSet:
			parse_firewall_ruleset(p1, fd, filename, &linenum);
			break;
		case oEmptyRuleSetPolicy:
			parse_empty_ruleset_policy(p1, filename, linenum);
			break;
		case oTrustedMACList:
			parse_trusted_mac_list(p1);
			break;
		case oBlockedMACList:
			parse_blocked_mac_list(p1);
			break;
		case oAllowedMACList:
			parse_allowed_mac_list(p1);
			break;
		case oMACmechanism:
			if (!strcasecmp("allow",p1)) config.macmechanism = MAC_ALLOW;
			else if (!strcasecmp("block",p1)) config.macmechanism = MAC_BLOCK;
			else {
				debug(LOG_ERR, "Bad arg %s to option %s on line %d in %s", p1, s, linenum, filename);
				debug(LOG_ERR, "Exiting...");
				exit(-1);
			}
			break;
		case oWebRoot:
			/* remove any trailing slashes from webroot path */
			while((p2 = strrchr(p1,'/')) == (p1 + strlen(p1) - 1)) *p2 = '\0';
			config.webroot = safe_strdup(p1);
			break;
		case oSplashPage:
			config.splashpage = safe_strdup(p1);
			break;
		case oImagesDir:
			config.imagesdir = safe_strdup(p1);
			break;
		case oPagesDir:
			config.pagesdir = safe_strdup(p1);
			break;
		case oRedirectURL:
			config.redirectURL = safe_strdup(p1);
			break;
		case oNdsctlSocket:
			free(config.ndsctl_sock);
			config.ndsctl_sock = safe_strdup(p1);
			break;
		case oDecongestHttpdThreads:
			if ((value = parse_boolean_value(p1)) != -1) {
				config.decongest_httpd_threads = value;
			} else {
				debug(LOG_ERR, "Bad arg %s to option %s on line %d in %s", p1, s, linenum, filename);
				debug(LOG_ERR, "Exiting...");
				exit(-1);
			}
			break;
		case oHttpdThreadThreshold:
			if (sscanf(p1, "%d", &config.httpd_thread_threshold) < 1) {
				debug(LOG_ERR, "Bad arg %s to option %s on line %d in %s", p1, s, linenum, filename);
				debug(LOG_ERR, "Exiting...");
				exit(-1);
			}
			break;
		case oHttpdThreadDelayMS:
			if (sscanf(p1, "%d", &config.httpd_thread_delay_ms) < 1) {
				debug(LOG_ERR, "Bad arg %s to option %s on line %d in %s", p1, s, linenum, filename);
				debug(LOG_ERR, "Exiting...");
				exit(-1);
			}
			break;
		case oClientIdleTimeout:
			if (sscanf(p1, "%d", &config.clienttimeout) < 1) {
				debug(LOG_ERR, "Bad arg %s to option %s on line %d in %s", p1, s, linenum, filename);
				debug(LOG_ERR, "Exiting...");
				exit(-1);
			}
			break;
		case oClientForceTimeout:
			if (sscanf(p1, "%d", &config.clientforceout) < 1) {
				debug(LOG_ERR, "Bad arg %s to option %s on line %d in %s", p1, s, linenum, filename);
				debug(LOG_ERR, "Exiting...");
				exit(-1);
			}
			break;
		case oPasswordAuthentication:
			if ((value = parse_boolean_value(p1)) != -1) {
				config.passwordauth = value;
			} else {
				debug(LOG_ERR, "Bad arg %s to option %s on line %d in %s", p1, s, linenum, filename);
				debug(LOG_ERR, "Exiting...");
				exit(-1);
			}
			break;
		case oUsernameAuthentication:
			if ((value = parse_boolean_value(p1)) != -1) {
				config.usernameauth = value;
			} else {
				debug(LOG_ERR, "Bad arg %s to option %s on line %d in %s", p1, s, linenum, filename);
				debug(LOG_ERR, "Exiting...");
				exit(-1);
			}
			break;
		case oPasswordAttempts:
			if (sscanf(p1, "%d", &config.passwordattempts) < 1) {
				debug(LOG_ERR, "Bad arg %s to option %s on line %d in %s", p1, s, linenum, filename);
				debug(LOG_ERR, "Exiting...");
				exit(-1);
			}
			break;
		case oUsername:
			set_username(p1);
			break;
		case oPassword:
			set_password(p1);
			break;
		case oSetMSS:
			if ((value = parse_boolean_value(p1)) != -1) {
				config.set_mss = value;
			} else {
				debug(LOG_ERR, "Bad arg %s to option %s on line %d in %s", p1, s, linenum, filename);
				debug(LOG_ERR, "Exiting...");
				exit(-1);
			}
			break;
		case oMSSValue:
			if (sscanf(p1, "%d", &config.mss_value) < 1) {
				debug(LOG_ERR, "Bad arg %s to option %s on line %d in %s", p1, s, linenum, filename);
				debug(LOG_ERR, "Exiting...");
				exit(-1);
			}
			break;
		case oTrafficControl:
			if ((value = parse_boolean_value(p1)) != -1) {
				config.traffic_control = value;
			} else {
				debug(LOG_ERR, "Bad arg %s to option %s on line %d in %s", p1, s, linenum, filename);
				debug(LOG_ERR, "Exiting...");
				exit(-1);
			}
			break;
		case oDownloadLimit:
			if (sscanf(p1, "%d", &config.download_limit) < 1) {
				debug(LOG_ERR, "Bad arg %s to option %s on line %d in %s", p1, s, linenum, filename);
				debug(LOG_ERR, "Exiting...");
				exit(-1);
			}
			break;
		case oUploadLimit:
			if (sscanf(p1, "%d", &config.upload_limit) < 1) {
				debug(LOG_ERR, "Bad arg %s to option %s on line %d in %s", p1, s, linenum, filename);
				debug(LOG_ERR, "Exiting...");
				exit(-1);
			}
			break;
		case oDownloadIMQ:
			if (sscanf(p1, "%d", &config.download_imq) < 1) {
				debug(LOG_ERR, "Bad arg %s to option %s on line %d in %s", p1, s, linenum, filename);
				debug(LOG_ERR, "Exiting...");
				exit(-1);
			}
			break;
		case oUploadIMQ:
			if (sscanf(p1, "%d", &config.upload_imq) < 1) {
				debug(LOG_ERR, "Bad arg %s to option %s on line %d in %s", p1, s, linenum, filename);
				debug(LOG_ERR, "Exiting...");
				exit(-1);
			}
			break;
		case oFWMarkAuthenticated:
			if (sscanf(p1, "%x", &config.FW_MARK_AUTHENTICATED) < 1 ||
					config.FW_MARK_AUTHENTICATED == 0 ||
					config.FW_MARK_AUTHENTICATED == config.FW_MARK_BLOCKED ||
					config.FW_MARK_AUTHENTICATED == config.FW_MARK_TRUSTED) {
				debug(LOG_ERR, "Bad arg %s to option %s on line %d in %s", p1, s, linenum, filename);
				debug(LOG_ERR, "Exiting...");
				exit(-1);
			}
			break;
		case oFWMarkBlocked:
			if (sscanf(p1, "%x", &config.FW_MARK_BLOCKED) < 1 ||
					config.FW_MARK_BLOCKED == 0 ||
					config.FW_MARK_BLOCKED == config.FW_MARK_AUTHENTICATED ||
					config.FW_MARK_BLOCKED == config.FW_MARK_TRUSTED) {
				debug(LOG_ERR, "Bad arg %s to option %s on line %d in %s", p1, s, linenum, filename);
				debug(LOG_ERR, "Exiting...");
				exit(-1);
			}
			break;
		case oFWMarkTrusted:
			if (sscanf(p1, "%x", &config.FW_MARK_TRUSTED) < 1 ||
					config.FW_MARK_TRUSTED == 0 ||
					config.FW_MARK_TRUSTED == config.FW_MARK_AUTHENTICATED ||
					config.FW_MARK_TRUSTED == config.FW_MARK_BLOCKED) {
				debug(LOG_ERR, "Bad arg %s to option %s on line %d in %s", p1, s, linenum, filename);
				debug(LOG_ERR, "Exiting...");
				exit(-1);
			}
			break;
		case oCheckInterval:
			if (sscanf(p1, "%i", &config.checkinterval) < 1 || config.checkinterval < 1) {
				debug(LOG_ERR, "Bad arg %s to option %s on line %d in %s", p1, s, linenum, filename);
				debug(LOG_ERR, "Exiting...");
				exit(-1);
			}
			break;
		case oSyslogFacility:
			if (sscanf(p1, "%d", &config.syslog_facility) < 1) {
				debug(LOG_ERR, "Bad arg %s to option %s on line %d in %s", p1, s, linenum, filename);
				debug(LOG_ERR, "Exiting...");
				exit(-1);
			}
			break;
		case oBadOption:
			debug(LOG_ERR, "Bad option %s on line %d in %s", s, linenum, filename);
			debug(LOG_ERR, "Exiting...");
			exit(-1);
			break;
		}
	}

	fclose(fd);

	debug(LOG_INFO, "Done reading configuration file '%s'", filename);
}

/** @internal
Parses a boolean value from the config file
*/
static int
parse_boolean_value(char *line)
{
	if (strcasecmp(line, "no") == 0 ||
			strcasecmp(line, "false") == 0 ||
			strcmp(line, "0") == 0
	   ) {
		return 0;
	}
	if (strcasecmp(line, "yes") == 0 ||
			strcasecmp(line, "true") == 0 ||
			strcmp(line, "1") == 0
	   ) {
		return 1;
	}

	return -1;
}

/* Parse a string to see if it is valid decimal dotted quad IP V4 format */
int check_ip_format(const char *possibleip)
{
	unsigned int a1,a2,a3,a4;

	return (sscanf(possibleip,"%u.%u.%u.%u",&a1,&a2,&a3,&a4) == 4
			&& a1 < 256 && a2 < 256 && a3 < 256 && a4 < 256);
}


/* Parse a string to see if it is valid MAC address format */
int check_mac_format(const char possiblemac[])
{
	char hex2[3];
	return
		sscanf(possiblemac,
			   "%2[A-Fa-f0-9]:%2[A-Fa-f0-9]:%2[A-Fa-f0-9]:%2[A-Fa-f0-9]:%2[A-Fa-f0-9]:%2[A-Fa-f0-9]",
			   hex2,hex2,hex2,hex2,hex2,hex2) == 6;
}

int add_to_trusted_mac_list(const char possiblemac[])
{
	char *mac = NULL;
	t_MAC *p = NULL;

	/* check for valid format */
	if (!check_mac_format(possiblemac)) {
		debug(LOG_NOTICE, "[%s] not a valid MAC address to trust", possiblemac);
		return -1;
	}

	mac = safe_malloc(18);

	sscanf(possiblemac, "%17[A-Fa-f0-9:]", mac);

	/* See if MAC is already on the list; don't add duplicates */
	for (p = config.trustedmaclist; p != NULL; p = p->next) {
		if (!strcasecmp(p->mac,mac)) {
			debug(LOG_INFO, "MAC address [%s] already on trusted list", mac);
			free(mac);
			return 1;
		}
	}

	/* Add MAC to head of list */
	p = safe_malloc(sizeof(t_MAC));
	p->mac = safe_strdup(mac);
	p->next = config.trustedmaclist;
	config.trustedmaclist = p;
	debug(LOG_INFO, "Added MAC address [%s] to trusted list", mac);
	free(mac);
	return 0;
}


/* Remove given MAC address from the config's trusted mac list.
 * Return 0 on success, nonzero on failure
 */
int remove_from_trusted_mac_list(const char possiblemac[])
{
	char *mac = NULL;
	t_MAC **p = NULL;
	t_MAC *del = NULL;

	/* check for valid format */
	if (!check_mac_format(possiblemac)) {
		debug(LOG_NOTICE, "[%s] not a valid MAC address", possiblemac);
		return -1;
	}

	mac = safe_malloc(18);

	sscanf(possiblemac, "%17[A-Fa-f0-9:]", mac);

	/* If empty list, nothing to do */
	if (config.trustedmaclist == NULL) {
		debug(LOG_INFO, "MAC address [%s] not on empty trusted list", mac);
		free(mac);
		return -1;
	}

	/* Find MAC on the list, remove it */
	for (p = &(config.trustedmaclist); *p != NULL; p = &((*p)->next)) {
		if (!strcasecmp((*p)->mac,mac)) {
			/* found it */
			del = *p;
			*p = del->next;
			debug(LOG_INFO, "Removed MAC address [%s] from trusted list", mac);
			free(del);
			free(mac);
			return 0;
		}
	}

	/* MAC was not on list */
	debug(LOG_INFO, "MAC address [%s] not on  trusted list", mac);
	free(mac);
	return -1;
}


/* Given a pointer to a comma or whitespace delimited sequence of
 * MAC addresses, add each MAC address to config.trustedmaclist.
 */
void parse_trusted_mac_list(const char ptr[])
{
	char *ptrcopy = NULL, *ptrcopyptr;
	char *possiblemac = NULL;

	debug(LOG_DEBUG, "Parsing string [%s] for trusted MAC addresses", ptr);

	/* strsep modifies original, so let's make a copy */
	ptrcopyptr = ptrcopy = safe_strdup(ptr);

	while ((possiblemac = strsep(&ptrcopy, ", \t"))) {
		if (strlen(possiblemac)>0) add_to_trusted_mac_list(possiblemac);
	}

	free(ptrcopyptr);
}


/* Add given MAC address to the config's blocked mac list.
 * Return 0 on success, nonzero on failure
 */
int add_to_blocked_mac_list(const char possiblemac[])
{
	char *mac = NULL;
	t_MAC *p = NULL;

	/* check for valid format */
	if (!check_mac_format(possiblemac)) {
		debug(LOG_NOTICE, "[%s] not a valid MAC address to block", possiblemac);
		return -1;
	}

	/* abort if not using BLOCK mechanism */
	if (MAC_BLOCK != config.macmechanism) {
		debug(LOG_NOTICE, "Attempt to access blocked MAC list but control mechanism != block");
		return -1;
	}

	mac = safe_malloc(18);

	sscanf(possiblemac, "%17[A-Fa-f0-9:]", mac);

	/* See if MAC is already on the list; don't add duplicates */
	for (p = config.blockedmaclist; p != NULL; p = p->next) {
		if (!strcasecmp(p->mac,mac)) {
			debug(LOG_INFO, "MAC address [%s] already on blocked list", mac);
			free(mac);
			return 1;
		}
	}

	/* Add MAC to head of list */
	p = safe_malloc(sizeof(t_MAC));
	p->mac = safe_strdup(mac);
	p->next = config.blockedmaclist;
	config.blockedmaclist = p;
	debug(LOG_INFO, "Added MAC address [%s] to blocked list", mac);
	free(mac);
	return 0;
}


/* Remove given MAC address from the config's blocked mac list.
 * Return 0 on success, nonzero on failure
 */
int remove_from_blocked_mac_list(const char possiblemac[])
{
	char *mac = NULL;
	t_MAC **p = NULL;
	t_MAC *del = NULL;

	/* check for valid format */
	if (!check_mac_format(possiblemac)) {
		debug(LOG_NOTICE, "[%s] not a valid MAC address", possiblemac);
		return -1;
	}

	/* abort if not using BLOCK mechanism */
	if (MAC_BLOCK != config.macmechanism) {
		debug(LOG_NOTICE, "Attempt to access blocked MAC list but control mechanism != block");
		return -1;
	}

	mac = safe_malloc(18);

	sscanf(possiblemac, "%17[A-Fa-f0-9:]", mac);

	/* If empty list, nothing to do */
	if (config.blockedmaclist == NULL) {
		debug(LOG_INFO, "MAC address [%s] not on empty blocked list", mac);
		free(mac);
		return -1;
	}

	/* Find MAC on the list, remove it */
	for (p = &(config.blockedmaclist); *p != NULL; p = &((*p)->next)) {
		if (!strcasecmp((*p)->mac,mac)) {
			/* found it */
			del = *p;
			*p = del->next;
			debug(LOG_INFO, "Removed MAC address [%s] from blocked list", mac);
			free(del);
			free(mac);
			return 0;
		}
	}

	/* MAC was not on list */
	debug(LOG_INFO, "MAC address [%s] not on  blocked list", mac);
	free(mac);
	return -1;
}


/* Given a pointer to a comma or whitespace delimited sequence of
 * MAC addresses, add each MAC address to config.blockedmaclist
 */
void parse_blocked_mac_list(const char ptr[])
{
	char *ptrcopy = NULL, *ptrcopyptr;
	char *possiblemac = NULL;

	debug(LOG_DEBUG, "Parsing string [%s] for MAC addresses to block", ptr);

	/* strsep modifies original, so let's make a copy */
	ptrcopyptr = ptrcopy = safe_strdup(ptr);

	while ((possiblemac = strsep(&ptrcopy, ", \t"))) {
		if (strlen(possiblemac)>0) add_to_blocked_mac_list(possiblemac);
	}

	free(ptrcopyptr);
}

/* Add given MAC address to the config's allowed mac list.
 * Return 0 on success, nonzero on failure
 */
int add_to_allowed_mac_list(const char possiblemac[])
{
	char *mac = NULL;
	t_MAC *p = NULL;

	/* check for valid format */
	if (!check_mac_format(possiblemac)) {
		debug(LOG_NOTICE, "[%s] not a valid MAC address to allow", possiblemac);
		return -1;
	}

	/* abort if not using ALLOW mechanism */
	if (MAC_ALLOW != config.macmechanism) {
		debug(LOG_NOTICE, "Attempt to access allowed MAC list but control mechanism != allow");
		return -1;
	}

	mac = safe_malloc(18);

	sscanf(possiblemac, "%17[A-Fa-f0-9:]", mac);

	/* See if MAC is already on the list; don't add duplicates */
	for (p = config.allowedmaclist; p != NULL; p = p->next) {
		if (!strcasecmp(p->mac,mac)) {
			debug(LOG_INFO, "MAC address [%s] already on allowed list", mac);
			free(mac);
			return 1;
		}
	}

	/* Add MAC to head of list */
	p = safe_malloc(sizeof(t_MAC));
	p->mac = safe_strdup(mac);
	p->next = config.allowedmaclist;
	config.allowedmaclist = p;
	debug(LOG_INFO, "Added MAC address [%s] to allowed list", mac);
	free(mac);
	return 0;
}


/* Remove given MAC address from the config's allowed mac list.
 * Return 0 on success, nonzero on failure
 */
int remove_from_allowed_mac_list(const char possiblemac[])
{
	char *mac = NULL;
	t_MAC **p = NULL;
	t_MAC *del = NULL;

	/* check for valid format */
	if (!check_mac_format(possiblemac)) {
		debug(LOG_NOTICE, "[%s] not a valid MAC address", possiblemac);
		return -1;
	}

	/* abort if not using ALLOW mechanism */
	if (MAC_ALLOW != config.macmechanism) {
		debug(LOG_NOTICE, "Attempt to access allowed MAC list but control mechanism != allow");
		return -1;
	}

	mac = safe_malloc(18);

	sscanf(possiblemac, "%17[A-Fa-f0-9:]", mac);

	/* If empty list, nothing to do */
	if (config.allowedmaclist == NULL) {
		debug(LOG_INFO, "MAC address [%s] not on empty allowed list", mac);
		free(mac);
		return -1;
	}

	/* Find MAC on the list, remove it */
	for (p = &(config.allowedmaclist); *p != NULL; p = &((*p)->next)) {
		if (!strcasecmp((*p)->mac,mac)) {
			/* found it */
			del = *p;
			*p = del->next;
			debug(LOG_INFO, "Removed MAC address [%s] from allowed list", mac);
			free(del);
			free(mac);
			return 0;
		}
	}

	/* MAC was not on list */
	debug(LOG_INFO, "MAC address [%s] not on  allowed list", mac);
	free(mac);
	return -1;
}

/* Given a pointer to a comma or whitespace delimited sequence of
 * MAC addresses, add each MAC address to config.allowedmaclist
 */
void parse_allowed_mac_list(const char ptr[])
{
	char *ptrcopy = NULL;
	char *ptrcopyptr;
	char *possiblemac = NULL;

	debug(LOG_DEBUG, "Parsing string [%s] for MAC addresses to allow", ptr);

	/* strsep modifies original, so let's make a copy */
	ptrcopyptr = ptrcopy = safe_strdup(ptr);

	while ((possiblemac = strsep(&ptrcopy, ", \t"))) {
		if (strlen(possiblemac) > 0) {
			add_to_allowed_mac_list(possiblemac);
		}
	}

	free(ptrcopyptr);
}



/** Set the debug log level.  See syslog.h
 *  Return 0 on success.
 */
int set_log_level(int level)
{
	config.debuglevel = level;
	return 0;
}

/** Set the gateway password.
 *  Return 0 on success.
 */
int set_password(const char s[])
{
	char *old = config.password;
	if (s) {
		config.password = safe_strdup(s);
		if (old) free(old);
		return 0;
	}
	return 1;
}

/** Set the gateway username.
 *  Return 0 on success.
 */
int set_username(const char s[])
{
	char *old = config.username;
	if (s) {
		config.username = safe_strdup(s);
		if (old) free(old);
		return 0;
	}
	return 1;
}

/** Verifies if the configuration is complete and valid.  Terminates the program if it isn't */
void
config_validate(void)
{
	config_notnull(config.gw_interface, "GatewayInterface");

	if (missing_parms) {
		debug(LOG_ERR, "Configuration is not complete, exiting...");
		exit(-1);
	}
}

/** @internal
    Verifies that a required parameter is not a null pointer
*/
static void
config_notnull(const void *parm, const char parmname[])
{
	if (parm == NULL) {
		debug(LOG_ERR, "%s is not set", parmname);
		missing_parms = 1;
	}
}
