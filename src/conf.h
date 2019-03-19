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

/** @file conf.h
    @brief Config file parsing
    @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
    @author Copyright (C) 2007 Paul Kube <nodogsplash@kokoro.ucsd.edu>
*/

#define COPYRIGHT "NodogSplash, Copyright (C) 2016 - 2019, The Nodogsplash Contributors"

#ifndef _CONF_H_
#define _CONF_H_

#define VERSION "3.3.3-beta"

/*@{*/
/** Defines */
/** How many times should we try detecting the interface with the default route
 * (in seconds).  If set to 0, it will keep retrying forever */
#define NUM_EXT_INTERFACE_DETECT_RETRY 0
/** How long we should wait per try
 *  to detect the interface with the default route if it isn't up yet (interval in seconds) */
#define EXT_INTERFACE_DETECT_RETRY_INTERVAL 1
#define MAC_ALLOW 0 /** macmechanism to block MAC's unless allowed */
#define MAC_BLOCK 1 /** macmechanism to allow MAC's unless blocked */

/** Defaults configuration values */
#ifndef SYSCONFDIR
#define DEFAULT_CONFIGFILE "/etc/nodogsplash/nodogsplash.conf"
#else
#define DEFAULT_CONFIGFILE SYSCONFDIR"/nodogsplash/nodogsplash.conf"
#endif
#define DEFAULT_DAEMON 1
#define DEFAULT_DEBUGLEVEL 1
#define DEFAULT_MAXCLIENTS 20
#define DEFAULT_GATEWAY_IPRANGE "0.0.0.0/0"
#define DEFAULT_GATEWAYNAME "NoDogSplash"
#define DEFAULT_GATEWAYPORT 2050
#define DEFAULT_CHECKINTERVAL 30
#define DEFAULT_SESSION_TIMEOUT 0
#define DEFAULT_SESSION_TIMEOUT_BLOCK 0
#define DEFAULT_SESSION_LIMIT_BLOCK 0
#define DEFAULT_PREAUTH_IDLE_TIMEOUT 10
#define DEFAULT_AUTH_IDLE_TIMEOUT 120
#define DEFAULT_WEBROOT "/etc/nodogsplash/htdocs"
#define DEFAULT_SPLASHPAGE "splash.html"
#define DEFAULT_STATUSPAGE "status.html"
#define DEFAULT_AUTHDIR "nodogsplash_auth"
#define DEFAULT_DENYDIR "nodogsplash_deny"
#define DEFAULT_PREAUTHDIR "nodogsplash_preauth"
#define DEFAULT_MACMECHANISM MAC_BLOCK
#define DEFAULT_SET_MSS 1
#define DEFAULT_MSS_VALUE 0
#define DEFAULT_TRAFFIC_CONTROL 0
#define DEFAULT_UPLOAD_LIMIT 0
#define DEFAULT_DOWNLOAD_LIMIT 0
#define DEFAULT_UPLOAD_IFB 0
#define DEFAULT_LOG_SYSLOG 0
#define DEFAULT_SYSLOG_FACILITY LOG_DAEMON
#define DEFAULT_NDSCTL_SOCK "/tmp/ndsctl.sock"
#define DEFAULT_INTERNAL_SOCK "/tmp/ndsctl.sock"
#define DEFAULT_FW_MARK_AUTHENTICATED 0x30000
#define DEFAULT_FW_MARK_TRUSTED 0x20000
#define DEFAULT_FW_MARK_BLOCKED 0x10000
/* N.B.: default policies here must be ACCEPT, REJECT, or RETURN
 * In the .conf file, they must be allow, block, or passthrough
 * Mapping between these enforced by parse_empty_ruleset_policy() */
#define DEFAULT_EMPTY_TRUSTED_USERS_POLICY "ACCEPT"
#define DEFAULT_EMPTY_TRUSTED_USERS_TO_ROUTER_POLICY "ACCEPT"
#define DEFAULT_EMPTY_USERS_TO_ROUTER_POLICY "REJECT"
#define DEFAULT_EMPTY_AUTHENTICATED_USERS_POLICY "RETURN"
#define DEFAULT_EMPTY_PREAUTHENTICATED_USERS_POLICY "REJECT"
#define DEFAULT_IP6 0
/*@}*/

/**
* Firewall targets
*/
typedef enum {
	TARGET_DROP,
	TARGET_REJECT,
	TARGET_ACCEPT,
	TARGET_LOG,
	TARGET_ULOG
} t_firewall_target;

/**
 * Firewall rules
 */
typedef struct _firewall_rule_t {
	t_firewall_target target;	/**< @brief t_firewall_target */
	char *protocol;		/**< @brief tcp, udp, etc ... */
	char *port;			/**< @brief Port to block/allow */
	char *mask;			/**< @brief Mask for the rule *destination* */
	char *ipset;			/**< @brief IPset rule */
	struct _firewall_rule_t *next;
} t_firewall_rule;

/**
 * Firewall rulesets
 */
typedef struct _firewall_ruleset_t {
	char *name;
	char *emptyrulesetpolicy;
	t_firewall_rule *rules;
	struct _firewall_ruleset_t *next;
} t_firewall_ruleset;

/**
 * MAC Addresses
 */
typedef struct _MAC_t {
	char *mac;
	struct _MAC_t *next;
} t_MAC;


/**
 * Configuration structure
 */
typedef struct {
	char configfile[255];		/**< @brief name of the config file */
	char *ndsctl_sock;		/**< @brief ndsctl path to socket */
	char *internal_sock;		/**< @brief internal path to socket */
	int daemon;			/**< @brief if daemon > 0, use daemon mode */
	int debuglevel;			/**< @brief Debug information verbosity */
	int maxclients;			/**< @brief Maximum number of clients allowed */
	char *gw_name;			/**< @brief Name of the gateway; e.g. its SSID */
	char *gw_interface;		/**< @brief Interface we will manage */
	char *gw_iprange;		/**< @brief IP range on gw_interface we will manage */
	char *gw_ip;			/**< @brief Internal IP (v4 or v6) for our web server */
	char *gw_address;		/**< @brief Internal IP with port for our web server */
	char *gw_domain;		/**< @brief A domain under which nodogsplash is reachable. */
	char *gw_http_name;	        /**< @brief Either gw_domain if defined or gw_address with port if required */
	char *gw_http_name_port;        /**< @brief Either gw_domain if defined or gw_address with port even not required */
	char *gw_mac;			/**< @brief MAC address of the interface we manage */
	unsigned int gw_port;		/**< @brief Port the webserver will run on */
	char *webroot;			/**< @brief Directory containing splash pages, etc. */
	char *splashpage;		/**< @brief Name of main splash page */
	char *statuspage;		/**< @brief Name of info status page */
	char *redirectURL;		/**< @brief URL to direct client to after authentication */
	char *authdir;			/**< @brief Notional relative dir for authentication URL */
	char *denydir;			/**< @brief Notional relative dir for denial URL */
	char *preauthdir;		/**< @brief Notional relative dir for preauth URL */
	int session_timeout;		/**< @brief Minutes of the default session length */
	int session_timeout_block;	/**< @brief state of default session_timeout block or not */
	int session_limit_block;	/**< @brief Download limit, MB after block */
	int preauth_idle_timeout;	/**< @brief Minutes a preauthenticated client will be kept in the system */
	int auth_idle_timeout;		/**< @brief Minutes an authenticated client will be kept in the system */
	int checkinterval;		/**< @brief Period the the client timeout check thread will run, in seconds */
	int set_mss;			/**< @brief boolean, whether to set mss */
	int mss_value;			/**< @brief int, mss value; <= 0 clamp to pmtu */
	int traffic_control;		/**< @brief boolean, whether to do tc */
	int download_limit;		/**< @brief Download limit, kb/s */
	int upload_limit;		/**< @brief Upload limit, kb/s */
	int upload_ifb;			/**< @brief Number of IFB handling upload */
	int log_syslog;			/**< @brief boolean, whether to log to syslog */
	int syslog_facility;		/**< @brief facility to use when using syslog for logging */
	int macmechanism; 		/**< @brief mechanism wrt MAC addrs */
	t_firewall_ruleset *rulesets;	/**< @brief firewall rules */
	t_MAC *trustedmaclist;		/**< @brief list of trusted macs */
	t_MAC *blockedmaclist;		/**< @brief list of blocked macs */
	t_MAC *allowedmaclist;		/**< @brief list of allowed macs */
	unsigned int fw_mark_authenticated;	/**< @brief iptables mark for authenticated packets */
	unsigned int fw_mark_blocked;	/**< @brief iptables mark for blocked packets */
	unsigned int fw_mark_trusted;	/**< @brief iptables mark for trusted packets */
	int ip6;			/**< @brief enable IPv6 */
	char *binauth;			/**< @brief external authentication program */
	char *preauth;			/**< @brief external preauthentication program */
} s_config;

/** @brief Get the current gateway configuration */
s_config *config_get_config(void);

/** @brief Initialise the conf system */
void config_init(void);

/** @brief Initialize the variables we override with the command line*/
void config_init_override(void);

/** @brief Reads the configuration file */
void config_read(const char filename[]);

/** @brief Check that the configuration is valid */
void config_validate(void);

/** @brief Fetch a firewall rule list, given name of the ruleset. */
t_firewall_rule *get_ruleset_list(const char[]);

/** @brief Fetch a firewall ruleset, given its name. */
t_firewall_ruleset *get_ruleset(const char[]);

/** @brief Add a firewall ruleset with the given name, and return it. */
t_firewall_ruleset *add_ruleset(const char[]);

/** @brief Say if a named firewall ruleset is empty. */
int is_empty_ruleset(const char[]);

/** @brief Get a named empty firewall ruleset policy, given ruleset name. */
char * get_empty_ruleset_policy(const char[]);

void parse_trusted_mac_list(const char[]);
void parse_blocked_mac_list(const char[]);
void parse_allowed_mac_list(const char[]);

int is_blocked_mac(const char *mac);
int is_allowed_mac(const char *mac);
int is_trusted_mac(const char *mac);

int add_to_blocked_mac_list(const char possiblemac[]);
int remove_from_blocked_mac_list(const char possiblemac[]);

int add_to_allowed_mac_list(const char possiblemac[]);
int remove_from_allowed_mac_list(const char possiblemac[]);

int remove_from_trusted_mac_list(const char possiblemac[]);
int add_to_trusted_mac_list(const char possiblemac[]);

int check_ip_format(const char[]);
int check_mac_format(const char[]);

/** config API, used in commandline.c */
int set_debuglevel(const char[]);

#define LOCK_CONFIG() do { \
	debug(LOG_DEBUG, "Locking config"); \
	pthread_mutex_lock(&config_mutex); \
	debug(LOG_DEBUG, "Config locked"); \
} while (0)

#define UNLOCK_CONFIG() do { \
	debug(LOG_DEBUG, "Unlocking config"); \
	pthread_mutex_unlock(&config_mutex); \
	debug(LOG_DEBUG, "Config unlocked"); \
} while (0)

#endif /* _CONF_H_ */
