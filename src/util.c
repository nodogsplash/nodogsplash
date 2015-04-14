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
 * $Id: util.c 1162 2007-01-06 23:51:02Z benoitg $
 */
/**
  @file util.c
  @brief Misc utility functions
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
  @author Copyright (C) 2006 Benoit Grégoire <bock@step.polymtl.ca>
  @author Copyright (C) 2008 Paul Kube <nodogsplash@kokoro.ucsd.edu>
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
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <ifaddrs.h>

#if defined(__NetBSD__)
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <util.h>
#endif

#ifdef __linux__
#include <netinet/in.h>
#include <net/if.h>
#endif

#include <string.h>
#include <pthread.h>
#include <netdb.h>

#include "common.h"
#include "client_list.h"
#include "safe.h"
#include "util.h"
#include "conf.h"
#include "debug.h"
#include "firewall.h"
#include "fw_iptables.h"


static pthread_mutex_t ghbn_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Defined in gateway.c */
extern time_t started_time;

/* Defined in clientlist.c */
extern pthread_mutex_t client_list_mutex;
extern pthread_mutex_t config_mutex;

/* Defined in auth.c */
extern unsigned int authenticated_since_start;

/* Defined in gateway.c */
extern int created_httpd_threads;
extern int current_httpd_threads;


/** Fork a child and execute a shell command.
 * The parent process waits for the child to return,
 * and returns the child's exit() value.
 * @return Return code of the command
 */
int
execute(const char cmd_line[], int quiet)
{
	int status, retval;
	pid_t pid, rc;
	struct sigaction sa, oldsa;
	const char *new_argv[4];
	new_argv[0] = "/bin/sh";
	new_argv[1] = "-c";
	new_argv[2] = cmd_line;
	new_argv[3] = NULL;

	/* Temporarily get rid of SIGCHLD handler (see gateway.c), until child exits.
	 * Will handle SIGCHLD here with waitpid() in the parent. */
	debug(LOG_DEBUG,"Setting default SIGCHLD handler SIG_DFL");
	sa.sa_handler = SIG_DFL;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_NOCLDSTOP | SA_RESTART;
	if (sigaction(SIGCHLD, &sa, &oldsa) == -1) {
		debug(LOG_ERR, "sigaction() failed to set default SIGCHLD handler: %s", strerror(errno));
	}

	pid = safe_fork();

	if (pid == 0) {    /* for the child process:         */

		if (quiet) close(2); /* Close stderr if quiet flag is on */
		if (execvp("/bin/sh", (char *const *)new_argv) == -1) {    /* execute the command  */
			debug(LOG_ERR, "execvp(): %s", strerror(errno));
		} else {
			debug(LOG_ERR, "execvp() failed");
		}
		exit(1);

	} else {        /* for the parent:      */

		debug(LOG_DEBUG, "Waiting for PID %d to exit", (int)pid);
		do {
			rc = waitpid(pid, &status, 0);
			if(rc == -1) {
				if(errno == ECHILD) {
					debug(LOG_DEBUG, "waitpid(): No child exists now. Assuming normal exit for PID %d", (int)pid);
					retval = 0;
				} else {
					debug(LOG_ERR, "Error waiting for child (waitpid() returned -1): %s", strerror(errno));
					retval = -1;
				}
				break;
			}
			if(WIFEXITED(status)) {
				debug(LOG_DEBUG, "Process PID %d exited normally, status %d", (int)rc, WEXITSTATUS(status));
				retval = (WEXITSTATUS(status));
			}
			if(WIFSIGNALED(status)) {
				debug(LOG_DEBUG, "Process PID %d exited due to signal %d", (int)rc, WTERMSIG(status));
				retval = -1;
			}
		} while (!WIFEXITED(status) && !WIFSIGNALED(status));

		debug(LOG_DEBUG, "Restoring previous SIGCHLD handler");
		if (sigaction(SIGCHLD, &oldsa, NULL) == -1) {
			debug(LOG_ERR, "sigaction() failed to restore SIGCHLD handler! Error %s", strerror(errno));
		}

		return retval;
	}
}

struct in_addr *
wd_gethostbyname(const char name[]) {
	struct hostent *he;
	struct in_addr *h_addr, *in_addr_temp;

	/* XXX Calling function is reponsible for free() */

	h_addr = safe_malloc(sizeof(struct in_addr));

	LOCK_GHBN();

	he = gethostbyname(name);

	if (he == NULL) {
		free(h_addr);
		UNLOCK_GHBN();
		return NULL;
	}

	in_addr_temp = (struct in_addr *)he->h_addr_list[0];
	h_addr->s_addr = in_addr_temp->s_addr;

	UNLOCK_GHBN();

	return h_addr;
}

char *
get_iface_ip(const char ifname[])
{
	char addrbuf[INET6_ADDRSTRLEN+1];
	const struct ifaddrs *cur;
	struct ifaddrs *addrs;
	s_config *config;
	int sockd;

	if(getifaddrs(&addrs) < 0) {
		debug(LOG_ERR, "getifaddrs(): %s", strerror(errno));
		return NULL;
	}

	config = config_get_config();

	/* Set default address */
	sprintf(addrbuf, config->ip6 ? "::" : "0.0.0.0");

	/* Iterate all interfaces */
	cur = addrs;
	while(cur != NULL) {
		if( (cur->ifa_addr != NULL) && (strcmp( cur->ifa_name, ifname ) == 0) ) {

			if(config->ip6 && cur->ifa_addr->sa_family == AF_INET6) {
				inet_ntop(AF_INET6, &((struct sockaddr_in6 *)cur->ifa_addr)->sin6_addr, addrbuf, sizeof(addrbuf));
				break;
			}

			if(!config->ip6 && cur->ifa_addr->sa_family == AF_INET) {
				inet_ntop(AF_INET, &((struct sockaddr_in *)cur->ifa_addr)->sin_addr, addrbuf, sizeof(addrbuf));
				break;
			}
		}

		cur = cur->ifa_next;
	}

	freeifaddrs(addrs);

	return safe_strdup(addrbuf);
}

char *
get_iface_mac(const char ifname[])
{
#if defined(__linux__)
	int r, s;
	s_config *config;
	struct ifreq ifr;
	char *hwaddr, mac[13];

	config = config_get_config();
	strcpy(ifr.ifr_name, ifname);

	s = socket(config->ip6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
	if (-1 == s) {
		debug(LOG_ERR, "get_iface_mac socket: %s", strerror(errno));
		return NULL;
	}

	r = ioctl(s, SIOCGIFHWADDR, &ifr);
	if (r == -1) {
		debug(LOG_ERR, "get_iface_mac ioctl(SIOCGIFHWADDR): %s", strerror(errno));
		close(s);
		return NULL;
	}

	hwaddr = ifr.ifr_hwaddr.sa_data;
	close(s);
	snprintf(mac, sizeof(mac), "%02X%02X%02X%02X%02X%02X",
			 hwaddr[0] & 0xFF,
			 hwaddr[1] & 0xFF,
			 hwaddr[2] & 0xFF,
			 hwaddr[3] & 0xFF,
			 hwaddr[4] & 0xFF,
			 hwaddr[5] & 0xFF
			);

	return safe_strdup(mac);
#elif defined(__NetBSD__)
	struct ifaddrs *ifa, *ifap;
	const char *hwaddr;
	char mac[13], *str = NULL;
	struct sockaddr_dl *sdl;

	if (getifaddrs(&ifap) == -1) {
		debug(LOG_ERR, "getifaddrs(): %s", strerror(errno));
		return NULL;
	}
	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
		if (strcmp(ifa->ifa_name, ifname) == 0 &&
				ifa->ifa_addr->sa_family == AF_LINK)
			break;
	}
	if (ifa == NULL) {
		debug(LOG_ERR, "%s: no link-layer address assigned");
		goto out;
	}
	sdl = (struct sockaddr_dl *)ifa->ifa_addr;
	hwaddr = LLADDR(sdl);
	snprintf(mac, sizeof(mac), "%02X%02X%02X%02X%02X%02X",
			 hwaddr[0] & 0xFF, hwaddr[1] & 0xFF,
			 hwaddr[2] & 0xFF, hwaddr[3] & 0xFF,
			 hwaddr[4] & 0xFF, hwaddr[5] & 0xFF);

	str = safe_strdup(mac);
out:
	freeifaddrs(ifap);
	return str;
#else
	return NULL;
#endif
}

/** Get name of external interface (the one with default route to the net).
 *  Caller must free.
 */
char *
get_ext_iface (void)
{
#ifdef __linux__
	FILE *input;
	char *device, *gw;
	int i = 1;
	int keep_detecting = 1;
	pthread_cond_t		cond = PTHREAD_COND_INITIALIZER;
	pthread_mutex_t		cond_mutex = PTHREAD_MUTEX_INITIALIZER;
	struct	timespec	timeout;
	device = (char *)malloc(16);
	gw = (char *)malloc(16);
	debug(LOG_DEBUG, "get_ext_iface(): Autodectecting the external interface from routing table");
	while(keep_detecting) {
		input = fopen("/proc/net/route", "r");
		while (!feof(input)) {
			/* XXX scanf(3) is unsafe, risks overrun */
			fscanf(input, "%s %s %*s %*s %*s %*s %*s %*s %*s %*s %*s\n", device, gw);
			if (strcmp(gw, "00000000") == 0) {
				free(gw);
				debug(LOG_INFO, "get_ext_iface(): Detected %s as the default interface after try %d", device, i);
				return device;
			}
		}
		fclose(input);
		debug(LOG_ERR, "get_ext_iface(): Failed to detect the external interface after try %d (maybe the interface is not up yet?).  Retry limit: %d", i, NUM_EXT_INTERFACE_DETECT_RETRY);
		/* Sleep for EXT_INTERFACE_DETECT_RETRY_INTERVAL seconds */
		timeout.tv_sec = time(NULL) + EXT_INTERFACE_DETECT_RETRY_INTERVAL;
		timeout.tv_nsec = 0;
		/* Mutex must be locked for pthread_cond_timedwait... */
		pthread_mutex_lock(&cond_mutex);
		/* Thread safe "sleep" */
		pthread_cond_timedwait(&cond, &cond_mutex, &timeout);
		/* No longer needs to be locked */
		pthread_mutex_unlock(&cond_mutex);
		//for (i=1; i<=NUM_EXT_INTERFACE_DETECT_RETRY; i++) {
		if (NUM_EXT_INTERFACE_DETECT_RETRY != 0 && i>NUM_EXT_INTERFACE_DETECT_RETRY) {
			keep_detecting = 0;
		}
		i++;
	}
	debug(LOG_ERR, "get_ext_iface(): Failed to detect the external interface after %d tries, aborting", i);
	exit(1);
	free(device);
	free(gw);
#endif
	return NULL;
}

/* Malloc's */
char *
format_time(unsigned long int secs)
{
	unsigned int days, hours, minutes, seconds;
	char * str;

	days = secs / (24 * 60 * 60);
	secs -= days * (24 * 60 * 60);
	hours = secs / (60 * 60);
	secs -= hours * (60 * 60);
	minutes = secs / 60;
	secs -= minutes * 60;
	seconds = secs;

	safe_asprintf(&str,"%ud %uh %um %us", days, hours, minutes, seconds);
	return str;
}

/* Caller must free. */
char *
get_uptime_string()
{
	return format_time(time(NULL)-started_time);
}

/*
 * @return A string containing human-readable status text.
 * MUST BE free()d by caller
 */
char *
get_status_text()
{
	char buffer[STATUS_BUF_SIZ];
	char timebuf[32];
	char * str;
	ssize_t len;
	s_config *config;
	t_client *client;
	int	   indx;
	unsigned long int now, uptimesecs, durationsecs = 0;
	unsigned long long int download_bytes, upload_bytes;
	t_MAC *trust_mac;
	t_MAC *allow_mac;
	t_MAC *block_mac;

	config = config_get_config();

	len = 0;
	snprintf(buffer, (sizeof(buffer) - len), "==================\nNoDogSplash Status\n====\n");
	len = strlen(buffer);

	now = time(NULL);
	uptimesecs = now - started_time;

	snprintf((buffer + len), (sizeof(buffer) - len), "Version: " VERSION "\n");
	len = strlen(buffer);

	str = format_time(uptimesecs);
	snprintf((buffer + len), (sizeof(buffer) - len), "Uptime: %s\n", str);
	len = strlen(buffer);
	free(str);

	snprintf((buffer + len), (sizeof(buffer) - len), "Gateway Name: %s\n", config->gw_name);
	len = strlen(buffer);

	snprintf((buffer + len), (sizeof(buffer) - len), "Managed interface: %s\n", config->gw_interface);
	len = strlen(buffer);

	snprintf((buffer + len), (sizeof(buffer) - len), "Managed IP range: %s\n", config->gw_iprange);
	len = strlen(buffer);

	snprintf((buffer + len), (sizeof(buffer) - len), "Server listening: %s:%d\n",
			 config->gw_address, config->gw_port);
	len = strlen(buffer);

	if(config->authenticate_immediately) {
		snprintf((buffer + len), (sizeof(buffer) - len), "Authenticate immediately: yes\n");
		len = strlen(buffer);

	} else {
		snprintf((buffer + len), (sizeof(buffer) - len), "Splashpage: %s/%s\n",
				 config->webroot, config->splashpage);
		len = strlen(buffer);
	}

	if(config->redirectURL) {
		snprintf((buffer + len), (sizeof(buffer) - len), "Redirect URL: %s\n",
				 config->redirectURL);
		len = strlen(buffer);
	}

	if(config->passwordauth) {
		snprintf((buffer + len), (sizeof(buffer) - len), "Gateway password: %s\n",
				 config->password);
		len = strlen(buffer);
	}

	if(config->usernameauth) {
		snprintf((buffer + len), (sizeof(buffer) - len), "Gateway username: %s\n",
				 config->username);
		len = strlen(buffer);
	}

	snprintf((buffer + len), (sizeof(buffer) - len), "Traffic control: %s\n", config->traffic_control ? "yes" : "no");
	len = strlen(buffer);

	if(config->traffic_control) {
		if(config->download_limit > 0) {
			snprintf((buffer + len), (sizeof(buffer) - len), "Download rate limit: %d kbit/s\n", config->download_limit);
			len = strlen(buffer);
		} else {
			snprintf((buffer + len), (sizeof(buffer) - len), "Download rate limit: none\n");
			len = strlen(buffer);
		}
		if(config->upload_limit > 0) {
			snprintf((buffer + len), (sizeof(buffer) - len), "Upload rate limit: %d kbit/s\n", config->upload_limit);
			len = strlen(buffer);
		} else {
			snprintf((buffer + len), (sizeof(buffer) - len), "Upload rate limit: none\n");
			len = strlen(buffer);
		}
	}

	download_bytes = iptables_fw_total_download();
	snprintf((buffer + len), (sizeof(buffer) - len), "Total download: %llu kByte", download_bytes/1000);
	len = strlen(buffer);
	snprintf((buffer + len), (sizeof(buffer) - len), "; avg: %.6g kbit/s\n", ((double) download_bytes) / 125 / uptimesecs);
	len = strlen(buffer);

	upload_bytes = iptables_fw_total_upload();
	snprintf((buffer + len), (sizeof(buffer) - len), "Total upload: %llu kByte", upload_bytes/1000);
	len = strlen(buffer);
	snprintf((buffer + len), (sizeof(buffer) - len), "; avg: %.6g kbit/s\n", ((double) upload_bytes) / 125 / uptimesecs);
	len = strlen(buffer);

	snprintf((buffer + len), (sizeof(buffer) - len), "====\n");
	len = strlen(buffer);

	snprintf((buffer + len), (sizeof(buffer) - len), "Client authentications since start: %u\n", authenticated_since_start);
	len = strlen(buffer);

	snprintf((buffer + len), (sizeof(buffer) - len), "Httpd request threads created/current: %d/%d\n", created_httpd_threads, current_httpd_threads);
	len = strlen(buffer);

	if(config->decongest_httpd_threads) {
		snprintf((buffer + len), (sizeof(buffer) - len), "Httpd thread decongest threshold: %d threads\n", config->httpd_thread_threshold);
		len = strlen(buffer);
		snprintf((buffer + len), (sizeof(buffer) - len), "Httpd thread decongest delay: %d ms\n", config->httpd_thread_delay_ms);
		len = strlen(buffer);
	}

	/* Update the client's counters so info is current */
	iptables_fw_counters_update();

	LOCK_CLIENT_LIST();

	snprintf((buffer + len), (sizeof(buffer) - len), "Current clients: %d\n", get_client_list_length());
	len = strlen(buffer);

	client = client_get_first_client();
	if(client) {
		snprintf((buffer + len), (sizeof(buffer) - len), "\n");
		len = strlen(buffer);
	}
	indx = 0;
	while (client != NULL) {
		snprintf((buffer + len), (sizeof(buffer) - len), "Client %d\n", indx);
		len = strlen(buffer);

		snprintf((buffer + len), (sizeof(buffer) - len), "  IP: %s MAC: %s\n", client->ip, client->mac);
		len = strlen(buffer);

		ctime_r(&(client->added_time),timebuf);
		snprintf((buffer + len), (sizeof(buffer) - len), "  Added:   %s", timebuf);
		len = strlen(buffer);

		ctime_r(&(client->counters.last_updated),timebuf);
		snprintf((buffer + len), (sizeof(buffer) - len), "  Active:  %s", timebuf);
		len = strlen(buffer);

		str = format_time(client->counters.last_updated - client->added_time);
		snprintf((buffer + len), (sizeof(buffer) - len), "  Active duration: %s\n", str);
		len = strlen(buffer);
		free(str);

		durationsecs = now - client->added_time;

		str = format_time(durationsecs);
		snprintf((buffer + len), (sizeof(buffer) - len), "  Added duration:  %s\n", str);
		len = strlen(buffer);
		free(str);

		snprintf((buffer + len), (sizeof(buffer) - len), "  Token: %s\n", client->token ? client->token : "none");
		len = strlen(buffer);

		snprintf((buffer + len), (sizeof(buffer) - len), "  State: %s\n",
				 fw_connection_state_as_string(client->fw_connection_state));
		len = strlen(buffer);

		download_bytes = client->counters.incoming;
		upload_bytes = client->counters.outgoing;

		snprintf((buffer + len), (sizeof(buffer) - len),
				 "  Download: %llu kByte; avg: %.6g kbit/s\n  Upload:   %llu kByte; avg: %.6g kbit/s\n\n",
				 download_bytes/1000, ((double)download_bytes)/125/durationsecs,
				 upload_bytes/1000, ((double)upload_bytes)/125/durationsecs);
		len = strlen(buffer);

		indx++;
		client = client->next;
	}

	UNLOCK_CLIENT_LIST();

	snprintf((buffer + len), (sizeof(buffer) - len), "====\n");
	len = strlen(buffer);

	snprintf((buffer + len), (sizeof(buffer) - len), "Blocked MAC addresses:");
	len = strlen(buffer);

	if(config->macmechanism == MAC_ALLOW) {
		snprintf((buffer + len), (sizeof(buffer) - len), " N/A\n");
		len = strlen(buffer);
	} else  if (config->blockedmaclist != NULL) {
		snprintf((buffer + len), (sizeof(buffer) - len), "\n");
		len = strlen(buffer);
		for (block_mac = config->blockedmaclist; block_mac != NULL; block_mac = block_mac->next) {
			snprintf((buffer + len), (sizeof(buffer) - len), "  %s\n", block_mac->mac);
			len = strlen(buffer);
		}
	} else {
		snprintf((buffer + len), (sizeof(buffer) - len), " none\n");
		len = strlen(buffer);
	}

	snprintf((buffer + len), (sizeof(buffer) - len), "Allowed MAC addresses:");
	len = strlen(buffer);

	if(config->macmechanism == MAC_BLOCK) {
		snprintf((buffer + len), (sizeof(buffer) - len), " N/A\n");
		len = strlen(buffer);
	} else  if (config->allowedmaclist != NULL) {
		snprintf((buffer + len), (sizeof(buffer) - len), "\n");
		len = strlen(buffer);
		for (allow_mac = config->allowedmaclist; allow_mac != NULL; allow_mac = allow_mac->next) {
			snprintf((buffer + len), (sizeof(buffer) - len), "  %s\n", allow_mac->mac);
			len = strlen(buffer);
		}
	} else {
		snprintf((buffer + len), (sizeof(buffer) - len), " none\n");
		len = strlen(buffer);
	}

	snprintf((buffer + len), (sizeof(buffer) - len), "Trusted MAC addresses:");
	len = strlen(buffer);

	if (config->trustedmaclist != NULL) {
		snprintf((buffer + len), (sizeof(buffer) - len), "\n");
		len = strlen(buffer);
		for (trust_mac = config->trustedmaclist; trust_mac != NULL; trust_mac = trust_mac->next) {
			snprintf((buffer + len), (sizeof(buffer) - len), "  %s\n", trust_mac->mac);
			len = strlen(buffer);
		}
	} else {
		snprintf((buffer + len), (sizeof(buffer) - len), " none\n");
		len = strlen(buffer);
	}

	snprintf((buffer + len), (sizeof(buffer) - len), "========\n");
	len = strlen(buffer);

	return safe_strdup(buffer);
}

/*
 * @return A string containing machine-readable clients list.
 * MUST BE free()d by caller
 */
char *
get_clients_text(void)
{
	char buffer[STATUS_BUF_SIZ];
	ssize_t len;
	t_client *client;
	int	   indx;
	unsigned long int now, durationsecs = 0;
	unsigned long long int download_bytes, upload_bytes;

	now = time(NULL);
	len = 0;

	/* Update the client's counters so info is current */
	iptables_fw_counters_update();

	LOCK_CLIENT_LIST();

	snprintf((buffer + len), (sizeof(buffer) - len), "%d\n", get_client_list_length());
	len = strlen(buffer);

	client = client_get_first_client();
	if(client) {
		snprintf((buffer + len), (sizeof(buffer) - len), "\n");
		len = strlen(buffer);
	}
	indx = 0;
	while (client != NULL) {
		snprintf((buffer + len), (sizeof(buffer) - len), "client_id=%d\n", indx);
		len = strlen(buffer);

		snprintf((buffer + len), (sizeof(buffer) - len), "ip=%s\nmac=%s\n", client->ip, client->mac);
		len = strlen(buffer);

		snprintf((buffer + len), (sizeof(buffer) - len), "added=%lld\n", (long long) client->added_time);
		len = strlen(buffer);

		snprintf((buffer + len), (sizeof(buffer) - len), "active=%lld\n", (long long) client->counters.last_updated);
		len = strlen(buffer);

		snprintf((buffer + len), (sizeof(buffer) - len), "duration=%lu\n", now - client->added_time);
		len = strlen(buffer);

		snprintf((buffer + len), (sizeof(buffer) - len), "token=%s\n", client->token ? client->token : "none");
		len = strlen(buffer);

		snprintf((buffer + len), (sizeof(buffer) - len), "state=%s\n",
				 fw_connection_state_as_string(client->fw_connection_state));
		len = strlen(buffer);

		durationsecs = now - client->added_time;
		download_bytes = client->counters.incoming;
		upload_bytes = client->counters.outgoing;

		snprintf((buffer + len), (sizeof(buffer) - len),
				 "downloaded=%llu\navg_down_speed=%.6g\nuploaded=%llu\navg_up_speed=%.6g\n\n",
				 download_bytes/1000, ((double)download_bytes)/125/durationsecs,
				 upload_bytes/1000, ((double)upload_bytes)/125/durationsecs);
		len = strlen(buffer);

		indx++;
		client = client->next;
	}

	UNLOCK_CLIENT_LIST();

	return safe_strdup(buffer);
}

unsigned short
rand16(void)
{
	static int been_seeded = 0;

	if (!been_seeded) {
		unsigned int seed = 0;
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
