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
			if (rc == -1) {
				if (errno == ECHILD) {
					debug(LOG_DEBUG, "waitpid(): No child exists now. Assuming normal exit for PID %d", (int)pid);
					retval = 0;
				} else {
					debug(LOG_ERR, "Error waiting for child (waitpid() returned -1): %s", strerror(errno));
					retval = -1;
				}
				break;
			}
			if (WIFEXITED(status)) {
				debug(LOG_DEBUG, "Process PID %d exited normally, status %d", (int)rc, WEXITSTATUS(status));
				retval = (WEXITSTATUS(status));
			}
			if (WIFSIGNALED(status)) {
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

	if (getifaddrs(&addrs) < 0) {
		debug(LOG_ERR, "getifaddrs(): %s", strerror(errno));
		return NULL;
	}

	config = config_get_config();

	/* Set default address */
	sprintf(addrbuf, config->ip6 ? "::" : "0.0.0.0");

	/* Iterate all interfaces */
	cur = addrs;
	while(cur != NULL) {
		if ( (cur->ifa_addr != NULL) && (strcmp( cur->ifa_name, ifname ) == 0) ) {

			if (config->ip6 && cur->ifa_addr->sa_family == AF_INET6) {
				inet_ntop(AF_INET6, &((struct sockaddr_in6 *)cur->ifa_addr)->sin6_addr, addrbuf, sizeof(addrbuf));
				break;
			}

			if (!config->ip6 && cur->ifa_addr->sa_family == AF_INET) {
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
	char *hwaddr, mac[18];

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
	snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
		hwaddr[0] & 0xFF, hwaddr[1] & 0xFF, hwaddr[2] & 0xFF,
		hwaddr[3] & 0xFF, hwaddr[4] & 0xFF, hwaddr[5] & 0xFF
	);

	return safe_strdup(mac);
#elif defined(__NetBSD__)
	struct ifaddrs *ifa, *ifap;
	const char *hwaddr;
	char mac[18], *str = NULL;
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
	snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
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
	pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
	pthread_mutex_t cond_mutex = PTHREAD_MUTEX_INITIALIZER;
	struct timespec timeout;
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
				fclose(input);
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
	char *str = NULL;

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

/* Custom print format string to file descriptor */
void
cprintf( int fd, const char *format, ... ) {
	char buffer[256];
	va_list vlist;
	int rc;

	va_start( vlist, format );
	rc = vsnprintf( buffer, sizeof(buffer), format, vlist );
	va_end( vlist );

	if (rc > 0 && rc < sizeof(buffer)) {
		write(fd, buffer, strlen(buffer));
	} else {
		debug(LOG_ERR, "failed to write format string: %s", format);
	}
}

void
ndsctl_status(int fd)
{
	char timebuf[32];
	char *str;
	s_config *config;
	t_client *client;
	int indx;
	unsigned long int now, uptimesecs, durationsecs = 0;
	unsigned long long int download_bytes, upload_bytes;
	t_MAC *trust_mac;
	t_MAC *allow_mac;
	t_MAC *block_mac;

	config = config_get_config();

	cprintf(fd, "==================\nNoDogSplash Status\n====\n");

	now = time(NULL);
	uptimesecs = now - started_time;

	cprintf(fd, "Version: " VERSION "\n");

	str = format_time(uptimesecs);
	cprintf(fd, "Uptime: %s\n", str);
	free(str);

	cprintf(fd, "Gateway Name: %s\n", config->gw_name);
	cprintf(fd, "Managed interface: %s\n", config->gw_interface);
	cprintf(fd, "Managed IP range: %s\n", config->gw_iprange);
	cprintf(fd, "Server listening: %s:%d\n", config->gw_address, config->gw_port);

	if (config->authenticate_immediately) {
		cprintf(fd, "Authenticate immediately: yes\n");
	} else {
		cprintf(fd, "Splashpage: %s/%s\n", config->webroot, config->splashpage);
	}

	if (config->redirectURL) {
		cprintf(fd, "Redirect URL: %s\n", config->redirectURL);
	}

	if (config->passwordauth) {
		cprintf(fd, "Gateway password: %s\n", config->password);
	}

	if (config->usernameauth) {
		cprintf(fd, "Gateway username: %s\n", config->username);
	}

	cprintf(fd, "Traffic control: %s\n", config->traffic_control ? "yes" : "no");

	if (config->traffic_control) {
		if (config->download_limit > 0) {
			cprintf(fd, "Download rate limit: %d kbit/s\n", config->download_limit);
		} else {
			cprintf(fd, "Download rate limit: none\n");
		}
		if (config->upload_limit > 0) {
			cprintf(fd, "Upload rate limit: %d kbit/s\n", config->upload_limit);
		} else {
			cprintf(fd, "Upload rate limit: none\n");
		}
	}

	download_bytes = iptables_fw_total_download();
	cprintf(fd, "Total download: %llu kByte", download_bytes/1000);
	cprintf(fd, "; avg: %.6g kbit/s\n", ((double) download_bytes) / 125 / uptimesecs);

	upload_bytes = iptables_fw_total_upload();
	cprintf(fd, "Total upload: %llu kByte", upload_bytes/1000);
	cprintf(fd, "; avg: %.6g kbit/s\n", ((double) upload_bytes) / 125 / uptimesecs);
	cprintf(fd, "====\n");
	cprintf(fd, "Client authentications since start: %u\n", authenticated_since_start);

	if (config->decongest_httpd_threads) {
		cprintf(fd, "Httpd thread decongest threshold: %d threads\n", config->httpd_thread_threshold);
		cprintf(fd, "Httpd thread decongest delay: %d ms\n", config->httpd_thread_delay_ms);
	}

	/* Update the client's counters so info is current */
	iptables_fw_counters_update();

	LOCK_CLIENT_LIST();

	cprintf(fd, "Current clients: %d\n", get_client_list_length());

	client = client_get_first_client();
	if (client) {
		cprintf(fd, "\n");
	}

	indx = 0;
	while (client != NULL) {
		cprintf(fd, "Client %d\n", indx);

		cprintf(fd, "  IP: %s MAC: %s\n", client->ip, client->mac);

		ctime_r(&(client->added_time),timebuf);
		cprintf(fd, "  Added:   %s", timebuf);

		ctime_r(&(client->counters.last_updated),timebuf);
		cprintf(fd, "  Active:  %s", timebuf);

		str = format_time(client->counters.last_updated - client->added_time);
		cprintf(fd, "  Active duration: %s\n", str);
		free(str);

		if (now > client->added_time) {
			durationsecs = now - client->added_time;
		} else {
			// prevent divison by 0 later
			durationsecs = 1;
		}

		str = format_time(durationsecs);
		cprintf(fd, "  Added duration:  %s\n", str);
		free(str);

		cprintf(fd, "  Token: %s\n", client->token ? client->token : "none");

		cprintf(fd, "  State: %s\n", fw_connection_state_as_string(client->fw_connection_state));

		download_bytes = client->counters.incoming;
		upload_bytes = client->counters.outgoing;

		cprintf(fd, "  Download: %llu kByte; avg: %.6g kbit/s\n  Upload:   %llu kByte; avg: %.6g kbit/s\n\n",
				download_bytes/1000, ((double)download_bytes)/125/durationsecs,
				upload_bytes/1000, ((double)upload_bytes)/125/durationsecs);

		indx++;
		client = client->next;
	}

	UNLOCK_CLIENT_LIST();

	cprintf(fd, "====\n");

	cprintf(fd, "Blocked MAC addresses:");

	if (config->macmechanism == MAC_ALLOW) {
		cprintf(fd, " N/A\n");
	} else  if (config->blockedmaclist != NULL) {
		cprintf(fd, "\n");
		for (block_mac = config->blockedmaclist; block_mac != NULL; block_mac = block_mac->next) {
			cprintf(fd, "  %s\n", block_mac->mac);
		}
	} else {
		cprintf(fd, " none\n");
	}

	cprintf(fd, "Allowed MAC addresses:");

	if (config->macmechanism == MAC_BLOCK) {
		cprintf(fd, " N/A\n");
	} else  if (config->allowedmaclist != NULL) {
		cprintf(fd, "\n");
		for (allow_mac = config->allowedmaclist; allow_mac != NULL; allow_mac = allow_mac->next) {
			cprintf(fd, "  %s\n", allow_mac->mac);
		}
	} else {
		cprintf(fd, " none\n");
	}

	cprintf(fd, "Trusted MAC addresses:");

	if (config->trustedmaclist != NULL) {
		cprintf(fd, "\n");
		for (trust_mac = config->trustedmaclist; trust_mac != NULL; trust_mac = trust_mac->next) {
			cprintf(fd, "  %s\n", trust_mac->mac);
		}
	} else {
		cprintf(fd, " none\n");
	}

	cprintf(fd, "========\n");
}

void
ndsctl_clients(int fd)
{
	t_client *client;
	int indx;
	unsigned long int now, durationsecs = 0;
	unsigned long long int download_bytes, upload_bytes;

	now = time(NULL);

	/* Update the client's counters so info is current */
	iptables_fw_counters_update();

	LOCK_CLIENT_LIST();

	cprintf(fd, "%d\n", get_client_list_length());

	client = client_get_first_client();
	if (client) {
		cprintf(fd, "\n");
	}

	indx = 0;
	while (client != NULL) {
		cprintf(fd, "client_id=%d\n", indx);
		cprintf(fd, "ip=%s\nmac=%s\n", client->ip, client->mac);
		cprintf(fd, "added=%lld\n", (long long) client->added_time);
		cprintf(fd, "active=%lld\n", (long long) client->counters.last_updated);
		cprintf(fd, "duration=%lu\n", now - client->added_time);
		cprintf(fd, "token=%s\n", client->token ? client->token : "none");
		cprintf(fd, "state=%s\n", fw_connection_state_as_string(client->fw_connection_state));

		durationsecs = now - client->added_time;
		download_bytes = client->counters.incoming;
		upload_bytes = client->counters.outgoing;

		cprintf(fd, "downloaded=%llu\navg_down_speed=%.6g\nuploaded=%llu\navg_up_speed=%.6g\n\n",
				download_bytes/1000, ((double)download_bytes)/125/durationsecs,
				upload_bytes/1000, ((double)upload_bytes)/125/durationsecs);

		indx++;
		client = client->next;
	}

	UNLOCK_CLIENT_LIST();
}

void
ndsctl_json(int fd)
{
	t_client *client;
	int indx;
	unsigned long int now, durationsecs = 0;
	unsigned long long int download_bytes, upload_bytes;

	now = time(NULL);

	/* Update the client's counters so info is current */
	iptables_fw_counters_update();

	LOCK_CLIENT_LIST();

	cprintf(fd, "{\n\"client_length\": %d,\n", get_client_list_length());

	client = client_get_first_client();
	indx = 0;

	cprintf(fd, "\"clients\":{\n");

	while (client != NULL) {
		cprintf(fd, "\"%s\":{\n", client->mac);
		cprintf(fd, "\"client_id\":%d,\n", indx);
		cprintf(fd, "\"ip\":\"%s\",\n\"mac\":\"%s\",\n", client->ip, client->mac);
		cprintf(fd, "\"added\":%lld,\n", (long long) client->added_time);
		cprintf(fd, "\"active\":%lld,\n", (long long) client->counters.last_updated);
		cprintf(fd, "\"duration\":%lu,\n", now - client->added_time);
		cprintf(fd, "\"token\":\"%s\",\n", client->token ? client->token : "none");
		cprintf(fd, "\"state\":\"%s\",\n", fw_connection_state_as_string(client->fw_connection_state));

		durationsecs = now - client->added_time;
		download_bytes = client->counters.incoming;
		upload_bytes = client->counters.outgoing;

		cprintf(fd, "\"downloaded\":\"%llu\",\n\"avg_down_speed\":\"%.6g\",\n\"uploaded\":\"%llu\",\n\"avg_up_speed\":\"%.6g\"\n",
			download_bytes/1000, ((double)download_bytes)/125/durationsecs,
			upload_bytes/1000, ((double)upload_bytes)/125/durationsecs);

		indx++;
		client = client->next;

		cprintf(fd, "}");
		if (client) {
			cprintf(fd, ",\n");
		}
	}

	cprintf(fd, "}}" );

	UNLOCK_CLIENT_LIST();
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
