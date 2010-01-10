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

#ifdef __linux__
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

#include "../config.h"

static pthread_mutex_t ghbn_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Defined in gateway.c */
extern time_t started_time;

/* Defined in clientlist.c */
extern	pthread_mutex_t	client_list_mutex;
extern	pthread_mutex_t	config_mutex;

/* Defined in commandline.c */
extern pid_t restart_orig_pid;

/* XXX Do these need to be locked ? */
static time_t last_online_time = 0;
static time_t last_offline_time = 0;
static time_t last_auth_online_time = 0;
static time_t last_auth_offline_time = 0;

long authenticated_this_session = 0;

/** Fork a child and execute a shell command, the parent
 * process waits for the child to return and returns the child's exit()
 * value.
 * @return Return code of the command
 */
int
execute(char *cmd_line, int quiet) {
  int pid,
    status,
    rc;

  const char *new_argv[4];
  new_argv[0] = "/bin/sh";
  new_argv[1] = "-c";
  new_argv[2] = cmd_line;
  new_argv[3] = NULL;

  pid = safe_fork();
  if (pid == 0) {    /* for the child process:         */
    /* We don't want to see any errors if quiet flag is on */
    if (quiet) close(2);
    if (execvp("/bin/sh", (char *const *)new_argv) < 0) {    /* execute the command  */
      debug(LOG_ERR, "execvp(): %s", strerror(errno));
      exit(1);
    }
  }
  else {        /* for the parent:      */
    debug(LOG_DEBUG, "Waiting for PID %d to exit", pid);
    rc = waitpid(pid, &status, 0);
    debug(LOG_DEBUG, "Process PID %d exited", rc);
  }

  return (WEXITSTATUS(status));
}

struct in_addr *
wd_gethostbyname(const char *name) {
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

char *get_iface_ip(char *ifname) {
#ifdef __linux__
  struct ifreq if_data;
#endif
  struct in_addr in;
  char *ip_str;
  int sockd;
  u_int32_t ip;

#ifdef __linux__
    
  /* Create a socket.  SOCK_PACKET is obsolete */
  if ((sockd = socket (PF_INET, SOCK_RAW, htons(0x8086))) < 0) {
    debug(LOG_ERR, "socket(): %s", strerror(errno));
    return NULL;
  }

  /* Get IP of internal interface */
  strcpy (if_data.ifr_name, ifname);

  /* Get the IP address */
  if (ioctl (sockd, SIOCGIFADDR, &if_data) < 0) {
    debug(LOG_ERR, "Finding IP for %s: ioctl(): SIOCGIFADDR %s", ifname,strerror(errno));
    return NULL;
  }
  memcpy ((void *) &ip, (void *) &if_data.ifr_addr.sa_data + 2, 4);
  in.s_addr = ip;

  ip_str = (char *)inet_ntoa(in);
  return safe_strdup(ip_str);
#else
  return safe_strdup("0.0.0.0");
#endif
}

char *get_iface_mac (char *ifname) {
#ifdef __linux__
  int r, s;
  struct ifreq ifr;
  char *hwaddr, mac[13];
    
  strcpy(ifr.ifr_name, ifname);

  s = socket(PF_INET, SOCK_RAW, htons(0x8086));
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
  snprintf(mac, 13, "%02X%02X%02X%02X%02X%02X", 
	   hwaddr[0] & 0xFF,
	   hwaddr[1] & 0xFF,
	   hwaddr[2] & 0xFF,
	   hwaddr[3] & 0xFF,
	   hwaddr[4] & 0xFF,
	   hwaddr[5] & 0xFF
	   );
       
  close(s);
  return safe_strdup(mac);
#else
  return NULL;
#endif
}

/** Get name of external interface (the one with default route to the net).
 *  Caller must free.
 */
char *get_ext_iface (void) {
#ifdef __linux__
  FILE *input;
  char *device, *gw;
  int i;
  pthread_cond_t		cond = PTHREAD_COND_INITIALIZER;
  pthread_mutex_t		cond_mutex = PTHREAD_MUTEX_INITIALIZER;
  struct	timespec	timeout;
  device = (char *)malloc(16);
  gw = (char *)malloc(16);
  debug(LOG_DEBUG, "get_ext_iface(): Autodectecting the external interface from routing table");
  for (i=1; i<=NUM_EXT_INTERFACE_DETECT_RETRY; i++) {
    input = fopen("/proc/net/route", "r");
    while (!feof(input)) {
      fscanf(input, "%s %s %*s %*s %*s %*s %*s %*s %*s %*s %*s\n", device, gw);
      if (strcmp(gw, "00000000") == 0) {
	free(gw);
	debug(LOG_INFO, "get_ext_iface(): Detected %s as the default interface after try %d", device, i);
	return device;
      }
    }
    fclose(input);
    debug(LOG_ERR, "get_ext_iface(): Failed to detect the external interface after try %d of %d (maybe the interface is not up yet?)", i, NUM_EXT_INTERFACE_DETECT_RETRY);
    /* Sleep for EXT_INTERFACE_DETECT_RETRY_INTERVAL seconds */
    timeout.tv_sec = time(NULL) + EXT_INTERFACE_DETECT_RETRY_INTERVAL;
    timeout.tv_nsec = 0;
    /* Mutex must be locked for pthread_cond_timedwait... */
    pthread_mutex_lock(&cond_mutex);	
    /* Thread safe "sleep" */
    pthread_cond_timedwait(&cond, &cond_mutex, &timeout);
    /* No longer needs to be locked */
    pthread_mutex_unlock(&cond_mutex);
  }
  debug(LOG_ERR, "get_ext_iface(): Failed to detect the external interface after %d tries, aborting", NUM_EXT_INTERFACE_DETECT_RETRY);
  exit(1);
  free(device);
  free(gw);
#endif
  return NULL;
}

/*
 * @return A string containing human-readable status text.
 * MUST BE free()d by caller
 */
char * get_status_text() {
  char buffer[STATUS_BUF_SIZ];
  char timebuf[32];
  ssize_t len;
  s_config *config;
  t_client	*first;
  int		indx;
  unsigned long int uptime = 0, uptimesecs = 0;
  unsigned int days = 0, hours = 0, minutes = 0, seconds = 0;
  unsigned long long int download_bytes, upload_bytes;
  t_MAC *trust_mac;
  t_MAC *block_mac;
	
  config = config_get_config();

  len = 0;
  snprintf(buffer, (sizeof(buffer) - len), "==================\nNoDogSplash Status\n====\n");
  len = strlen(buffer);

  uptimesecs = uptime = time(NULL) - started_time;
  days    = uptime / (24 * 60 * 60);
  uptime -= days * (24 * 60 * 60);
  hours   = uptime / (60 * 60);
  uptime -= hours * (60 * 60);
  minutes = uptime / 60;
  uptime -= minutes * 60;
  seconds = uptime;

  snprintf((buffer + len), (sizeof(buffer) - len), "Version: " VERSION "\n");
  len = strlen(buffer);

  snprintf((buffer + len), (sizeof(buffer) - len), "Uptime: %ud %uh %um %us\n", days, hours, minutes, seconds);
  len = strlen(buffer);

  snprintf((buffer + len), (sizeof(buffer) - len), "Gateway Name: %s\n", config->gw_name);
  len = strlen(buffer);

  snprintf((buffer + len), (sizeof(buffer) - len), "Managed interface: %s\n", config->gw_interface);
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
  snprintf((buffer + len), (sizeof(buffer) - len), "Total download: %llu kbytes", download_bytes/1000);
  len = strlen(buffer);
  snprintf((buffer + len), (sizeof(buffer) - len), "; avg: %.6g kbit/s\n", ((double) download_bytes) / 125 / uptimesecs);
  len = strlen(buffer);

  upload_bytes = iptables_fw_total_upload();
  snprintf((buffer + len), (sizeof(buffer) - len), "Total upload: %llu kbytes", upload_bytes/1000);
  len = strlen(buffer);
  snprintf((buffer + len), (sizeof(buffer) - len), "; avg: %.6g kbit/s\n", ((double) upload_bytes) / 125 / uptimesecs);
  len = strlen(buffer);


  /** not needed in nodogsplash, since we don't permit ndsctl restart
  snprintf((buffer + len), (sizeof(buffer) - len), "Has been restarted: ");
  len = strlen(buffer);
  if (restart_orig_pid) {
    snprintf((buffer + len), (sizeof(buffer) - len), "yes (from PID %d)\n", restart_orig_pid);
    len = strlen(buffer);
  }
  else {
    snprintf((buffer + len), (sizeof(buffer) - len), "no\n");
    len = strlen(buffer);
  }
  */

  snprintf((buffer + len), (sizeof(buffer) - len), "====\n");
  len = strlen(buffer);

  snprintf((buffer + len), (sizeof(buffer) - len), "Clients authenticated this session: %lu\n", authenticated_this_session);
  len = strlen(buffer);

  
  

  /* Update the client's counters so info is current */
  iptables_fw_counters_update();
  

  LOCK_CLIENT_LIST();
	
  snprintf((buffer + len), (sizeof(buffer) - len), "Current clients: %d\n", get_client_list_length());
  len = strlen(buffer);

  first = client_get_first_client();
  if(first) {
    snprintf((buffer + len), (sizeof(buffer) - len), "\n");
    len = strlen(buffer);
  }
  indx = 0;
  while (first != NULL) {
    snprintf((buffer + len), (sizeof(buffer) - len), "Client %d\n", indx);
    len = strlen(buffer);

    snprintf((buffer + len), (sizeof(buffer) - len), "  IP: %s MAC: %s\n", first->ip, first->mac);
    len = strlen(buffer);

    ctime_r(&(first->added_time),timebuf);
    snprintf((buffer + len), (sizeof(buffer) - len), "  Added:   %s", timebuf);
    len = strlen(buffer);

    ctime_r(&(first->counters.last_updated),timebuf);
    snprintf((buffer + len), (sizeof(buffer) - len), "  Active:  %s", timebuf);
    len = strlen(buffer);

    uptimesecs = uptime = first->counters.last_updated - first->added_time;
    days    = uptime / (24 * 60 * 60);
    uptime -= days * (24 * 60 * 60);
    hours   = uptime / (60 * 60);
    uptime -= hours * (60 * 60);
    minutes = uptime / 60;
    uptime -= minutes * 60;
    seconds = uptime;

    snprintf((buffer + len), (sizeof(buffer) - len), "  Active time: %ud %uh %um %us\n", days, hours, minutes, seconds);
    len = strlen(buffer);

    snprintf((buffer + len), (sizeof(buffer) - len), "  Token: %s\n", first->token ? first->token : "none");
    len = strlen(buffer);

    snprintf((buffer + len), (sizeof(buffer) - len), "  State: %s\n",
	     fw_connection_state_as_string(first->fw_connection_state));
    len = strlen(buffer);

    download_bytes = first->counters.incoming;
    upload_bytes = first->counters.outgoing;

    snprintf((buffer + len), (sizeof(buffer) - len),
	     "  Download: %llu kbytes; avg: %.6g kbit/s\n  Upload:   %llu kbytes; avg: %.6g kbit/s\n\n",
	     download_bytes/1000, ((double)download_bytes)/125/uptimesecs,
	     upload_bytes/1000, ((double)upload_bytes)/125/uptimesecs);
    len = strlen(buffer);

    indx++;
    first = first->next;
  }

  UNLOCK_CLIENT_LIST();

  snprintf((buffer + len), (sizeof(buffer) - len), "====\n");
  len = strlen(buffer);
  
  snprintf((buffer + len), (sizeof(buffer) - len), "Blocked MAC addresses:\n");
  len = strlen(buffer);

  if (config->blockedmaclist != NULL) {
    for (block_mac = config->blockedmaclist; block_mac != NULL; block_mac = block_mac->next) {
      snprintf((buffer + len), (sizeof(buffer) - len), "  %s\n", block_mac->mac);
      len = strlen(buffer);
    }
  } else {
      snprintf((buffer + len), (sizeof(buffer) - len), "  none\n");
      len = strlen(buffer);
  }

  snprintf((buffer + len), (sizeof(buffer) - len), "Trusted MAC addresses:\n");
  len = strlen(buffer);

  if (config->trustedmaclist != NULL) {
    for (trust_mac = config->trustedmaclist; trust_mac != NULL; trust_mac = trust_mac->next) {
      snprintf((buffer + len), (sizeof(buffer) - len), "  %s\n", trust_mac->mac);
      len = strlen(buffer);
    }
  } else {
      snprintf((buffer + len), (sizeof(buffer) - len), "  none\n");
      len = strlen(buffer);
  }
  
  snprintf((buffer + len), (sizeof(buffer) - len), "========\n");
  len = strlen(buffer);
  
  return safe_strdup(buffer);
}
