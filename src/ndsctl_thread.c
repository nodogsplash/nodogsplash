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

/* $Id: ndsctl_thread.c 969 2006-02-23 17:09:32Z papril $ */
/** @file ndsctl_thread.c
    @brief Monitoring and control of nodogsplash, server part
    @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@acv.ca>
    trivially modified for nodogsplash
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>

#include "common.h"
#include "httpd.h"
#include "util.h"
#include "conf.h"
#include "debug.h"
#include "auth.h"
#include "fw_iptables.h"
#include "firewall.h"
#include "client_list.h"
#include "ndsctl_thread.h"

/* Defined in clientlist.c */
extern	pthread_mutex_t	client_list_mutex;
extern	pthread_mutex_t	config_mutex;

/* From commandline.c: */
extern char ** restartargv;
static void *thread_ndsctl_handler(void *);
static void ndsctl_status(int);
static void ndsctl_stop(int);
static void ndsctl_reset(int, char *);
static void ndsctl_restart(int);

/** Launches a thread that monitors the control socket for request
@param arg Must contain a pointer to a string containing the Unix domain socket to open
@todo This thread loops infinitely, need a watchdog to verify that it is still running?
*/  
void
thread_ndsctl(void *arg) {
  int	sock,
    fd;
  char	*sock_name;
  struct 	sockaddr_un	sa_un;
  int result;
  pthread_t	tid;
  socklen_t len;

  debug(LOG_DEBUG, "Starting ndsctl.");

  memset(&sa_un, 0, sizeof(sa_un));
  sock_name = (char *)arg;
  debug(LOG_DEBUG, "Socket name: %s", sock_name);

  if (strlen(sock_name) > (sizeof(sa_un.sun_path) - 1)) {
    /* TODO: Die handler with logging.... */
    debug(LOG_ERR, "NDSCTL socket name too long");
    exit(1);
  }
	

  debug(LOG_DEBUG, "Creating socket");
  sock = socket(PF_UNIX, SOCK_STREAM, 0);

  debug(LOG_DEBUG, "Got server socket %d", sock);

  /* If it exists, delete... Not the cleanest way to deal. */
  unlink(sock_name);

  debug(LOG_DEBUG, "Filling sockaddr_un");
  strcpy(sa_un.sun_path, sock_name); /* XXX No size check because we
				      * check a few lines before. */
  sa_un.sun_family = AF_UNIX;
	
  debug(LOG_DEBUG, "Binding socket (%s) (%d)", sa_un.sun_path,
	strlen(sock_name));
	
  /* Which to use, AF_UNIX, PF_UNIX, AF_LOCAL, PF_LOCAL? */
  if (bind(sock, (struct sockaddr *)&sa_un, strlen(sock_name) 
	   + sizeof(sa_un.sun_family))) {
    debug(LOG_ERR, "Could not bind control socket: %s",
	  strerror(errno));
    pthread_exit(NULL);
  }

  if (listen(sock, 5)) {
    debug(LOG_ERR, "Could not listen on control socket: %s",
	  strerror(errno));
    pthread_exit(NULL);
  }

  while (1) {
    memset(&sa_un, 0, sizeof(sa_un));
    if ((fd = accept(sock, (struct sockaddr *)&sa_un, &len)) == -1){
      debug(LOG_ERR, "Accept failed on control socket: %s",
	    strerror(errno));
    } else {
      debug(LOG_DEBUG, "Accepted connection on ndsctl socket %d (%s)", fd, sa_un.sun_path);
      result = pthread_create(&tid, NULL, &thread_ndsctl_handler, (void *)fd);
      if (result != 0) {
	debug(LOG_ERR, "FATAL: Failed to create a new thread (ndsctl handler) - exiting");
	termination_handler(0);
      }
      pthread_detach(tid);
    }
  }
}


static void *
thread_ndsctl_handler(void *arg) {
  int	fd,
    done,
    i;
  char	request[MAX_BUF];
  ssize_t	read_bytes,
    len;

  debug(LOG_DEBUG, "Entering thread_ndsctl_handler....");

  fd = (int)arg;
	
  debug(LOG_DEBUG, "Read bytes and stuff from %d", fd);

  /* Init variables */
  read_bytes = 0;
  done = 0;
  memset(request, 0, sizeof(request));
	
  /* Read.... */
  while (!done && read_bytes < (sizeof(request) - 1)) {
    len = read(fd, request + read_bytes,
	       sizeof(request) - read_bytes);

    /* Have we gotten a command yet? */
    for (i = read_bytes; i < (read_bytes + len); i++) {
      if (request[i] == '\r' || request[i] == '\n') {
	request[i] = '\0';
	done = 1;
      }
    }
		
    /* Increment position */
    read_bytes += len;
  }

  debug(LOG_DEBUG, "ndsctl request received: [%s]", request);

  if (strncmp(request, "status", 6) == 0) {
    ndsctl_status(fd);
  } else if (strncmp(request, "stop", 4) == 0) {
    ndsctl_stop(fd);
  } else if (strncmp(request, "reset", 5) == 0) {
    ndsctl_reset(fd, (request + 6));
  } else if (strncmp(request, "restart", 7) == 0) {
    ndsctl_restart(fd);
  }

  if (!done) {
    debug(LOG_ERR, "Invalid ndsctl request.");
    shutdown(fd, 2);
    close(fd);
    pthread_exit(NULL);
  }

  debug(LOG_DEBUG, "ndsctl request processed: [%s]", request);
	
  shutdown(fd, 2);
  close(fd);
  debug(LOG_DEBUG, "Exiting thread_ndsctl_handler....");

  return NULL;
}

static void
ndsctl_status(int fd) {
  char * status = NULL;
  int len = 0;

  status = get_status_text();
  len = strlen(status);

  write(fd, status, len);

  free(status);
}

/** A bit of an hack, self kills.... */
static void
ndsctl_stop(int fd) {
  pid_t	pid;

  pid = getpid();
  kill(pid, SIGINT);
}

static void
ndsctl_restart(int afd) {
  int	sock,
    fd;
  char	*sock_name;
  struct 	sockaddr_un	sa_un;
  int result;
  s_config * conf = NULL;
  t_client * client = NULL;
  char * tempstring = NULL;
  pid_t pid;
  ssize_t written;
  socklen_t len;

  conf = config_get_config();

  debug(LOG_NOTICE, "Will restart myself");

  /*
   * First, prepare the internal socket
   */
  memset(&sa_un, 0, sizeof(sa_un));
  sock_name = conf->internal_sock;
  debug(LOG_DEBUG, "Socket name: %s", sock_name);

  if (strlen(sock_name) > (sizeof(sa_un.sun_path) - 1)) {
    /* TODO: Die handler with logging.... */
    debug(LOG_ERR, "INTERNAL socket name too long");
    return;
  }

  debug(LOG_DEBUG, "Creating socket");
  sock = socket(PF_UNIX, SOCK_STREAM, 0);

  debug(LOG_DEBUG, "Got internal socket %d", sock);

  /* If it exists, delete... Not the cleanest way to deal. */
  unlink(sock_name);

  debug(LOG_DEBUG, "Filling sockaddr_un");
  strcpy(sa_un.sun_path, sock_name); /* XXX No size check because we check a few lines before. */
  sa_un.sun_family = AF_UNIX;
	
  debug(LOG_DEBUG, "Binding socket (%s) (%d)", sa_un.sun_path, strlen(sock_name));
	
  /* Which to use, AF_UNIX, PF_UNIX, AF_LOCAL, PF_LOCAL? */
  if (bind(sock, (struct sockaddr *)&sa_un, strlen(sock_name) + sizeof(sa_un.sun_family))) {
    debug(LOG_ERR, "Could not bind internal socket: %s", strerror(errno));
    return;
  }

  if (listen(sock, 5)) {
    debug(LOG_ERR, "Could not listen on internal socket: %s", strerror(errno));
    return;
  }
	
  /*
   * The internal socket is ready, fork and exec ourselves
   */
  debug(LOG_DEBUG, "Forking in preparation for exec()...");
  pid = safe_fork();
  if (pid > 0) {
    /* Parent */

    /* Wait for the child to connect to our socket :*/
    debug(LOG_DEBUG, "Waiting for child to connect on internal socket");
    if ((fd = accept(sock, (struct sockaddr *)&sa_un, &len)) == -1){
      debug(LOG_ERR, "Accept failed on internal socket: %s", strerror(errno));
      close(sock);
      return;
    }

    close(sock);

    debug(LOG_DEBUG, "Received connection from child.  Sending them all existing clients");

    /* The child is connected. Send them over the socket the existing clients */
    LOCK_CLIENT_LIST();
    client = client_get_first_client();
    while (client) {
      /* Send this client */
      safe_asprintf(&tempstring,
		    "CLIENT|ip=%s|mac=%s|token=%s|fw_connection_state=%u|added_time=%llu|counters_incoming=%llu|counters_outgoing=%llu|counters_last_updated=%llu\n",
		    client->ip,
		    client->mac,
		    client->token ? client->token : "NULL",
		    client->fw_connection_state,
		    (unsigned long long) (client->added_time),
		    client->counters.incoming,
		    client->counters.outgoing,
		    (unsigned long long) client->counters.last_updated);
      debug(LOG_DEBUG, "Sending to child client data: %s", tempstring);
      len = 0;
      while (len != strlen(tempstring)) {
	written = write(fd, (tempstring + len), strlen(tempstring) - len);
	if (written == -1) {
	  debug(LOG_ERR, "Failed to write client data to child: %s", strerror(errno));
	  free(tempstring);
	  break;
	}
	else {
	  len += written;
	}
      }
      free(tempstring);
      client = client->next;
    }
    UNLOCK_CLIENT_LIST();

    close(fd);

    debug(LOG_INFO, "Sent all existing clients to child.  Committing suicide!");

    shutdown(afd, 2);
    close(afd);

    /* Our job in life is done. Commit suicide! */
    ndsctl_stop(afd);
  }
  else {
    /* Child */
    close(sock);
    shutdown(afd, 2);
    close(afd);
    debug(LOG_NOTICE, "Re-executing myself (%s)", restartargv[0]);
    setsid();
    execvp(restartargv[0], restartargv);
    /* If we've reached here the exec() failed - die quickly and silently */
    debug(LOG_ERR, "I failed to re-execute myself: %s", strerror(errno));
    debug(LOG_ERR, "Exiting without cleanup");
    exit(1);
  }

}

static void
ndsctl_reset(int fd, char *arg) {
  t_client	*node;

  debug(LOG_DEBUG, "Entering ndsctl_reset...");
	
  LOCK_CLIENT_LIST();
  debug(LOG_DEBUG, "Argument: %s (@%x)", arg, arg);
	
  /* We get the node or return... */
  if ((node = client_list_find_by_ip(arg)) != NULL);
  else if ((node = client_list_find_by_mac(arg)) != NULL);
  else {
    debug(LOG_DEBUG, "Client not found.");
    UNLOCK_CLIENT_LIST();
    write(fd, "No", 2);
    return;
  }

  debug(LOG_DEBUG, "Got node %x.", node);
	
  /* deny.... */
  /* TODO: maybe just deleting the connection is not best... But this
   * is a manual command, I don't anticipate it'll be that useful. */
  iptables_fw_access(AUTH_MAKE_DEAUTHENTICATED, node->ip, node->mac);
  client_list_delete(node);
	
  UNLOCK_CLIENT_LIST();
	
  write(fd, "Yes", 3);
	
  debug(LOG_DEBUG, "Exiting ndsctl_reset...");
}
