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

/* $Id: ndsctl.c 901 2006-01-17 18:58:13Z mina $ */
/** @file ndsctl.c
    @brief Monitoring and control of nodogsplash, client part
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
#include <errno.h>

#include "ndsctl.h"

/* N.B. this is ndsctl.h s_config, not conf.h s_config */
s_config config;

static void usage(void);
static void init_config(void);
static void parse_commandline(int, char **);
static int connect_to_server(char *);
static int send_request(int, char *);
static void ndsctl_status(void);
static void ndsctl_stop(void);
static void ndsctl_restart(void);
static void ndsctl_block(void);
static void ndsctl_unblock(void);
static void ndsctl_trust(void);
static void ndsctl_untrust(void);
static void ndsctl_auth(void);
static void ndsctl_deauth(void);

/** @internal
 * @brief Print usage
 *
 * Prints usage, called when ndsctl is run with -h or with an unknown option
 */
static void
usage(void) {
  printf("Usage: ndsctl [options] command [arguments]\n");
  printf("\n");
  printf("options:\n");
  printf("  -s <path>         Path to the socket\n");
  printf("  -h                Print usage\n");
  printf("\n");
  printf("commands:\n");
  printf("  status            Obtain the status of nodogsplash\n");
  printf("  stop              Stop the running nodogsplash\n");
  printf("  auth ip           Authenticate user with specified ip\n");
  printf("  deauth mac|ip     Deauthenticate user with specified mac or ip\n");
  printf("  block mac         Block the given MAC address\n");
  printf("  unblock mac       Unblock the given MAC address\n");
  printf("  trust mac         Trust the given MAC address\n");
  printf("  untrust mac       Untrust the given MAC address\n");
  printf("\n");
}

/** @internal
 *
 * Init default values in config struct
 */
static void
init_config(void) {
  config.socket = strdup(DEFAULT_SOCK);
  config.command = NDSCTL_UNDEF;
}

/** @internal
 *
 * Uses getopt() to parse the command line and set configuration values
 */
void
parse_commandline(int argc, char **argv) {
  extern int optind;
  int c;

  while (-1 != (c = getopt(argc, argv, "s:h"))) {
    switch(c) {
    case 'h':
      usage();
      exit(1);
      break;

    case 's':
      if (optarg) {
	free(config.socket);
	config.socket = strdup(optarg);
      }
      break;

    default:
      usage();
      exit(1);
      break;
    }
  }

  if ((argc - optind) <= 0) {
    usage();
    exit(1);
  }

  if (strcmp(*(argv + optind), "status") == 0) {
    config.command = NDSCTL_STATUS;
  }

  else if (strcmp(*(argv + optind), "stop") == 0) {
    config.command = NDSCTL_STOP;
  } 
  else if (strcmp(*(argv + optind), "block") == 0) {
    config.command = NDSCTL_BLOCK;
    if ((argc - (optind + 1)) <= 0) {
      fprintf(stderr, "ndsctl: Error: You must specify a "
	      "MAC address to block\n");
      usage();
      exit(1);
    }
    config.param = strdup(*(argv + optind + 1));
  }
  else if (strcmp(*(argv + optind), "unblock") == 0) {
    config.command = NDSCTL_UNBLOCK;
    if ((argc - (optind + 1)) <= 0) {
      fprintf(stderr, "ndsctl: Error: You must specify a "
	      "MAC address to unblock\n");
      usage();
      exit(1);
    }
    config.param = strdup(*(argv + optind + 1));
  }
  else if (strcmp(*(argv + optind), "trust") == 0) {
    config.command = NDSCTL_TRUST;
    if ((argc - (optind + 1)) <= 0) {
      fprintf(stderr, "ndsctl: Error: You must specify a "
	      "MAC address to trust\n");
      usage();
      exit(1);
    }
    config.param = strdup(*(argv + optind + 1));
  }
  else if (strcmp(*(argv + optind), "untrust") == 0) {
    config.command = NDSCTL_UNTRUST;
    if ((argc - (optind + 1)) <= 0) {
      fprintf(stderr, "ndsctl: Error: You must specify a "
	      "MAC address to untrust\n");
      usage();
      exit(1);
    }
    config.param = strdup(*(argv + optind + 1));
  }
  else if (strcmp(*(argv + optind), "auth") == 0) {
    config.command = NDSCTL_AUTH;
    if ((argc - (optind + 1)) <= 0) {
      fprintf(stderr, "ndsctl: Error: You must specify an IP "
	      "address to auth\n");
      usage();
      exit(1);
    }
    config.param = strdup(*(argv + optind + 1));
  }
  else if (strcmp(*(argv + optind), "deauth") == 0) {
    config.command = NDSCTL_DEAUTH;
    if ((argc - (optind + 1)) <= 0) {
      fprintf(stderr, "ndsctl: Error: You must specify an IP "
	      "or a Mac address to deauth\n");
      usage();
      exit(1);
    }
    config.param = strdup(*(argv + optind + 1));
  }
  else {
    fprintf(stderr, "ndsctl: Error: Invalid command \"%s\"\n", *(argv + optind));
    usage();
    exit(1);
  }
}

static int
connect_to_server(char *sock_name) {
  int sock;
  struct sockaddr_un	sa_un;
	
  /* Connect to socket */
  sock = socket(AF_UNIX, SOCK_STREAM, 0);
  memset(&sa_un, 0, sizeof(sa_un));
  sa_un.sun_family = AF_UNIX;
  strncpy(sa_un.sun_path, sock_name, (sizeof(sa_un.sun_path) - 1));

  if (connect(sock, (struct sockaddr *)&sa_un, 
	      strlen(sa_un.sun_path) + sizeof(sa_un.sun_family))) {
    fprintf(stderr, "ndsctl: nodogsplash probably not started (Error: %s)\n", strerror(errno));
    exit(1);
  }

  return sock;
}

static int
send_request(int sock, char *request) {
  ssize_t	len,
    written;
		
  len = 0;
  while (len != strlen(request)) {
    written = write(sock, (request + len), strlen(request) - len);
    if (written == -1) {
      fprintf(stderr, "Write to nodogsplash failed: %s\n",
	      strerror(errno));
      exit(1);
    }
    len += written;
  }

  return((int)len);
}

static void
ndsctl_status(void) {
  int	sock;
  char	buffer[4096];
  char	request[16];
  int	len;

  sock = connect_to_server(config.socket);
		
  strncpy(request, "status\r\n\r\n", 15);

  len = send_request(sock, request);
	
  while ((len = read(sock, buffer, sizeof(buffer))) > 0) {
    buffer[len] = '\0';
    printf("%s", buffer);
  }

  shutdown(sock, 2);
  close(sock);
}

static void
ndsctl_stop(void) {
  int	sock;
  char	buffer[4096];
  char	request[16];
  int	len;

  sock = connect_to_server(config.socket);
		
  strncpy(request, "stop\r\n\r\n", 15);

  len = send_request(sock, request);
	
  while ((len = read(sock, buffer, sizeof(buffer))) > 0) {
    buffer[len] = '\0';
    printf("%s", buffer);
  }

  shutdown(sock, 2);
  close(sock);
}

void
ndsctl_deauth(void) {
  int	sock;
  char	buffer[4096];
  char	request[64];
  int	len,
    rlen;

  sock = connect_to_server(config.socket);
		
  strncpy(request, "deauth ", 64);
  strncat(request, config.param, (64 - strlen(request)));
  strncat(request, "\r\n\r\n", (64 - strlen(request)));

  len = send_request(sock, request);
	
  len = 0;
  memset(buffer, 0, sizeof(buffer));
  while ((len < sizeof(buffer)) && ((rlen = read(sock, (buffer + len),
						 (sizeof(buffer) - len))) > 0)){
    len += rlen;
  }

  if (strcmp(buffer, "Yes") == 0) {
    printf("Client %s deauthenticated.\n", config.param);
  } else if (strcmp(buffer, "No") == 0) {
    printf("Client %s not found.\n", config.param);
  } else {
    fprintf(stderr, "ndsctl: Error: nodogsplash sent an abnormal "
	    "reply.\n");
  }

  shutdown(sock, 2);
  close(sock);
}

void
ndsctl_auth(void) {
  int	sock;
  char	buffer[4096];
  char	request[64];
  int	len,
    rlen;

  sock = connect_to_server(config.socket);
		
  strncpy(request, "auth ", 64);
  strncat(request, config.param, (64 - strlen(request)));
  strncat(request, "\r\n\r\n", (64 - strlen(request)));

  len = send_request(sock, request);
	
  len = 0;
  memset(buffer, 0, sizeof(buffer));
  while ((len < sizeof(buffer)) && ((rlen = read(sock, (buffer + len),
						 (sizeof(buffer) - len))) > 0)){
    len += rlen;
  }

  if (strcmp(buffer, "Yes") == 0) {
    printf("Client %s authenticated.\n", config.param);
  } else if (strcmp(buffer, "No") == 0) {
    printf("Failed to authenticate client %s.\n", config.param);
  } else {
    fprintf(stderr, "ndsctl: Error: nodogsplash sent an abnormal "
	    "reply:\n  \"%s\"",buffer);
  }

  shutdown(sock, 2);
  close(sock);
}

void
ndsctl_block(void) {
  int	sock;
  char	buffer[4096];
  char	request[64];
  int	len,
    rlen;

  sock = connect_to_server(config.socket);
		
  strncpy(request, "block ", 64);
  strncat(request, config.param, (64 - strlen(request)));
  strncat(request, "\r\n\r\n", (64 - strlen(request)));

  len = send_request(sock, request);
	
  len = 0;
  memset(buffer, 0, sizeof(buffer));
  while ((len < sizeof(buffer)) && ((rlen = read(sock, (buffer + len),
						 (sizeof(buffer) - len))) > 0)){
    len += rlen;
  }

  if (strcmp(buffer, "Yes") == 0) {
    printf("MAC %s blocked.\n", config.param);
  } else if (strcmp(buffer, "No") == 0) {
    printf("Failed to block MAC %s.\n", config.param);
  } else {
    fprintf(stderr, "ndsctl: Error: nodogsplash sent an abnormal "
	    "reply.\n");
  }

  shutdown(sock, 2);
  close(sock);
}

void
ndsctl_unblock(void) {
  int	sock;
  char	buffer[4096];
  char	request[64];
  int	len,
    rlen;

  sock = connect_to_server(config.socket);
		
  strncpy(request, "unblock ", 64);
  strncat(request, config.param, (64 - strlen(request)));
  strncat(request, "\r\n\r\n", (64 - strlen(request)));

  len = send_request(sock, request);
	
  len = 0;
  memset(buffer, 0, sizeof(buffer));
  while ((len < sizeof(buffer)) && ((rlen = read(sock, (buffer + len),
						 (sizeof(buffer) - len))) > 0)){
    len += rlen;
  }

  if (strcmp(buffer, "Yes") == 0) {
    printf("MAC %s unblocked.\n", config.param);
  } else if (strcmp(buffer, "No") == 0) {
    printf("Failed to unblock MAC %s.\n", config.param);
  } else {
    fprintf(stderr, "ndsctl: Error: nodogsplash sent an abnormal "
	    "reply.\n");
  }

  shutdown(sock, 2);
  close(sock);
}


void
ndsctl_trust(void) {
  int	sock;
  char	buffer[4096];
  char	request[64];
  int	len,
    rlen;

  sock = connect_to_server(config.socket);
		
  strncpy(request, "trust ", 64);
  strncat(request, config.param, (64 - strlen(request)));
  strncat(request, "\r\n\r\n", (64 - strlen(request)));

  len = send_request(sock, request);
	
  len = 0;
  memset(buffer, 0, sizeof(buffer));
  while ((len < sizeof(buffer)) && ((rlen = read(sock, (buffer + len),
						 (sizeof(buffer) - len))) > 0)){
    len += rlen;
  }

  if (strcmp(buffer, "Yes") == 0) {
    printf("MAC %s trusted.\n", config.param);
  } else if (strcmp(buffer, "No") == 0) {
    printf("Failed to trust MAC %s.\n", config.param);
  } else {
    fprintf(stderr, "ndsctl: Error: nodogsplash sent an abnormal "
	    "reply.\n");
  }

  shutdown(sock, 2);
  close(sock);
}

void
ndsctl_untrust(void) {
  int	sock;
  char	buffer[4096];
  char	request[64];
  int	len,
    rlen;

  sock = connect_to_server(config.socket);
		
  strncpy(request, "untrust ", 64);
  strncat(request, config.param, (64 - strlen(request)));
  strncat(request, "\r\n\r\n", (64 - strlen(request)));

  len = send_request(sock, request);
	
  len = 0;
  memset(buffer, 0, sizeof(buffer));
  while ((len < sizeof(buffer)) && ((rlen = read(sock, (buffer + len),
						 (sizeof(buffer) - len))) > 0)){
    len += rlen;
  }

  if (strcmp(buffer, "Yes") == 0) {
    printf("MAC %s untrusted.\n", config.param);
  } else if (strcmp(buffer, "No") == 0) {
    printf("Failed to untrust MAC %s.\n", config.param);
  } else {
    fprintf(stderr, "ndsctl: Error: nodogsplash sent an abnormal "
	    "reply.\n");
  }

  shutdown(sock, 2);
  close(sock);
}


static void
ndsctl_restart(void) {
  int	sock;
  char	buffer[4096];
  char	request[16];
  int	len;

  sock = connect_to_server(config.socket);
		
  strncpy(request, "restart\r\n\r\n", 15);

  len = send_request(sock, request);
	
  while ((len = read(sock, buffer, sizeof(buffer))) > 0) {
    buffer[len] = '\0';
    printf("%s", buffer);
  }

  shutdown(sock, 2);
  close(sock);
}

int
main(int argc, char **argv) {

  /* Init configuration */
  init_config();
  parse_commandline(argc, argv);

  switch(config.command) {
  case NDSCTL_STATUS:
    ndsctl_status();
    break;
	
  case NDSCTL_STOP:
    ndsctl_stop();
    break;

  case NDSCTL_RESTART:
    ndsctl_restart();
    break;

  case NDSCTL_BLOCK:
    ndsctl_block();
    break;

  case NDSCTL_UNBLOCK:
    ndsctl_unblock();
    break;

  case NDSCTL_TRUST:
    ndsctl_trust();
    break;

  case NDSCTL_UNTRUST:
    ndsctl_untrust();
    break;

  case NDSCTL_AUTH:
    ndsctl_auth();
    break;

  case NDSCTL_DEAUTH:
    ndsctl_deauth();
    break;
		
  default:
    /* XXX NEVER REACHED */
    fprintf(stderr, "Unknown opcode: %d\n", config.command);
    exit(1);
    break;
  }
  exit(0);
}
