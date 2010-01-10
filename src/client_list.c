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
 * $Id: client_list.c 901 2006-01-17 18:58:13Z mina $
 */
/** @file client_list.c
  @brief Client List Functions
  @author Copyright (C) 2004 Alexandre Carmel-Veillex <acv@acv.ca>
  @author Copyright (C) 2007 Paul Kube <nodogsplash@kokoro.ucsd.edu>
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

#include <string.h>

#include "safe.h"
#include "debug.h"
#include "conf.h"
#include "client_list.h"
#include "firewall.h"

/** Client counter */
static int client_count = 0;

/** Global mutex to protect access to the client list */
pthread_mutex_t client_list_mutex = PTHREAD_MUTEX_INITIALIZER;

/** @internal
 * Holds a pointer to the first element of the list 
 */ 
t_client         *firstclient = NULL;

/** Return current length of the client list
 */
int
get_client_list_length() {
  return client_count;
}

/** Get the first element of the client list
 */
t_client *
client_get_first_client(void)
{
    return firstclient;
}

/**
 * Initializes the list of connected clients (client)
 */
void
client_list_init(void) {
  firstclient = NULL;
  client_count = 0;
}

/** Based on the parameters it receives, this function creates a new entry
 * in the client list. All the memory allocation is done here.
 * @param ip IP address
 * @param mac MAC address
 * @param token Token
 * @return Pointer to the client we just created
 */
t_client         *
client_list_append(char *ip, char *mac, char *token) {
  t_client         *client, *prevclient;
  s_config *config;
  int maxclients;

  config = config_get_config();
  maxclients = config->maxclients;
  if(client_count >= maxclients) {
    debug(LOG_NOTICE, "Already list %d clients, cannot add %s %s", client_count, ip, mac);
    return NULL;
  }

  prevclient = NULL;
  client = firstclient;

  while (client != NULL) {
    prevclient = client;
    client = client->next;
  }

  client = safe_malloc(sizeof(t_client));
  memset(client, 0, sizeof(t_client));

  client->ip = safe_strdup(ip);
  client->mac = safe_strdup(mac);
  client->token = token ? safe_strdup(token) : NULL;
  client->fw_connection_state = FW_MARK_PREAUTHENTICATED;
  client->counters.incoming = client->counters.incoming_history = 0;
  client->counters.outgoing = client->counters.outgoing_history = 0;
  client->counters.last_updated = time(NULL);
  client->added_time = time(NULL);

  debug(LOG_NOTICE, "Adding %s %s token %s to client list",
	    client->ip, client->mac, client->token ? client->token : "none");

  if (prevclient == NULL) {
    firstclient = client;
  } else {
    prevclient->next = client;
  }

  client_count++;

  return client;
}

/** Finds a  client by its IP and MAC, returns NULL if the client could not
 * be found
 * @param ip IP we are looking for in the linked list
 * @param mac MAC we are looking for in the linked list
 * @return Pointer to the client, or NULL if not found
 */
t_client         *
client_list_find(char *ip, char *mac) {
  t_client         *ptr;

  ptr = firstclient;
  while (NULL != ptr) {
    if (0 == strcmp(ptr->ip, ip) && 0 == strcmp(ptr->mac, mac))
      return ptr;
    ptr = ptr->next;
  }

  return NULL;
}


/**
 * Finds a  client by its IP, returns NULL if the client could not
 * be found
 * @param ip IP we are looking for in the linked list
 * @return Pointer to the client, or NULL if not found
 */
t_client         *
client_list_find_by_ip(char *ip) {
  t_client         *ptr;

  ptr = firstclient;
  while (NULL != ptr) {
    if (0 == strcmp(ptr->ip, ip))
      return ptr;
    ptr = ptr->next;
  }

  return NULL;
}

/**
 * Finds a  client by its Mac, returns NULL if the client could not
 * be found
 * @param mac Mac we are looking for in the linked list
 * @return Pointer to the client, or NULL if not found
 */
t_client         *
client_list_find_by_mac(char *mac) {
  t_client         *ptr;

  ptr = firstclient;
  while (NULL != ptr) {
    if (0 == strcmp(ptr->mac, mac))
      return ptr;
    ptr = ptr->next;
  }

  return NULL;
}

/** Finds a client by its token
 * @param token Token we are looking for in the linked list
 * @return Pointer to the client, or NULL if not found
 */
t_client *
client_list_find_by_token(char *token) {
  t_client         *ptr;

  ptr = firstclient;
  while (NULL != ptr) {
    if (0 == strcmp(ptr->token, token))
      return ptr;
    ptr = ptr->next;
  }

  return NULL;
}

/** @internal
 * @brief Frees the memory used by a t_client structure
 * This function frees the memory used by the t_client structure in the
 * proper order.
 * @param client Points to the client to be freed
 */
void
_client_list_free_node(t_client * client) {

  if (client->mac != NULL)
    free(client->mac);

  if (client->ip != NULL)
    free(client->ip);

  if (client->token != NULL)
    free(client->token);

  free(client);
}

/**
 * @brief Deletes a client from the client list
 *
 * Removes the specified client from the client list and then calls
 * the function _client_list_free_node to free the memory taken by the client.
 * @param client Points to the client to be deleted
 */
void
client_list_delete(t_client * client) {
  t_client         *ptr;

  ptr = firstclient;

  if (ptr == NULL) {
    debug(LOG_ERR, "Node list empty!");
  } else if (ptr == client) {
    firstclient = ptr->next;
    _client_list_free_node(client);
    client_count--;
  } else {
    /* Loop forward until we reach our point in the list. */
    while (ptr->next != NULL && ptr->next != client) {
      ptr = ptr->next;
    }
    /* If we reach the end before finding out element, complain. */
    if (ptr->next == NULL) {
      debug(LOG_ERR, "Node to delete could not be found.");
    } else {
      /* Free element. */
      debug(LOG_NOTICE, "Deleting %s %s token %s from client list",
	    client->ip, client->mac, client->token ? client->token : "none");
      ptr->next = client->next;
      _client_list_free_node(client);
      client_count--;


    }
  }
}
