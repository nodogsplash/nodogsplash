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

/* $Id: httpd_thread.c 901 2006-01-17 18:58:13Z mina $ */

/** @file httpd_thread.c
    @brief Handles one web request.
    @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@acv.ca>
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>

#include "httpd.h"

#include "common.h"
#include "debug.h"
#include "httpd_thread.h"


/* Defined in gateway.c */
extern pthread_mutex_t httpd_mutex;
extern int created_httpd_threads;
extern int current_httpd_threads;

/** Entry point for httpd request handling thread.
@param args Two item array of void-cast pointers to the httpd and request struct
*/
void
thread_httpd(void *args)
{
	void **params;
	httpd *webserver;
	request *r;
	int serialnum;

	pthread_mutex_lock(&httpd_mutex);
	current_httpd_threads++;
	pthread_mutex_unlock(&httpd_mutex);

	params = (void **)args;
	webserver = *params;
	r = *(params + 1);
	serialnum = *((int *)*(params + 2));
	free(*(params + 2)); /* XXX We must release this here. */
	free(params); /* XXX We must release this here. */

	if (httpdReadRequest(webserver, r) == 0) {
		/*
		 * We read the request fine
		 */
		debug(LOG_DEBUG, "Thread %d calling httpdProcessRequest() for %s", serialnum, r->clientAddr);
		httpdProcessRequest(webserver, r);
		debug(LOG_DEBUG, "Thread %d returned from httpdProcessRequest() for %s", serialnum, r->clientAddr);
	} else {
		debug(LOG_DEBUG, "Thread %d: No valid request received from %s", serialnum, r->clientAddr);
	}
	debug(LOG_DEBUG, "Thread %d ended request from %s", serialnum, r->clientAddr);
	httpdEndRequest(r);

	pthread_mutex_lock(&httpd_mutex);
	current_httpd_threads--;
	pthread_mutex_unlock(&httpd_mutex);
}
