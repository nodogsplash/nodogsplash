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

/* $Id: http.h 1104 2006-10-09 00:58:46Z acv $ */
/** @file http.h
    @brief HTTP IO functions
    @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
*/

#ifndef _HTTP_H_
#define _HTTP_H_

#include "httpd.h"
#include "client_list.h"

/**@brief Callback for libhttpd, serves nodogsplash splash page */
void http_nodogsplash_callback_404(httpd *webserver, request *r);
/**@brief Callback for libhttpd, serves nodogsplash splash page */
void http_nodogsplash_callback_index(httpd *webserver, request *r);
/**@brief Callback for libhttpd, authenticates a client for nodogsplash */
void http_nodogsplash_callback_auth(httpd *webserver, request *r);
/**@brief Callback for libhttpd, denies a client for nodogsplash */
void http_nodogsplash_callback_deny(httpd *webserver, request *r);
/**@brief Add client identified in request to client list. */
t_client* http_nodogsplash_add_client(request *r);
/**@brief Serve a 307 Temporary Redirect */
void http_nodogsplash_redirect(request *r, char *url);
/**@brief Serve the splash page from its file */
void http_nodogsplash_serve_splash(request *r, char *token);
/**@brief Handle initial contact from client */
void http_nodogsplash_first_contact(request *r);
/**@brief Decode token and redirect URL from a request */
void http_nodogsplash_decode_authtarget(request *r, char **token, char **redir);
/**@brief Malloc and return a string that is the authenticating URL */
char* http_nodogsplash_encode_authtarget(request *r, char *token);
/**@brief Allocate and return a random string of 8 hex digits
   suitable as an authentication token */
char * http_make_auth_token();
/** @brief Sends HTML header to web browser */
void http_nodogsplash_header(request *r, char *title);
/** @brief Sends HTML footer to web browser */
void http_nodogsplash_footer(request *r);

#endif /* _HTTP_H_ */
