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
    @author Copyright (C) 2007 Paul Kube <nodogsplash@kokoro.ucsd.edu>
*/

#ifndef _HTTP_H_
#define _HTTP_H_

#include "auth.h"
#include "httpd.h"
#include "client_list.h"


/**
 * Define parts of an authentication target.
 */
typedef struct _auth_target_t {
	char *ip;			/**< @brief IP of auth server */
	int port;			/**< @brief Port of auth server */
	char *authdir;		/**< @brief Auth dir */
	char *denydir;		/**< @brief Deny dir */
	char *authaction;		/**< @brief Auth action */
	char *denyaction;		/**< @brief Deny action */
	char *authtarget;		/**< @brief Deny action */
	char *token;			/**< @brief Client token */
	char *redir;			/**< @brief Client redirect target */
	char *voucher;    /**< @brief voucher token */
	char *username;		/**< @brief User name */
	char *password;		/**< @brief User password */
	char *info;			/**< @brief Auxilliary info */
} t_auth_target;

/**@brief Callback for libhttpd, serves nodogsplash splash page */
void http_nodogsplash_callback_404(httpd *webserver, request *r);
/**@brief Callback for libhttpd, serves nodogsplash splash page */
void http_nodogsplash_callback_index(httpd *webserver, request *r);
/**@brief Callback for libhttpd, authenticates a client for nodogsplash */
void http_nodogsplash_callback_auth(httpd *webserver, request *r);
/**@brief Callback for libhttpd, denies a client for nodogsplash */
void http_nodogsplash_callback_deny(httpd *webserver, request *r);
/**@brief The multipurpose authentication action handler */
void http_nodogsplash_callback_action(request *r, t_auth_target *authtarget, t_authaction action);
/**@brief Add client identified in request to client list. */
t_client* http_nodogsplash_add_client(request *r);
/**@brief Serve a 302 Found */
void http_nodogsplash_redirect(request *r, const char url[]);
/**@brief Redirect to remote auth server */
void http_nodogsplash_redirect_remote_auth(request *r, t_auth_target *authtarget);
/**@brief Serve the splash page from its file */
void http_nodogsplash_serve_splash(request *r, t_auth_target *authtarget, t_client *client, const char error_msg[]);
/**@brief Serve the info page from its file */
void http_nodogsplash_serve_info(request *r, const char title[], const char content[]);
/**@brief Handle initial contact from client */
void http_nodogsplash_first_contact(request *r);
/**@brief Decode token and redirect URL from a request */
t_auth_target* http_nodogsplash_decode_authtarget(request *r);
/**@brief Malloc and return a t_auth_target struct encoding info */
t_auth_target* http_nodogsplash_make_authtarget(const char token[], const char redir[]);
/**@brief Free a t_auth_target struct */
void http_nodogsplash_free_authtarget(t_auth_target* authtarget);
/**@brief Perform username/password check if configured to use it */
int http_nodogsplash_check_userpass(request *r, t_auth_target *authtarget);
/**@brief Malloc and return a redirect URL */
const char * http_nodogsplash_make_redir(const char origurl[]);
/**@brief Do password check if configured */
int http_nodogsplash_check_password(request *r, t_auth_target *authtarget);
/**@brief Allocate and return a random string of 8 hex digits
   suitable as an authentication token */
const char * http_make_auth_token();
/** @brief Sends HTML header to web browser */
void http_nodogsplash_header(request *r, const char title[]);
/** @brief Sends HTML footer to web browser */
void http_nodogsplash_footer(request *r);


#endif /* _HTTP_H_ */
