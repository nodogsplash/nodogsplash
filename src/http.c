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

/* $Id: http.c 1104 2006-10-09 00:58:46Z acv $ */
/** @file http.c
  @brief HTTP IO functions
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>

#include "httpd.h"

#include "safe.h"
#include "debug.h"
#include "conf.h"
#include "auth.h"
#include "firewall.h"
#include "http.h"
#include "httpd.h"
#include "client_list.h"
#include "common.h"

#include "util.h"

#include "../config.h"

extern pthread_mutex_t	client_list_mutex;


void 
http_callback_about(httpd *webserver, request *r) {
  http_nodogsplash_header(r, "About nodogsplash");
  httpdOutput(r, "This is nodogsplash version <b>" VERSION "</b>");
  http_nodogsplash_footer(r);
}

void 
http_callback_status(httpd *webserver, request *r) {
  char * status = NULL;
  status = get_status_text();
  http_nodogsplash_header(r, "nodogsplash Status");
  httpdOutput(r, "<pre>");
  httpdOutput(r, status);
  httpdOutput(r, "</pre>");
  http_nodogsplash_footer(r);
  free(status);
}


void
http_nodogsplash_header(request *r, char *title) {
  httpdOutput(r, "<html>\n");
  httpdOutput(r, "<head>\n");
  httpdPrintf(r, "<title>%s</title>\n", title);
  httpdOutput(r, "<meta HTTP-EQUIV='Pragma' CONTENT='no-cache'>\n");

  httpdOutput(r, "<style>\n");
  httpdOutput(r, "body {\n");
  httpdOutput(r, "  margin: 10px 60px 0 60px; \n");
  httpdOutput(r, "  font-family : bitstream vera sans, sans-serif;\n");
  httpdOutput(r, "  color: #000000;\n");
  httpdOutput(r, "}\n");

  httpdOutput(r, "a {\n");
  httpdOutput(r, "  color: #000000;\n");
  httpdOutput(r, "}\n");

  httpdOutput(r, "a:active {\n");
  httpdOutput(r, "  color: #000000;\n");
  httpdOutput(r, "}\n");

  httpdOutput(r, "a:link {\n");
  httpdOutput(r, "  color: #000000;\n");
  httpdOutput(r, "}\n");

  httpdOutput(r, "a:visited {\n");
  httpdOutput(r, "  color: #000000;\n");
  httpdOutput(r, "}\n");

  httpdOutput(r, "#header {\n");
  httpdOutput(r, "  height: 30px;\n");
  httpdOutput(r, "  background-color: #DDDDDD;\n");
  httpdOutput(r, "  padding: 20px;\n");
  httpdOutput(r, "  font-size: 20pt;\n");
  httpdOutput(r, "  text-align: center;\n");
  httpdOutput(r, "  border: 2px solid #000000;\n");
  httpdOutput(r, "  border-bottom: 0;\n");
  httpdOutput(r, "}\n");

  httpdOutput(r, "#menu {\n");
  httpdOutput(r, "  width: 200px;\n");
  httpdOutput(r, "  float: right;\n");
  httpdOutput(r, "  background-color: #DDDDDD;\n");
  httpdOutput(r, "  border: 2px solid #000000;\n");
  httpdOutput(r, "  font-size: 80%;\n");
  httpdOutput(r, "  min-height: 300px;\n");
  httpdOutput(r, "}\n");

  httpdOutput(r, "#menu h2 {\n");
  httpdOutput(r, "  margin: 0;\n");
  httpdOutput(r, "  background-color: #000000;\n");
  httpdOutput(r, "  text-align: center;\n");
  httpdOutput(r, "  color: #DDDDDD;\n");
  httpdOutput(r, "}\n");

  httpdOutput(r, "#copyright {\n");
  httpdOutput(r, "}\n");

  httpdOutput(r, "#content {\n");
  httpdOutput(r, "  padding: 20px;\n");
  httpdOutput(r, "  border: 2px solid #000000;\n");
  httpdOutput(r, "  min-height: 300px;\n");
  httpdOutput(r, "}\n");
  httpdOutput(r, "</style>\n");

  httpdOutput(r, "</head>\n");

  httpdOutput(r, "<body\n");

  httpdOutput(r, "<div id=\"header\">\n");
  httpdPrintf(r, "    %s\n", title);
  httpdOutput(r, "</div>\n");

  httpdOutput(r, "<div id=\"menu\">\n");


  httpdOutput(r, "    <h2>Info</h2>\n");
  httpdOutput(r, "    <ul>\n");
  httpdOutput(r, "    <li>Version: " VERSION "\n");
  httpdPrintf(r, "    <li>Node ID: %s\n", config_get_config()->gw_name);
  httpdOutput(r, "    </ul>\n");
  httpdOutput(r, "    <br>\n");

  httpdOutput(r, "</div>\n");

  httpdOutput(r, "<div id=\"content\">\n");
  httpdPrintf(r, "<h2>%s</h2>\n", title);
}

void
http_nodogsplash_footer(request *r) {
  httpdOutput(r, "</div>\n");

  httpdOutput(r, "<div id=\"copyright\">\n");
  httpdOutput(r, "Copyright (C) 2004-2007.  This software is released under the GNU GPL license.\n");
  httpdOutput(r, "</div>\n");

  httpdOutput(r, "</body>\n");
  httpdOutput(r, "</html>\n");
}


/** The 404 handler adds the client to the client list
 *  and serves the splash page
 */
void
http_nodogsplash_callback_404(httpd *webserver, request *r) {
  t_client *client;
  
  debug(LOG_INFO, "Capturing as 404 request from %s for [%s%s]",
	r->clientAddr, r->request.host, r->request.path);

  
  client = http_nodogsplash_add_client(r);
  if(client) {
    http_nodogsplash_serve_splash(r,client->token,r->request.host,r->request.path);
  }

}


/** The index handler adds the client to the client list
 *  and serves the splash page
 */
void 
http_nodogsplash_callback_index(httpd *webserver, request *r) {
  t_client *client;

  debug(LOG_INFO, "Capturing index request from %s for [%s%s]",
	r->clientAddr, r->request.host, r->request.path);

  client = http_nodogsplash_add_client(r);
  if(client) {
    http_nodogsplash_serve_splash(r,client->token,r->request.host,r->request.path);
  }
}

void
_report_warning(request *r, char *msg) {
    debug(LOG_WARNING, msg);
    http_nodogsplash_header(r, "Nodogsplash Error");
    httpdOutput(r, msg);
    http_nodogsplash_footer(r);
}

/** The multipurpose handler */
void
http_nodogsplash_callback_action(httpd *webserver, request *r, t_authaction action) {
  t_client	*client;
  char *mac;
  char *ip;
  char *p1, *p2, *pathcopy;
  char *redir = NULL;
  char *clienttoken = NULL;
  char *requesttoken = NULL;
  s_config *config;

  config = config_get_config();
  
  /* Get components of path in request */
  /* Make a copy; we will modify it */
  pathcopy = safe_strdup(r->request.path);
  /* path has the form: /<directory>/<rest>,
   * where <directory> is not needed here,and
   * where <rest> has been httpdUrlEncoded to encode slashes.
   * (See http_nodogsplash_serve_splash() for how this
   * path is constructed.)
   * So, here we first find <rest> and httpdUrlDecode it,
   * to see that <rest> has the form: <requesttoken>/<redir>
   */
  p1 = strchr(pathcopy,'/');        /* initial slash */
  if(!p1) { _report_warning(r,"Malformed action request: first"); free(pathcopy); return; }
  p1++;
  p1 = strchr(p1,'/');              /* second slash */
  if(!p1) { _report_warning(r,"Malformed action request: second"); free(pathcopy); return; }
  p1++;
  /* httpdUrlDecode the rest.  This recovers slashes, among other things. */
  p1 = httpdUrlDecode(p1); /* Note: this decodes in-place */
  /* now look for <requesttoken>/<redir> */
  p2 = strchr(p1,'/');              /* third slash */
  if(!p2) { _report_warning(r,"Malformed action request: third"); free(pathcopy); return; }
  *p2 = '\0';
  /* p1 now pointing at terminated token; allocate a copy */
  requesttoken = safe_strdup(p1); 
  p2++;
  /* p2 now pointing at decoded redirect; allocate a copy */
  safe_asprintf(&redir,"http://%s",p2);
  free(pathcopy);

  ip = r->clientAddr;

  if (!(mac = arp_get(ip))) {
    /* We could not get their MAC address */
    
    debug(LOG_WARNING, "Failed to retrieve MAC address for ip %s", ip);
    http_nodogsplash_header(r, "Nodogsplash Error");
    httpdOutput(r, "Failed to retrieve your MAC address.");
    http_nodogsplash_footer(r);
    free(requesttoken);
    free(redir);
    return;
  }

  /* We have their MAC address, find them on the client list */
  LOCK_CLIENT_LIST();
  client = client_list_find(ip, mac);
  if(client && client->token) clienttoken = safe_strdup(client->token);
  UNLOCK_CLIENT_LIST();

  if(!client) {
    debug(LOG_WARNING, "Client %s at %s requesting action %d is not on client list",
	  ip, mac, action);
    http_nodogsplash_header(r, "Nodogsplash Error");
    httpdOutput(r, "You are not on the client list.");
    http_nodogsplash_footer(r);
    free(mac);
    free(requesttoken);
    free(redir);
    return;
  }

  /* We have a client */
  /* If there is a redir in the config, use it instead of redir in this request */
  if(config->redirectURL) {
    free(redir);
    redir = safe_strdup(config->redirectURL);
  }

  /* Do we have a client token? */
  if(!clienttoken) {
    debug(LOG_WARNING, "Client %s at %s does not have a token", ip, mac);
    http_nodogsplash_header(r, "Nodogsplash Error");
    httpdOutput(r, "No token available.");
    http_nodogsplash_footer(r);
    free(mac);
    free(requesttoken);
    free(redir);
    return;
  } 

  debug(LOG_DEBUG, "Action %d: IP %s MAC %s: client: %s, request: %s",
	action, ip, mac, clienttoken, requesttoken);  
  debug(LOG_DEBUG, "Redirect:  %s", redir);
  /* Check if tokens match */
  if (! strcmp(clienttoken,requesttoken)) {
    /* take action */
    switch(action) {
    case AUTH_MAKE_AUTHENTICATED:
      auth_client_action(ip,mac,action);
      http_nodogsplash_redirect(r, redir);
      break;
    case AUTH_MAKE_DEAUTHENTICATED:
      auth_client_action(ip,mac,action);
      http_nodogsplash_header(r, "Nodogsplash Deny");
      httpdOutput(r, "OK, see you later!");
      http_nodogsplash_footer(r);
      break;
    default:
      debug(LOG_ERR, "Unknown auth action: %d", action);
    }
    
  } else {
    /* tokens don't match, reject */
    debug(LOG_NOTICE, "Client %s at MAC %s tokens %s, %s do not match",
	  r->clientAddr, mac, clienttoken, requesttoken);
    http_nodogsplash_header(r, "Nodogsplash Error");
    httpdOutput(r, "Tokens do not match.");
    http_nodogsplash_footer(r);
  }
  free(mac);
  free(redir);
  free(requesttoken);
  free(clienttoken);

}

/** The auth handler registers the client as authenticated, and redirects their web request */
void
http_nodogsplash_callback_auth(httpd *webserver, request *r) {

  http_nodogsplash_callback_action ( webserver, r, AUTH_MAKE_AUTHENTICATED );

}

/** The deny handler removes the client from the client list */
void
http_nodogsplash_callback_deny(httpd *webserver, request *r) {

  http_nodogsplash_callback_action ( webserver, r, AUTH_MAKE_DEAUTHENTICATED );

}



/**
 *  Add client making a request to client list, creating a
 *  random token for them.
 *  Does nothing if a client with the same IP and MAC address
 *  is already on the list.
 *
 *  N.B.: This does not authenticate the client; it only makes
 *  their information available on the client list.
 */
t_client *
http_nodogsplash_add_client(request *r) {
  t_client	*client;
  char	*mac, *token;
  s_config	*config;

  if (!(mac = arp_get(r->clientAddr))) {
    /* We could not get their MAC address */
    debug(LOG_WARNING, "Failed to retrieve MAC address for ip %s", r->clientAddr);
  } 


  LOCK_CLIENT_LIST();
			
  if ((client = client_list_find(r->clientAddr, mac)) == NULL) {
    token = http_make_auth_token();  /* get a new random token */
    debug(LOG_DEBUG, "New client %s at %s token %s",
	  r->clientAddr, mac, token);
    client = client_list_append(r->clientAddr, mac, token);
    free(token);
  } else {
    debug(LOG_DEBUG, "Client %s at %s already exists",
	  r->clientAddr, mac);
  }
  UNLOCK_CLIENT_LIST();
  free(mac);
  return client;
}
 

/* Serve the splash page from its file. */
void
http_nodogsplash_serve_splash(request *r, char *token, char *host, char *path) {
  char *redirectURL;
  char line [MAX_BUF];
  char *splashfilename, *authtarget, *denytarget, *imagesdir;
  char *encodedthp, *tokenhostpath;
  FILE *fd;
  s_config	*config;


  config = config_get_config();
  /* Set variables; these can be interpolated in the splash page text. */

  httpdAddVariable(r,"gatewayname",config->gw_name);

  /* Work on setting up auth and deny targets. */
  safe_asprintf(&tokenhostpath,"%s/%s%s", token, host, path);
  /* We httpdUrlEncode() the concatenation of token, host, path.
   * This requires a modified version of httpdUrlEncode() which encodes slashes
   * (as well as the usual things).
   * This is because we must have an
   * authtarget that looks like a top-level directory, and one file in it.
   * (Similarly for denytarget.)
   * Slashes will be recovered when we httpdUrlDecode() in
   * http_nodogsplash_callback_action().
   */
  encodedthp = httpdUrlEncode(tokenhostpath);  /* malloc's */
  free(tokenhostpath);
  safe_asprintf(&authtarget, "http://%s:%d/%s/%s",
		config->gw_address, config->gw_port, config->authdir, encodedthp);
  httpdAddVariable(r,"authtarget",authtarget);
  free(authtarget);
  
  safe_asprintf(&denytarget, "http://%s:%d/%s/%s",
		config->gw_address, config->gw_port, config->denydir, encodedthp);
  httpdAddVariable(r,"denytarget",denytarget);
  free(denytarget);
  
  free(encodedthp);

  safe_asprintf(&imagesdir, "/%s", config->imagesdir);
  httpdAddVariable(r,"imagesdir",imagesdir);
  free(imagesdir);

  /* Pipe page from file */
  safe_asprintf(&splashfilename, "%s/%s", config->webroot, config->splashpage );
  if (!(fd = fopen(splashfilename, "r"))) {
    debug(LOG_ERR, "Could not open splash page file '%s'", splashfilename);
    http_nodogsplash_header(r, "Nodogsplash Error");
    httpdOutput(r, "Failed to open splash page file");
    http_nodogsplash_footer(r);
  } else {
    while (fgets(line, MAX_BUF, fd)) {
      httpdOutput(r,line);
    }
    fclose(fd);
  }

  free(splashfilename);

}

void
http_nodogsplash_redirect(request *r, char *url) {
  char *header;

  httpdSetResponse(r, "307 Temporary Redirect");
  safe_asprintf(&header, "Location: %s",url);
  httpdAddHeader(r, header);

  httpdPrintf(r, "<html><head></head><body><a href='%s'>Click here to continue to<br>%s</a></body></html>",url,url);

  free(header);

}

/** Allocate and return a random string of 8 hex digits suitable as an authentication token.
 *  Caller must free.
 */
char *
http_make_auth_token() {
  char * token;

  safe_asprintf(&token,"%04hx%04hx", rand16(), rand16());

  return token;
}
