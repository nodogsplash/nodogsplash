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


/** The 404 handler is one way a client can first hit nodogsplash.
 */
void
http_nodogsplash_callback_404(httpd *webserver, request *r) {
  
  debug(LOG_INFO, "Capturing as 404 request from %s for [%s%s]",
	r->clientAddr, r->request.host, r->request.path);

  http_nodogsplash_first_contact(r);
}


/** The index handler is one way a client can first hit nodogsplash.
 */
void 
http_nodogsplash_callback_index(httpd *webserver, request *r) {

  debug(LOG_INFO, "Capturing index request from %s for [%s%s]",
	r->clientAddr, r->request.host, r->request.path);

  http_nodogsplash_first_contact(r);
}

/** Respond to attempted access from a preauthenticated client.
 *  Add the client to the client list and serves the splash page.
 */
void 
http_nodogsplash_first_contact(request *r) {
  t_client *client;
  t_auth_target *authtarget;
  s_config *config;

  config = config_get_config();

  client = http_nodogsplash_add_client(r);
  /* http_nodogsplash_add_client() should log and return null on error */
  if(!client) return;

  authtarget =
    http_nodogsplash_make_authtarget(client->token,
				     r->request.host,
				     r->request.path);

  if(config->authenticate_immediately) {
    http_nodogsplash_callback_action(r,authtarget,AUTH_MAKE_AUTHENTICATED);
  } else {
    /* TODO: RemoteAuthenticator functionality?
     */
    http_nodogsplash_serve_splash(r,authtarget);
  }

  http_nodogsplash_free_authtarget(authtarget);

}

void
_report_warning(request *r, char *msg) {
    debug(LOG_WARNING, msg);
    http_nodogsplash_header(r, "Nodogsplash Error");
    httpdOutput(r, msg);
    http_nodogsplash_footer(r);
}

/** The multipurpose authentication action handler
 */
void
http_nodogsplash_callback_action(request *r,
				 t_auth_target *authtarget,
				 t_authaction action) {
  t_client	*client;
  char *mac;
  char *ip;
  char *clienttoken = NULL;
  char *requesttoken = authtarget->token;
  char *redir = authtarget->redir;
  s_config *config;

  config = config_get_config();
  
  ip = r->clientAddr;

  if(!requesttoken) {
    debug(LOG_WARNING, "No token in request from ip %s", ip);
    return;
  }
  if(!redir) {
    debug(LOG_WARNING, "No redirect in request from ip %s", ip);
    return;
  }

  if (!(mac = arp_get(ip))) {
    /* We could not get their MAC address */
    debug(LOG_WARNING, "Failed to retrieve MAC address for ip %s", ip);
    http_nodogsplash_header(r, "Nodogsplash Error");
    httpdOutput(r, "Failed to retrieve your MAC address.");
    http_nodogsplash_footer(r);
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
    return;
  }

  /* We have a client */

  /* Do we have a client token? */
  if(!clienttoken) {
    debug(LOG_WARNING, "Client %s at %s does not have a token", ip, mac);
    http_nodogsplash_header(r, "Nodogsplash Error");
    httpdOutput(r, "No token available.");
    http_nodogsplash_footer(r);
    free(mac);
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
      httpdOutput(r, "Authentication revoked.");
      http_nodogsplash_footer(r);
      break;
    default:
      debug(LOG_ERR, "Unknown auth action: %d", action);
    }
    
  } else {
    /* tokens don't match, reject */
    debug(LOG_WARNING, "Client %s at MAC %s tokens %s, %s do not match",
	  r->clientAddr, mac, clienttoken, requesttoken);
    http_nodogsplash_header(r, "Nodogsplash Error");
    httpdOutput(r, "Tokens do not match.");
    http_nodogsplash_footer(r);
  }
  free(mac);
  free(clienttoken);

}

/** The auth handler registers the client as authenticated, and redirects their web request */
void
http_nodogsplash_callback_auth(httpd *webserver, request *r) {
  t_auth_target *authtarget;

  /* Get info we need from request, and do action */
  authtarget = http_nodogsplash_decode_authtarget(r);
  http_nodogsplash_callback_action (r,authtarget,AUTH_MAKE_AUTHENTICATED );
  http_nodogsplash_free_authtarget(authtarget);
}

/** The deny handler removes the client from the client list */
void
http_nodogsplash_callback_deny(httpd *webserver, request *r) {
  t_auth_target *authtarget;

  /* Get info we need from request, and do action */
  authtarget = http_nodogsplash_decode_authtarget(r);
  http_nodogsplash_callback_action (r,authtarget,AUTH_MAKE_DEAUTHENTICATED );
  http_nodogsplash_free_authtarget(authtarget);
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
 


/* Given a client request, pipe the splash page from the splash page file. */
void
http_nodogsplash_serve_splash(request *r, t_auth_target *authtarget) {
  char *abspath;
  char line [MAX_BUF];
  char *splashfilename;
  FILE *fd;
  s_config	*config;

  
  config = config_get_config();

  /* Set variables; these can be interpolated in the splash page text. */
  httpdAddVariable(r,"gatewayname",config->gw_name);
  httpdAddVariable(r,"tok",authtarget->token);
  httpdAddVariable(r,"redir",authtarget->redir);
  httpdAddVariable(r,"authaction",authtarget->authaction);
  httpdAddVariable(r,"denyaction",authtarget->denyaction);
  httpdAddVariable(r,"authtarget",authtarget->authtarget);
  /* We need to have imagesdir and pagesdir appear in the page
     as absolute paths, so they work no matter what the
     initial user request URL was  */
  safe_asprintf(&abspath, "/%s", config->imagesdir);
  httpdAddVariable(r,"imagesdir",abspath);
  free(abspath);
  safe_asprintf(&abspath, "/%s", config->pagesdir);
  httpdAddVariable(r,"pagesdir",abspath);
  free(abspath);
  
  /* Pipe the splash page from its file */
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

/**
 * Allocate and return a pointer to a t_auth_target struct encoding information
 * needed to eventually authenticate a client.
 * See http_nodogsplash_make_authtarget().
 * Fields token and redir will be set;
 * all other fields in the struct are zeroed.
 * The struct should be freed by http_nodogsplash_free_authtarget().
 */
t_auth_target *
http_nodogsplash_decode_authtarget(request *r) {
  char *p1;
  httpVar *var;
  request *r2;
  t_auth_target *authtarget;
  
  /* r->request.path should have the form: /<directory>/<rest>,
   * where <directory> has had its effect already in determining which
   * callback is procesing the request, so we ignore it here,
   * and where <rest> is a string encoding variables and values in the
   * usual way.
   * So, here we find <rest>, and store variable/value pairs in the request,
   * to find values of token and redir.
   */
  p1 =   strchr(r->request.path,'/');        /* initial slash */
  if(!p1) {
    _report_warning(r,"Malformed action request: first");
    return NULL;
  }
  p1++;
  p1 = strchr(p1,'/');              /* second slash */
  if(!p1) {
    _report_warning(r,"Malformed action request: second");
    return NULL;
  }
  p1++;
  if(*p1 == '?') p1++;
  
  /* Create another request struct r2 to avoid polluting r */
  r2 = safe_malloc(sizeof(request));
  memset(r2, 0, sizeof(request));

  /* Parse <rest>, store variables in r2
   * N.B.: httpd_storeData() httpd_unescape's variable values
   */
  httpd_storeData(r2,p1);
  /* now get variable values from r2 */
  authtarget = safe_malloc(sizeof(t_auth_target));
  memset(authtarget, 0, sizeof(t_auth_target));
  var = httpdGetVariableByName(r2,"tok");
  if(var) {
    authtarget->token = safe_strdup(var->value);
  }
  var = httpdGetVariableByName(r2,"redir");
  if(var) {
    authtarget->redir = safe_strdup(var->value);
  }
  httpdFreeVariables(r2);
  free(r2);

  return authtarget;

}

/**
 * Allocate and return a pointer to a t_auth_target struct encoding information
 * needed to eventually authenticate a client.
 * The struct should be freed by http_nodogsplash_free_authtarget().
 */
t_auth_target*
http_nodogsplash_make_authtarget(char* token, char* redirhost, char* redirpath) {
  char *encodedredir;
  t_auth_target* authtarget;
  s_config *config;

  config = config_get_config();

  authtarget = safe_malloc(sizeof(t_auth_target));
  memset(authtarget, 0, sizeof(t_auth_target));

  authtarget->ip = safe_strdup(config->gw_address);
  authtarget->port = config->gw_port;
  authtarget->authdir = safe_strdup(config->authdir);
  authtarget->denydir = safe_strdup(config->denydir);
  safe_asprintf(&(authtarget->authaction),"http://%s:%d/%s/",authtarget->ip,authtarget->port,authtarget->authdir);
  safe_asprintf(&(authtarget->denyaction),"http://%s:%d/%s/",authtarget->ip,authtarget->port,authtarget->denydir);
  authtarget->token = safe_strdup(token);
  if(config->redirectURL) {
    debug(LOG_DEBUG,"Client requested http://%s%s, substituting %s",
	  redirhost,redirpath,config->redirectURL);
    authtarget->redir = safe_strdup(config->redirectURL);
  } else {
    safe_asprintf(&(authtarget->redir),"http://%s%s",redirhost,redirpath);
  }
  /* URL encode the redirect URL for authtarget */
  encodedredir = httpdUrlEncode(authtarget->redir);  /* malloc's */
  safe_asprintf(&(authtarget->authtarget), "%s?redir=%s&tok=%s",
		authtarget->authaction,
		encodedredir,
		authtarget->token);
  free(encodedredir);

  return authtarget;
}




void
http_nodogsplash_free_authtarget(t_auth_target* authtarget) {

  if(authtarget->ip) free(authtarget->ip);
  if(authtarget->authdir) free(authtarget->authdir);
  if(authtarget->denydir) free(authtarget->denydir);
  if(authtarget->authaction) free(authtarget->authaction);
  if(authtarget->denyaction) free(authtarget->denyaction);
  if(authtarget->authtarget) free(authtarget->authtarget);
  if(authtarget->token) free(authtarget->token);
  if(authtarget->redir) free(authtarget->redir);
  if(authtarget->user) free(authtarget->user);
  if(authtarget->passwd) free(authtarget->passwd);
  free(authtarget);

}



/** Allocate and return a random string of 8 hex digits
 *  suitable as an authentication token.
 *  Caller must free.
 */
char *
http_make_auth_token() {
  char * token;

  safe_asprintf(&token,"%04hx%04hx", rand16(), rand16());

  return token;
}
