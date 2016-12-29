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

/* $Id: auth.h 1104 2006-10-09 00:58:46Z acv $ */
/** @file auth.h
    @brief Authentication handling thread
    @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@miniguru.ca>
*/

#ifndef _AUTH_H_
#define _AUTH_H_

/**
 * @brief Actions to take on clients.
 */
typedef enum {
	AUTH_MAKE_DEAUTHENTICATED = 1, /**< To make client 'deauthenticated' */
	AUTH_MAKE_AUTHENTICATED = 2 /**< To make client 'authenticated' */
} t_authaction;

/** @brief Take action on a single client */
void auth_client_action(const char ip[], const char mac[], t_authaction action);

/** @brief Periodically check if connections expired */
void *thread_client_timeout_check(void *arg);

#endif
