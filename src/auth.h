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

/** @file auth.h
    @brief Authentication handling thread
    @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@miniguru.ca>
*/

#ifndef _AUTH_H_
#define _AUTH_H_

int auth_client_deauth(unsigned id, const char *reason);
int auth_client_auth(unsigned id, const char *reason);
int auth_client_auth_nolock(const unsigned id, const char *reason);
int auth_client_trust(const char *mac);
int auth_client_untrust(const char *mac);
int auth_client_allow(const char *mac);
int auth_client_unallow(const char *mac);
int auth_client_block(const char *mac);
int auth_client_unblock(const char *mac);

/** @brief Periodically check if connections expired */
void *thread_client_timeout_check(void *arg);

/** @brief Deauth all authenticated clients */
void auth_client_deauth_all();

#endif
