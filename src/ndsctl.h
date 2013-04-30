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

/* $Id: ndsctl.h 901 2006-01-17 18:58:13Z mina $ */
/** @file ndsctl.h
    @brief nodogsplash monitoring client
    @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@acv.ca>
    trivially modified 2007 for nodogsplash
*/

#ifndef _NDSCTL_H_
#define _NDSCTL_H_

#define DEFAULT_SOCK	"/tmp/ndsctl.sock"

#define NDSCTL_TERMINATOR	"\r\n\r\n"

#define NDSCTL_UNDEF		0
#define NDSCTL_STATUS		1
#define NDSCTL_STOP		2
#define NDSCTL_KILL		3
#define NDSCTL_RESTART		4
#define NDSCTL_BLOCK		5
#define NDSCTL_UNBLOCK		6
#define NDSCTL_ALLOW		7
#define NDSCTL_UNALLOW		8
#define NDSCTL_TRUST		9
#define NDSCTL_UNTRUST		10
#define NDSCTL_AUTH		11
#define NDSCTL_DEAUTH		12
#define NDSCTL_LOGLEVEL		13
#define NDSCTL_PASSWORD		14
#define NDSCTL_USERNAME		15
#define NDSCTL_CLIENTS 		16


typedef struct {
	char	*socket;
	int	command;
	char	*param;
} s_config;


#endif /* _NDSCTL_H_ */
