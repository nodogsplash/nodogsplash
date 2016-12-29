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

/* $Id: ndsctl_thread.h 901 2006-01-17 18:58:13Z mina $ */
/** @file ndsctl_thread.h
    @brief nodogsplash monitoring thread
    @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@acv.ca>
    trivially modified for nodogsplash
*/

#ifndef _NDSCTL_THREAD_H_
#define _NDSCTL_THREAD_H_


#define DEFAULT_NDSCTL_SOCK	"/tmp/ndsctl.sock"

/** @brief Listen for nodogsplash control messages on a unix domain socket */
void *thread_ndsctl(void *arg);


#endif
