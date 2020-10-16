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

/** @file ndsctl_thread.c
    @brief FakeDNS for NoDogSplash
	Original: http://lordikc.free.fr/sources/fdns.c
	*/

	/*
Copyright (c) 2010, Gilles BERNARD lordikc at free dot fr
All rights reserved.
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.
* Neither the name of the Author nor the
names of its contributors may be used to endorse or promote products
derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE REGENTS AND CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

// Work based on
// rfc1035
// http://code.activestate.com/recipes/491264-mini-fake-dns-server/
// http://www.netfor2.com/dns.htm

#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h> 
#include <string.h> 

#include "debug.h"
#include "fakedns_thread.h"


#define PORT 5553
#define MSG_SIZE 512

FDNSARGS defaults = { PORT, {192,168,10,1} };

void *thread_fakedns(void *zargs)
{
	struct sockaddr_in addr, server;
	FDNSARGS *args;
	char msg[MSG_SIZE];

	if(NULL == zargs)
	{
		args = &defaults;
	}
	else
	{
		args = (FDNSARGS*)zargs;
	}
	debug(LOG_INFO, "Inargs %d.%d.%d.%d:%d", args->targetaddr[0], args->targetaddr[1], args->targetaddr[2], args->targetaddr[3], args->port);

	// socket creation 
	int sd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sd < 0) {
		debug(LOG_ERR, "FAKEDNS couldn't get dgram socket.");
		return NULL;
	}

	// bind local server port 
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = htonl(INADDR_ANY);
	server.sin_port = htons(args->port);
	int rc = bind(sd, (struct sockaddr*) & server, sizeof(server));
	if (rc < 0) {
		debug(LOG_ERR, "FAKEDNS couldn't bind to port %d.", args->port);
		return NULL;
	}

	debug(LOG_NOTICE, "FakeDNS Running on port %d...", args->port);

	int len = sizeof(addr);
	int flags = 0;
	while (1) {
		// receive message 
		int n = recvfrom(sd, msg, MSG_SIZE, flags,
			(struct sockaddr*) & addr, (socklen_t *)&len);

		if (n < 0) { continue; }
		debug(LOG_DEBUG, "DNS Request Received [I don't care what it is].");

		// Same Id
		msg[2] = 0x81; msg[3] = 0x80; // Change Opcode and flags 
		msg[6] = 0; msg[7] = 1; // One answer
		msg[8] = 0; msg[9] = 0; // NSCOUNT
		msg[10] = 0; msg[11] = 0; // ARCOUNT

		//ToDo: if args->targetaddr[0] == -1, return NXDOMAIN
		//		if args->targetaddr[0] == -2, return NODATA

		// Keep request in message and add answer
		msg[n++] = 0xC0; msg[n++] = 0x0C; // Offset to the domain name
		msg[n++] = 0x00; msg[n++] = 0x01; // Type 1
		msg[n++] = 0x00; msg[n++] = 0x01; // Class 1
		msg[n++] = 0x00; msg[n++] = 0x00; msg[n++] = 0x00; msg[n++] = 5; // TTL - 5 seconds
		msg[n++] = 0x00; msg[n++] = 0x04; // Size --> 4
		msg[n++] = args->targetaddr[0]; msg[n++] = args->targetaddr[1]; msg[n++] = args->targetaddr[2]; msg[n++] = args->targetaddr[3]; // IP

																																		// Send the answer
		sendto(sd, msg, n, flags, (struct sockaddr*) & addr, len);
		debug(LOG_DEBUG, "DNS Response Sent.");

	}
	//We don't return; you must kill us. 
}
