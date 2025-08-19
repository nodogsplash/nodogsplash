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

/** @file commandline.c
    @brief Command line argument handling
    @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>

#include "debug.h"
#include "safe.h"
#include "conf.h"


static void usage(void);

/** @internal
 * @brief Print usage
 *
 * Prints usage, called when nodogsplash is run with -h or with an unknown option
 */
static void
usage(void)
{
	printf("Usage: nodogsplash [options]\n"
		"\n"
		"  -c <path>   Use configuration file\n"
		"  -f          Run in foreground\n"
		"  -d <level>  Debug level (%d-%d)\n"
		"  -s          Log to syslog\n"
		"  -w <path>   Ndsctl socket path\n"
		"  -h          Print this help\n"
		"  -v          Print version\n"
		"\n", DEBUGLEVEL_MIN, DEBUGLEVEL_MAX
	);
}

/** Uses getopt() to parse the command line and set configuration values
 */
void parse_commandline(int argc, char **argv)
{
	int c;

	s_config *config = config_get_config();

	while (-1 != (c = getopt(argc, argv, "c:hfd:sw:vi:r:64"))) {

		switch(c) {

		case 'h':
			usage();
			exit(1);
			break;

		case 'c':
			if (optarg) {
				strncpy(config->configfile, optarg, sizeof(config->configfile)-1);
			}
			break;

		case 'w':
			if (optarg) {
				free(config->ndsctl_sock);
				config->ndsctl_sock = safe_strdup(optarg);
			}
			break;

		case 'f':
			config->daemon = 0;
			break;

		case 'd':
			if (set_debuglevel(optarg)) {
				printf("Could not set debuglevel to %d\n", atoi(optarg));
				exit(1);
			}
			break;

		case 's':
			config->log_syslog = 1;
			break;

		case 'v':
			printf("This is Nodogsplash version " VERSION "\n");
			exit(1);
			break;

		case 'r':
			if (optarg) {
				free(config->webroot);
				config->webroot = safe_strdup(optarg);
			}
			break;

		case '4':
			config->ip6 = 0;
			break;

		case '6':
			printf("IPv6 is not supported yet\n");
			exit(1);
			config->ip6 = 1;
			break;

		default:
			usage();
			exit(1);
			break;
		}
	}
}
