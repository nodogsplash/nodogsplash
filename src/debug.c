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

/** @file debug.c
    @brief Debug output routines
    @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
*/

#include <stdio.h>
#include <errno.h>
#include <syslog.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>

#include "util.h"
#include "conf.h"
#include "debug.h"


static int do_log(int level, int debuglevel) {
	switch (level) {
		case LOG_EMERG:
		case LOG_ERR:
			// quiet
			return (debuglevel >= 0);
		case LOG_WARNING:
		case LOG_NOTICE:
			// default
			return (debuglevel >= 1);
		case LOG_INFO:
			// verbose
			return (debuglevel >= 2);
		case LOG_DEBUG:
			// debug
			return (debuglevel >= 3);
		default:
			debug(LOG_ERR, "Unhandled debug level: %d", level);
			return 1;
	}
}

/** @internal
Do not use directly, use the debug macro */
void
_debug(const char filename[], int line, int level, const char *format, ...)
{
	char buf[28];
	va_list vlist;
	s_config *config;
	FILE *out;
	time_t ts;
	sigset_t block_chld;

	time(&ts);

	config = config_get_config();

	if (do_log(level, config->debuglevel)) {
		sigemptyset(&block_chld);
		sigaddset(&block_chld, SIGCHLD);
		sigprocmask(SIG_BLOCK, &block_chld, NULL);

		if (config->daemon) {
			out = stdout;
		} else {
			out = stderr;
		}

		fprintf(out, "[%d][%.24s][%u](%s:%d) ", level, format_time(ts, buf), getpid(), filename, line);
		va_start(vlist, format);
		vfprintf(out, format, vlist);
		va_end(vlist);
		fputc('\n', out);
		fflush(out);

		if (config->log_syslog) {
			openlog("nodogsplash", LOG_PID, config->syslog_facility);
			va_start(vlist, format);
			vsyslog(level, format, vlist);
			va_end(vlist);
			closelog();
		}

		sigprocmask(SIG_UNBLOCK, &block_chld, NULL);
	}
}
