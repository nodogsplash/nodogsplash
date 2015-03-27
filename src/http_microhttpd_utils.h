/*
 * uhttpd - Tiny single-threaded httpd
 *
 *	 Copyright (C) 2010-2013 Jo-Philipp Wich <xm@subsignal.org>
 *	 Copyright (C) 2013 Felix Fietkau <nbd@openwrt.org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _UHTTPD_UTILS_

#include <sys/stat.h>

#include <stdarg.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <alloca.h>
#include <time.h>
#include <unistd.h>

struct uh_addr {
	uint8_t family;
	uint16_t port;
	union {
		struct in_addr in;
		struct in6_addr in6;
	};
};

#define min(x, y) (((x) < (y)) ? (x) : (y))
#define max(x, y) (((x) > (y)) ? (x) : (y))

#define array_size(x) \
	(sizeof(x) / sizeof(x[0]))

#define fd_cloexec(fd) \
	fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC)

#ifdef __GNUC__
#define __printf(a, b) __attribute__((format(printf, a, b)))
#else
#define __printf(a, b)
#endif

int uh_urldecode(char *buf, int blen, const char *src, int slen);
int uh_urlencode(char *buf, int blen, const char *src, int slen);
int uh_b64decode(char *buf, int blen, const void *src, int slen);

#endif
