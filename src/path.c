/* libmicrohttpd 1.4.55
 *
 * Copyright (c) 2004, Jan Kneschke, incremental
 *  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * - Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * - Neither the name of the 'incremental' nor the names of its contributors may
 *   be used to endorse or promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

/* - special case: empty string returns empty string
 * - on windows or cygwin: replace \ with /
 * - strip leading spaces
 * - prepends "/" if not present already
 * - resolve "/../", "//" and "/./" the usual way:
 *   the first one removes a preceding component, the other two
 *   get compressed to "/".
 * - "/." and "/.." at the end are similar, but always leave a trailing
 *   "/"
 *
 * /blah/..         gets  /
 * /blah/../foo     gets  /foo
 * /abc/./xyz       gets  /abc/xyz
 * /abc//xyz        gets  /abc/xyz
 *
 * NOTE: src and dest can point to the same buffer, in which case,
 *       the operation is performed in-place.
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define force_assert(a, ...)

void buffer_path_simplify(char *dest, const char *src)
{
	/* current character, the one before, and the one before that from input */
	char c, pre1, pre2;
	char *start, *slash, *out;
	const char *walk;

	force_assert(NULL != dest && NULL != src);

	if (strlen(src) == 0) {
		strcpy(dest, "");
		return;
	}

	force_assert('\0' == src->ptr[src->used-1]);

#if defined(__WIN32) || defined(__CYGWIN__)
	/* cygwin is treating \ and / the same, so we have to that too */
	{
		char *p;
		for (p = src->ptr; *p; p++) {
			if (*p == '\\') *p = '/';
		}
	}
#endif

	walk  = src;
	start = dest;
	out   = dest;
	slash = dest;

	/* skip leading spaces */
	while (*walk == ' ') {
		walk++;
	}
	if (*walk == '.') {
		if (walk[1] == '/' || walk[1] == '\0')
			++walk;
		else if (walk[1] == '.' && (walk[2] == '/' || walk[2] == '\0'))
			walk+=2;
	}

	pre1 = 0;
	c = *(walk++);

	while (c != '\0') {
		/* assert((src != dest || out <= walk) && slash <= out); */
		/* the following comments about out and walk are only interesting if
		 * src == dest; otherwise the memory areas don't overlap anyway.
		 */
		pre2 = pre1;
		pre1 = c;

		/* possibly: out == walk - need to read first */
		c    = *walk;
		*out = pre1;

		out++;
		walk++;
		/* (out <= walk) still true; also now (slash < out) */

		if (c == '/' || c == '\0') {
			const size_t toklen = out - slash;
			if (toklen == 3 && pre2 == '.' && pre1 == '.' && *slash == '/') {
				/* "/../" or ("/.." at end of string) */
				out = slash;
				/* if there is something before "/..", there is at least one
				 * component, which needs to be removed */
				if (out > start) {
					out--;
					while (out > start && *out != '/') out--;
				}

				/* don't kill trailing '/' at end of path */
				if (c == '\0') out++;
				/* slash < out before, so out_new <= slash + 1 <= out_before <= walk */
			} else if (toklen == 1 || (pre2 == '/' && pre1 == '.')) {
				/* "//" or "/./" or (("/" or "/.") at end of string) */
				out = slash;
				/* don't kill trailing '/' at end of path */
				if (c == '\0') out++;
				/* slash < out before, so out_new <= slash + 1 <= out_before <= walk */
			}

			slash = out;
		}
	}

	dest[out - start] = '\0';
}

#ifdef _TESTS
int _buffer_path_simplify(char *input)
{
	char dest[4096] = { 0 };
	buffer_path_simplify(&dest[0], input);
	printf("'%s' = '%s'\n", dest, input);
	return 1;
}

int test_buffer_path_simplify()
{
	_buffer_path_simplify("");
	_buffer_path_simplify("/");
	_buffer_path_simplify("/../");
	return 1;
}
#endif /* _TESTS */
