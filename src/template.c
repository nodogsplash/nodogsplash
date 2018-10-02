#include "template.h"

#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "debug.h"
#include "safe.h"


static const char *get_variable_value(const struct template *vars, const char *name)
{
	int i;

	i = 0;
	while (vars[i].name) {
		if (strcmp(vars[i].name, name) == 0) {
			return vars[i].value;
		}
		i += 1;
	}

	return NULL;
}

/* This is compatible with the old nodogsplash templater.
 * Variable names starts with an '$'.
 * Variable ending is detected if when first non-alphanumeric char is shown - except underline ('_').
 */
int tmpl_parse(struct template *vars, char *dst, size_t dst_len, const char *src, size_t src_len)
{
	int src_i = 0; /* track input buffer position */
	int dst_i = 0;
	int varlen;
	int valuelen;
	char varname[32]; /* contains the varname */
	const char *varnameptr; /* intermediate pointer */
	const char *value; /* value of a variable */

	memset(dst, 0x0, dst_len);
	while ((src_i < src_len) && (dst_i < dst_len)) {
		if (src[src_i] != '$') {
			dst[dst_i] = src[src_i];
			dst_i++;
			src_i++;
			continue;
		}

		/* we know it's a '$'. But we are interest in the next char */
		src_i++;

		/* read the whole variable name */
		varnameptr = src + src_i;
		for (varlen = 0; (varlen < (src_len - src_i)) &&
				(isalnum(varnameptr[varlen]) || varnameptr[varlen] == '_')
				; varlen++)
			;

		/* variable too long, can't be a valid variable */
		if (varlen > (sizeof(varname) - 1)) {
			/* we already parsed the varname and can skip these chars
			 * but we need to copy these first to the output buffer */
			memcpy(dst + dst_i, varnameptr, (varlen > (dst_len - dst_i)) ? (dst_len - dst_i) : varlen);
			src_i += varlen;
			dst_i += varlen;
			continue;
		}

		memset(varname, 0x0, sizeof(varname));
		strncpy(varname, varnameptr, varlen);
		value = get_variable_value(vars, varname);

		/* check if varname was found in valid variable names */
		if (value == NULL) {
			/* we already parsed the varname and can skip these chars */
			memcpy(dst + dst_i, varnameptr, (varlen > (dst_len - dst_i)) ? (dst_len - dst_i) : varlen);
			src_i += varlen;
			dst_i += varlen;
			continue;
		}

		/* it's a valid varname and contains a variable replace it */
		valuelen = strlen(value);
		memcpy(dst + dst_i, value, (valuelen > (dst_len - dst_i)) ? (dst_len - dst_i) : valuelen);
		dst_i += valuelen;
		src_i += varlen;
	}

	return 0;
}
