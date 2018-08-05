#include "template.h"

#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "debug.h"
#include "safe.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

static int get_variable_index(const struct templater *templor, const char *name)
{
	int i;

	for (i = 0; i < templor->var_count; i++) {
		if (strcmp(name, templor->variables[i].name) == 0) {
			return i;
		}
	}

	return -1;
}

static const char *get_variable_value(const struct templater *templor, const char *name)
{
	int idx;

	idx = get_variable_index(templor, name);

	return (idx < 0) ? NULL : templor->variables[idx].value;
}

/* This is compatible with the old nodogsplash templater.
 * Variable names starts with an '$'.
 * Variable ending is detected if when first non-alphanumeric char is shown - except underline ('_').
 */
int tmpl_parse(struct templater *templor, char *dst, size_t dst_len, const char *src, size_t src_len)
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
			strncpy(dst + dst_i, varnameptr, (varlen > (dst_len - dst_i)) ? (dst_len - dst_i) : varlen);
			src_i += varlen;
			dst_i += varlen;
			continue;
		}

		memset(varname, 0x0, sizeof(varname));
		strncpy(varname, varnameptr, varlen);
		value = get_variable_value(templor, varname);

		/* check if varname was found in valid variable names */
		if (value == NULL) {
			/* we already parsed the varname and can skip these chars */
			strncpy(dst + dst_i, varnameptr, (varlen > (dst_len - dst_i)) ? (dst_len - dst_i) : varlen);
			src_i += varlen;
			dst_i += varlen;
			continue;
		}

		/* it's a valid varname and contains a variable replace it */
		valuelen = strlen(value);
		strncpy(dst + dst_i, value, valuelen > dst_len-dst_i ? dst_len-dst_i : valuelen);
		dst_i += valuelen;
		src_i += varlen;
	}

	return 0;
}

int tmpl_set_variable(struct templater *templor, const char *name, const char *value)
{
	int idx;

	if (!name || !value) {
		debug(LOG_ERR, "set variable with NULL name or value. name: %s, value: %s", name, value);
		return -1;
	}

	if (templor->var_count >= ARRAY_SIZE(templor->variables)) {
		// no more variable space
		debug(LOG_ERR, "No more space for variable %s in templater.", name);
		return -1;
	}

	idx = get_variable_index(templor, name);
	if (idx >= 0) {
		// variable already set
		debug(LOG_ERR, "Variable %s already set in templater.", name);
		return -1;
	}

	idx = templor->var_count;
	templor->variables[idx].name = name;
	templor->variables[idx].value = value;
	templor->var_count += 1;

	return 0;
}

void tmpl_init_templor(struct templater *templor)
{
	memset(templor, 0, sizeof(struct templater));
}
