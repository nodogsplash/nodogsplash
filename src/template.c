#include "template.h"

#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "safe.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

const char *variable_names[18] = {
	"authaction",
	"authtarget",
	"clientip",
	"clientmac",
	"content",
	"denyaction",
	"error_msg",
	"gatewaymac",
	"gatewayname",
	"imagesdir",
	"maxclients",
	"nclients",
	"pagesdir",
	"redir",
	"title",
	"tok",
	"uptime",
	"version"
};

static int get_variable_index(const char *name)
{
	int j;

	for(j=0; j < ARRAY_SIZE(variable_names); j++) {
		if(strcmp(name, variable_names[j]) == 0) {
			fprintf(stderr, "vari %s = %s %d", name, variable_names[j], j);
			return j;
		}
	}

	return -1;
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
	char varname[32]; /* contain the varname */
	const char *varnameptr; /* intermediate pointer */
	int varidx; /* the position of the variable in variable_names */

	memset(dst, 0x0, dst_len);
	while((src_i < src_len) && (dst_i < dst_len)) {
		if(src[src_i] != '$') {
			dst[dst_i]	= src[src_i];
			dst_i++;
			src_i++;
			continue;
		}

		/* we know it's a '$'. But we are interest in the next char */
		src_i++;

		/* read the whole variablename */
		varnameptr = src + src_i;
		for(varlen=0; (varlen < (src_len-src_i)) &&
				(isalnum(varnameptr[varlen]) || varnameptr[varlen] == '_')
				; varlen++)
			;

		/* variable to long, cant be a valid variable */
		if(varlen > sizeof(varname)-1) {
			/* we already parsed the varname and can skip these chars
			 * but we need to copy these first to the output buffer */
			strncpy(dst + dst_i, varnameptr, varlen > dst_len-dst_i ? dst_len-dst_i : varlen);
			src_i += varlen;
			dst_i += varlen;
			continue;
		}

		memset(varname, 0x0, sizeof(varname));
		strncpy(varname, varnameptr, varlen);
		varidx = get_variable_index(varname);

		/* check if varname was found in valid variable names */
		if (varidx == -1) {
			/* we already parsed the varname and can skip these chars */
			strncpy(dst + dst_i, varnameptr, varlen > dst_len-dst_i ? dst_len-dst_i : varlen);
			src_i += varlen;
			dst_i += varlen;
			continue;
		}

		/* check if	variable name is empty */
		if (templor->variables[varidx] == NULL ||
				strlen(templor->variables[varidx]) == 0) {
			src_i += varlen;
			continue;
		}

		/* it's a valid varname and contains a variable replace it */
		valuelen = strlen(templor->variables[varidx]);
		strncpy(dst + dst_i, templor->variables[varidx], valuelen > dst_len-dst_i ? dst_len-dst_i : valuelen);
		dst_i += valuelen;
		src_i += varlen;
	}
	return 0;
}

int tmpl_set_variable(struct templater *templor, const char *name, const char *value)
{
	int idx;

	if(!templor)
		return -1;

	if(!value)
		return -1;

	idx = get_variable_index(name);
	if(idx < 0)
		return -1;

	if(templor->variables[idx])
		free((void *)templor->variables[idx]);

	templor->variables[idx] = safe_strdup(value);

	return 0;
}

void tmpl_init_templor(struct templater *templor)
{
	if(!templor)
		return;
	memset(templor, 0x0, sizeof(*templor));
}
