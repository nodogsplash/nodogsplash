#ifndef TEMPLATE_H
#define TEMPLATE_H

#include <stdlib.h>

/**
 * @brief holds all valid variable name/value pairs
 */
struct templater {
	struct {
		const char *name;
		const char *value;
	} variables[32]; /* must have enough space to hold all variables */
	int var_count;
};

/**
 * @brief parse a template and replace all variable names with their variables
 * @param templor holds the struct template
 * @param dst
 * @param dst_len
 * @param src
 * @param src_len
 * @return
 */
int tmpl_parse(struct templater *templor, char *dst, size_t dst_len, const char *src, size_t src_len);

/**
 * @brief set a variable
 * @param templor
 * @param name
 * @param value
 * @return
 */
int tmpl_set_variable(struct templater *templor, const char *name, const char *value);

/**
 * @brief initialize templator
 * @param templor
 */
void tmpl_init_templor(struct templater *templor);

#endif // TEMPLATE_H
