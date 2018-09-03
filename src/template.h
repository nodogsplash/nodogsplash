#ifndef TEMPLATE_H
#define TEMPLATE_H

#include <stdlib.h>

/**
 * @brief holds one variable name/value pairs
 *
 */
struct template {
	const char *name;
	const char *value;
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
int tmpl_parse(struct template *vars, char *dst, size_t dst_len, const char *src, size_t src_len);


#endif // TEMPLATE_H
