#ifndef _NDS_MICROHTTPD_H
#define _NDS_MICROHTTPD_H

#include <stdio.h>

struct MHD_Connection;

enum MHD_Result libmicrohttpd_cb (void *cls,
					struct MHD_Connection *connection,
					const char *url,
					const char *method,
					const char *version,
					const char *upload_data, size_t *upload_data_size, void **ptr);


#endif /* _NDS_MICROHTTPD_H */
