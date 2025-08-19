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
\********************************************************************/

/** @file state_file.h
    @brief State file import/exporter using json
    @author Copyright (C) 2025 Alexander Couzens <lynxis@fe80.eu>
*/

#ifndef _STATE_FILE_H_
#define _STATE_FILE_H_

#ifdef WITH_STATE_FILE

#include <json-c/json.h>

#include "client_list.h"

int state_file_import_client(json_object *json_client);
int state_file_import(const char *path);

int state_file_export(const char *path);
json_object *state_file_export_client(t_client *client);

#endif /* WITH_STATE_FILE */
#endif /* _STATE_FILE_H_ */
