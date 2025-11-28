
/** @file state_file.c
    @brief State file import/exporter using json
    @author Copyright (C) 2025 Alexander Couzens <lynxis@fe80.eu>
*/

#include <errno.h>
#include <string.h>
#include <sys/stat.h>

#include <json-c/json.h>

#include "auth.h"
#include "client_list.h"
#include "debug.h"
#include "safe.h"

#define NDS_JSON_EXPORT_VERSION 1
#define GOTO_ERR(_err, x) if ((x)) { goto _err; }

json_object *
state_file_export_client(t_client *client)
{
	json_object *cli = json_object_new_object();
	if (!cli)
		return NULL;

	GOTO_ERR(err, json_object_object_add(cli, "ip", json_object_new_string(client->ip)));
	GOTO_ERR(err, json_object_object_add(cli, "mac", json_object_new_string(client->mac)));
	GOTO_ERR(err, json_object_object_add(cli, "token", json_object_new_string(client->token)));
	GOTO_ERR(err, json_object_object_add(cli, "fw_connection_state", json_object_new_int64(client->fw_connection_state)));
	GOTO_ERR(err, json_object_object_add(cli, "session_start", json_object_new_uint64(client->session_start)));
	GOTO_ERR(err, json_object_object_add(cli, "session_end", json_object_new_uint64(client->session_end)));
	GOTO_ERR(err, json_object_object_add(cli, "download_limit", json_object_new_int64(client->download_limit)));
	GOTO_ERR(err, json_object_object_add(cli, "upload_limit", json_object_new_int64(client->upload_limit)));
	GOTO_ERR(err, json_object_object_add(cli, "id", json_object_new_uint64(client->id)));

	json_object *counters = json_object_new_object();
	if (!counters)
		goto err;

	GOTO_ERR(err_counter, json_object_object_add(counters, "incoming", json_object_new_uint64(client->counters.incoming)));
	GOTO_ERR(err_counter, json_object_object_add(counters, "outgoing", json_object_new_uint64(client->counters.outgoing)));
	GOTO_ERR(err_counter, json_object_object_add(counters, "last_updated", json_object_new_uint64(client->counters.last_updated)));
	/* unsure if the lifetime of child object _always_ go towards the parent (cli) */
	GOTO_ERR(err, json_object_object_add(cli, "counters", counters));

	return cli;

err_counter:
	json_object_put(counters);
err:
	json_object_put(cli);
	return NULL;
}

int
state_file_export(const char *path)
{
	int rc = 0;
	json_object *top = json_object_new_object();

	if (!top)
		return -ENOMEM;

	GOTO_ERR(err, json_object_object_add(top, "version", json_object_new_int64(NDS_JSON_EXPORT_VERSION)));
	GOTO_ERR(err, json_object_object_add(top, "name", json_object_new_string("nodogsplash")));

	json_object *clist = json_object_new_array();
	if (!clist)
		goto err;

	LOCK_CLIENT_LIST();
	t_client *ptr;
	for (ptr = client_get_first_client(); ptr; ptr = ptr->next) {
		json_object *client = state_file_export_client(ptr);
		if (!client) {
			UNLOCK_CLIENT_LIST();
			goto err_clist;
		}
		json_object_array_add(clist, client);
	}
	UNLOCK_CLIENT_LIST();
	GOTO_ERR(err_clist, json_object_object_add(top, "clients", clist));

	if ((rc = json_object_to_file(path, top))) {
		debug(LOG_ERR, "Failed to write nodogsplash to a file, json_object_to_file() failed with rc %d."
			       " json-c failure: %s",
		      rc, json_util_get_last_err());
		return -EINVAL;
	}

	json_object_put(top);
	return 0;

err_clist:
	json_object_put(clist);
err:
	json_object_put(top);
	return -EINVAL;
}

/* Set _target to a json object of _jsn_obj.
 * The object must be freed by json_object_put() later.
 *
 * pseudo code equivalent:
 *   _target = json_object_object_get(top, "foo");
 *   if (!validate_type(_target, json_type_object)) { goto _err };
 */
#define JSON_GET_FIELD_OBJECT(_target, _err, _jsn_obj, _field, _jsn_type) do { \
		json_object *jsn_ptr; \
		if (!json_object_object_get_ex(_jsn_obj, _field, &jsn_ptr)) { \
		    debug(LOG_ERR, "Failed to get " _field); \
		    goto err; \
		} \
		if (!json_object_is_type(jsn_ptr, _jsn_type)) { \
		    debug(LOG_ERR, "Wrong type for field " _field " found type %s, expected %s", \
			  json_type_to_name(json_object_get_type(jsn_ptr)), \
			  json_type_to_name(_jsn_type)); \
		    goto err; \
		} \
		_target = jsn_ptr; \
	} while (0)

/* Set _target to the value of the json behind field */
#define JSON_GET_FIELD(_target, _err, _jsn_obj, _field, _jsn_type, _jsn_func) do { \
		json_object *jsn_ptr = json_object_object_get(_jsn_obj, _field); \
		if (!jsn_ptr) { \
			debug(LOG_ERR, "Failed to get " _field); \
			goto err; \
		} \
		if (!json_object_is_type(jsn_ptr, _jsn_type)) { \
			debug(LOG_ERR, "Wrong type for field " _field " found type %s, expected %s", \
					json_type_to_name(json_object_get_type(jsn_ptr)), \
					json_type_to_name(_jsn_type)); \
			goto err; \
		}	\
		_target = _jsn_func(jsn_ptr); \
	} while (0)

int
state_file_import_client(json_object *json_client)
{
	t_client *client = NULL;
	const char *mac = NULL;
	const char *ip = NULL;
	unsigned id;
	JSON_GET_FIELD(mac, err, json_client, "mac", json_type_string, json_object_get_string);
	JSON_GET_FIELD(ip, err, json_client, "ip", json_type_string, json_object_get_string);
	JSON_GET_FIELD(id, err, json_client, "id", json_type_int, json_object_get_uint64);

	client = client_list_find(mac, ip);
	if (client) {
		debug(LOG_ERR, "Found a duplicate client containing same ip & mac (%s / %s) !", ip, mac);
		return -1;
	}

	client = client_list_find_by_id(id);
	if (client) {
		debug(LOG_ERR, "Found a duplicate client containing same id (%d)!", id);
		return -1;
	}

	client = client_list_add_client(mac, ip);
	if (!client) {
		debug(LOG_ERR, "Failed to add client with mac %s, ip %s. Maybe invalid mac or ip?", mac, ip);
		return -1;
	}

	const char *token = NULL;
	JSON_GET_FIELD(token, err, json_client, "token", json_type_string, json_object_get_string);
	if (client->token)
		free(client->token);

	client->token = safe_strdup(token);
	client->id = id;

	JSON_GET_FIELD(client->session_start, err, json_client, "session_start", json_type_int, json_object_get_uint64);
	JSON_GET_FIELD(client->session_end, err, json_client, "session_end", json_type_int, json_object_get_uint64);
	JSON_GET_FIELD(client->download_limit, err, json_client, "download_limit", json_type_int, json_object_get_int);
	JSON_GET_FIELD(client->upload_limit, err, json_client, "upload_limit", json_type_int, json_object_get_int);

	json_object *counters = NULL;
	JSON_GET_FIELD_OBJECT(counters, err, json_client, "counters", json_type_object);
	JSON_GET_FIELD(client->counters.incoming, err, counters, "incoming", json_type_int, json_object_get_uint64);
	JSON_GET_FIELD(client->counters.outgoing, err, counters, "outgoing", json_type_int, json_object_get_uint64);
	JSON_GET_FIELD(client->counters.last_updated, err, counters, "last_updated", json_type_int, json_object_get_uint64);

	unsigned int fw_connection_state = -1;
	JSON_GET_FIELD(fw_connection_state, err, json_client, "fw_connection_state", json_type_int, json_object_get_int64);

	auth_change_state(client, fw_connection_state, "import_state_file");

	return 0;
err:
	if (client)
		client_list_delete(client);
	return -1;
}

/*! Import the client list from path. The function expects the client list to be empty.
 *
 * \param path Path to the state file
 * \return 0 on success, 1 if file doesn't exist, 2 file couldn't access for other reasons. <= 0 if an error while parsing happened.
 */
int
state_file_import(const char *path)
{
	int rc;
	struct stat statbuf = {};
	rc = stat(path, &statbuf);
	if (rc) {
		if (errno == ENOENT) {
			debug(LOG_DEBUG, "State file doesn't exist. Can't load old state.");
			return 1;
		} else {
			debug(LOG_DEBUG, "State file couldn't accessed. errno %d - %s.", errno, strerror(errno));
			return 2;
		}
	}

	rc = -EINVAL;

	json_object *top = json_object_from_file(path);
	if (!top) {
		debug(LOG_ERR, "Failed to parse state file %s", json_util_get_last_err());
		return -1;
	}

	int64_t version = -1;
	JSON_GET_FIELD(version, err, top, "version", json_type_int, json_object_get_int64);
	if (version != NDS_JSON_EXPORT_VERSION) {
		debug(LOG_ERR, "Invalid version of state file");
		goto err;
	}

	const char *name = NULL;
	JSON_GET_FIELD(name, err, top, "name", json_type_string, json_object_get_string);
	if (strcmp(name, "nodogsplash")) {
		debug(LOG_ERR, "Invalid name in state file. Expected %s, but found %s",
		      "nodogsplash", name);
		goto err;
	}

	json_object *clients = NULL;
	JSON_GET_FIELD_OBJECT(clients, err, top, "clients", json_type_array);

	LOCK_CLIENT_LIST();
	int len = json_object_array_length(clients);
	for (int i = 0; i < len; i++) {
		json_object *client = json_object_array_get_idx(clients, i);
		if (!json_object_is_type(client, json_type_object)) {
			debug(LOG_ERR, "clients: Invalid type of array entry %d in state file. Expected %s, but found %s",
			      i,
			      json_type_to_name(json_type_object),
			      json_type_to_name(json_object_get_type(client)));
			UNLOCK_CLIENT_LIST();
			goto err;
		}

		rc = state_file_import_client(client);
		if (rc) {
			debug(LOG_ERR, "clients: Ignoring invalid client entry %s", json_object_to_json_string(client));
		}
	}
	UNLOCK_CLIENT_LIST();

	json_object_put(top);
	return 0;

err:
	json_object_put(top);
	return rc;
}
