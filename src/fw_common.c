#include "debug.h"
#include "fw_common.h"

/** Used to mark packets, and characterize client state.  Unmarked packets are considered 'preauthenticated' */
unsigned int FW_MARK_PREAUTHENTICATED; /**< @brief 0: Actually not used as a packet mark */
unsigned int FW_MARK_AUTHENTICATED;    /**< @brief The client is authenticated */
unsigned int FW_MARK_BLOCKED;          /**< @brief The client is blocked */
unsigned int FW_MARK_TRUSTED;          /**< @brief The client is trusted */
unsigned int FW_MARK_MASK;             /**< @brief Iptables mask: bitwise or of the others */

/** Return a string representing a connection state */
const char *
fw_common_connection_state_as_string(int mark)
{
	if (mark == FW_MARK_PREAUTHENTICATED)
		return "Preauthenticated";
	if (mark == FW_MARK_AUTHENTICATED)
		return "Authenticated";
	if (mark == FW_MARK_TRUSTED)
		return "Trusted";
	if (mark == FW_MARK_BLOCKED)
		return "Blocked";
	return "ERROR: unrecognized mark";
}

int
fw_common_init_marks()
{
	/* Check FW_MARK values are distinct.  */
	if (FW_MARK_BLOCKED == FW_MARK_TRUSTED ||
			FW_MARK_TRUSTED == FW_MARK_AUTHENTICATED ||
			FW_MARK_AUTHENTICATED == FW_MARK_BLOCKED) {
		debug(LOG_ERR, "FW_MARK_BLOCKED, FW_MARK_TRUSTED, FW_MARK_AUTHENTICATED not distinct values.");
		return -1;
	}

	/* Check FW_MARK values nonzero.  */
	if (FW_MARK_BLOCKED == 0 ||
			FW_MARK_TRUSTED == 0 ||
			FW_MARK_AUTHENTICATED == 0) {
		debug(LOG_ERR, "FW_MARK_BLOCKED, FW_MARK_TRUSTED, FW_MARK_AUTHENTICATED not all nonzero.");
		return -1;
	}

	FW_MARK_PREAUTHENTICATED = 0;  /* always 0 */
	/* FW_MARK_MASK is bitwise OR of other marks */
	FW_MARK_MASK = FW_MARK_BLOCKED | FW_MARK_TRUSTED | FW_MARK_AUTHENTICATED;

	debug(LOG_INFO,"Firewall mark %s: 0x%x",
		fw_common_connection_state_as_string(FW_MARK_PREAUTHENTICATED),
		FW_MARK_PREAUTHENTICATED);
	debug(LOG_INFO,"Firewall mark %s: 0x%x",
		fw_common_connection_state_as_string(FW_MARK_AUTHENTICATED),
		FW_MARK_AUTHENTICATED);
	debug(LOG_INFO,"Firewall mark %s: 0x%x",
		fw_common_connection_state_as_string(FW_MARK_TRUSTED),
		FW_MARK_TRUSTED);
	debug(LOG_INFO,"Firewall mark %s: 0x%x",
		fw_common_connection_state_as_string(FW_MARK_BLOCKED),
		FW_MARK_BLOCKED);

	return 0;
}

