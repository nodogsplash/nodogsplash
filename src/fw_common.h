#ifndef _NDS_FW_COMMON_H_
#define _NDS_FW_COMMON_H_

/** Used to mark packets, and characterize client state.  Unmarked packets are considered 'preauthenticated' */
extern unsigned int FW_MARK_PREAUTHENTICATED; /**< @brief 0: Actually not used as a packet mark */
extern unsigned int FW_MARK_AUTHENTICATED;    /**< @brief The client is authenticated */
extern unsigned int FW_MARK_BLOCKED;          /**< @brief The client is blocked */
extern unsigned int FW_MARK_TRUSTED;          /**< @brief The client is trusted */
extern unsigned int FW_MARK_MASK;             /**< @brief Iptables mask: bitwise or of the others */

/*@{*/
/**Iptable chain names used by nodogsplash */
#define CHAIN_TO_INTERNET "ndsNET"
#define CHAIN_TO_ROUTER "ndsRTR"
#define CHAIN_TRUSTED_TO_ROUTER "ndsTRT"
#define CHAIN_OUTGOING  "ndsOUT"
#define CHAIN_INCOMING  "ndsINC"
#define CHAIN_AUTHENTICATED     "ndsAUT"
#define CHAIN_PREAUTHENTICATED   "ndsPRE"
#define CHAIN_BLOCKED    "ndsBLK"
#define CHAIN_ALLOWED    "ndsALW"
#define CHAIN_TRUSTED    "ndsTRU"

#define CHAIN_MARK "ndsMARK"
#define CHAIN_FILTER_NAT_OUTGOING "f_ndsOUT_NAT"
#define CHAIN_NAT_OUTGOING "ndsOUT_NAT"

/** @brief Return a string representing a connection state */
const char *fw_common_connection_state_as_string(int mark);


int fw_common_init_marks(void);

#endif /* _NDS_FW_COMMON_H_ */