#include "fw_abstract.h"

fw_ops fw_gops;

void fw_use_iptables() {
	fw_gops.init = iptables_fw_init;
	fw_gops.destroy = iptables_fw_destroy;
	fw_gops.allow_mac = iptables_allow_mac;
	fw_gops.block_mac = iptables_block_mac;
	fw_gops.trust_mac = iptables_trust_mac;
	fw_gops.do_command = iptables_do_command;
	fw_gops.connection_state_as_string = iptables_fw_connection_state_as_string;
	fw_gops.untrust_mac = iptables_untrust_mac;
	fw_gops.unallow_mac = iptables_unallow_mac;
	fw_gops.unblock_mac = iptables_unblock_mac;
	fw_gops.authenticate = iptables_fw_authenticate;
	fw_gops.total_upload = iptables_fw_total_upload;
	fw_gops.deauthenticate = iptables_fw_deauthenticate;
	fw_gops.total_download = iptables_fw_total_download;
	fw_gops.counters_update = iptables_fw_counters_update;
}

