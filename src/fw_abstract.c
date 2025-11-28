#include "fw_abstract.h"

fw_ops fw_gops;

void fw_use_iptables() {
	fw_gops.init = iptables_fw_init;
	fw_gops.destroy = iptables_fw_destroy;
	fw_gops.allow_mac = iptables_allow_mac;
	fw_gops.block_mac = iptables_block_mac;
	fw_gops.trust_mac = iptables_trust_mac;
	fw_gops.do_command = iptables_do_command;
	fw_gops.untrust_mac = iptables_untrust_mac;
	fw_gops.unallow_mac = iptables_unallow_mac;
	fw_gops.unblock_mac = iptables_unblock_mac;
	fw_gops.authenticate = iptables_fw_authenticate;
	fw_gops.total_upload = iptables_fw_total_upload;
	fw_gops.deauthenticate = iptables_fw_deauthenticate;
	fw_gops.total_download = iptables_fw_total_download;
	fw_gops.counters_update = iptables_fw_counters_update;
}

void fw_use_nftables() {
	fw_gops.init = nftables_fw_init;
	fw_gops.destroy = nftables_fw_destroy;
	fw_gops.allow_mac = nftables_allow_mac;
	fw_gops.block_mac = nftables_block_mac;
	fw_gops.trust_mac = nftables_trust_mac;
	fw_gops.do_command = nftables_do_command;
	fw_gops.untrust_mac = nftables_untrust_mac;
	fw_gops.unallow_mac = nftables_unallow_mac;
	fw_gops.unblock_mac = nftables_unblock_mac;
	fw_gops.authenticate = nftables_fw_authenticate;
	fw_gops.total_upload = nftables_fw_total_upload;
	fw_gops.deauthenticate = nftables_fw_deauthenticate;
	fw_gops.total_download = nftables_fw_total_download;
	fw_gops.counters_update = nftables_fw_counters_update;
	nftables_initialize_nft_context();
}

