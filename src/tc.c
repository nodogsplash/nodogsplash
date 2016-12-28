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
 * You should have received a copy of the GNU General Public License*
 * along with this program; if not, contact:                        *
 *                                                                  *
 * Free Software Foundation           Voice:  +1-617-542-5942       *
 * 59 Temple Place - Suite 330        Fax:    +1-617-542-2652       *
 * Boston, MA  02111-1307,  USA       gnu@gnu.org                   *
 *                                                                  *
 \********************************************************************/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "common.h"

#include "safe.h"
#include "conf.h"
#include "client_list.h"
#include "auth.h"
#include "fw_iptables.h"
#include "firewall.h"
#include "debug.h"
#include "util.h"

#include "tc.h"


/**
 * Make this nonzero to supress the error output during destruction.
 */
static int tc_quiet = 0;


/** @internal */
static int
tc_do_command(char *format, ...)
{
	va_list vlist;
	char *fmt_cmd;
	char *cmd;
	int rc;

	va_start(vlist, format);
	safe_vasprintf(&fmt_cmd, format, vlist);
	va_end(vlist);

	safe_asprintf(&cmd, "tc %s", fmt_cmd);

	free(fmt_cmd);

	debug(LOG_DEBUG, "Executing command: %s", cmd);

	rc = execute(cmd, tc_quiet);

	free(cmd);

	return rc;
}

int
tc_attach_client(char *down_dev, int download_limit, char *up_dev, int upload_limit, int idx, char *ip)
{
	int rc = 0;
	s_config *config = config_get_config();
	int dlimit = (download_limit < config->download_limit ? download_limit : config->download_limit);
	int ulimit = (upload_limit < config->upload_limit ? upload_limit : config->upload_limit);
	int id = 3 * idx + 10;

	if (dlimit > 0) {
		/* guarantee 20% bandwidth, upper limit 100% */
		rc |= tc_do_command("class add dev %s parent 1:1 classid 1:%d hfsc sc rate %dkbit ul rate %dkbit",
						down_dev, id, dlimit / 5, dlimit);
		/* low latency class for DNS and ICMP */
		rc |= tc_do_command("class add dev %s parent 1:%d classid 1:%d hfsc rt m1 %dkbit d 25ms m2 %dkbit ls m1 %dkbit d 25ms m2 %dkbit ul rate %dkbit",
						down_dev, id, id + 1, (dlimit / 5) * 4, dlimit / 20, dlimit / 10, dlimit / 10, dlimit);
		rc |= tc_do_command("filter add dev %s protocol ip parent 1: prio %d u32 match ip dst %s match ip protocol %d 0xff flowid 1:%d",
						down_dev, id, ip, 1, id + 1);
		rc |= tc_do_command("filter add dev %s protocol ip parent 1: prio %d u32 match ip dst %s match ip sport %d 0xffff flowid 1:%d",
						down_dev, id + 1, ip, 53, id + 1);
		/* bulk traffic class */
		rc |= tc_do_command("class add dev %s parent 1:%d classid 1:%d hfsc ls m1 0kbit d 100ms m2 %dkbit ul rate %dkbit",
						down_dev, id, id + 2, dlimit / 5, dlimit / 10);
		rc |= tc_do_command("filter add dev %s protocol ip parent 1: prio %d u32 match ip dst %s flowid 1:%d",
						down_dev, id + 2, ip, id + 2);
		/* codel for each leaf class */
		rc |= tc_do_command("qdisc add dev %s parent 1:%d handle %d: fq_codel limit 800 quantum 300 ecn",
						down_dev, id + 1, id + 1);
		rc |= tc_do_command("qdisc add dev %s parent 1:%d handle %d: fq_codel limit 800 quantum 300 ecn",
						down_dev, id + 2, id + 2);
	}
	if (ulimit > 0) {
		/* guarantee 20% bandwidth, upper limit 100% */
		rc |= tc_do_command("class add dev %s parent 1:1 classid 1:%d hfsc sc rate %dkbit ul rate %dkbit",
						up_dev, id, ulimit / 5, ulimit);
		/* low latency class for DNS and ICMP */
		rc |= tc_do_command("class add dev %s parent 1:%d classid 1:%d hfsc rt m1 %dkbit d 25ms m2 %dkbit ls m1 %dkbit d 25ms m2 %dkbit ul rate %dkbit",
						up_dev, id, id + 1, (ulimit / 5) * 4, ulimit / 20, ulimit / 10, ulimit / 10, ulimit);
		rc |= tc_do_command("filter add dev %s protocol ip parent 1: prio %d u32 match ip src %s match ip protocol %d 0xff flowid 1:%d",
						up_dev, id, ip, 1, id + 1);
		rc |= tc_do_command("filter add dev %s protocol ip parent 1: prio %d u32 match ip src %s match ip dport %d 0xffff flowid 1:%d",
						up_dev, id + 1, ip, 53, id + 1);
		/* bulk traffic class */
		rc |= tc_do_command("class add dev %s parent 1:%d classid 1:%d hfsc ls m1 0kbit d 100ms m2 %dkbit ul rate %dkbit",
						up_dev, id, id + 2, ulimit / 5, ulimit / 10);
		rc |= tc_do_command("filter add dev %s protocol ip parent 1: prio %d u32 match ip src %s flowid 1:%d",
						up_dev, id + 2, ip, id + 2);
		/* codel for each leaf class */
		rc |= tc_do_command("qdisc add dev %s parent 1:%d handle %d: fq_codel limit 800 quantum 300 ecn",
						up_dev, id + 1, id + 1);
		rc |= tc_do_command("qdisc add dev %s parent 1:%d handle %d: fq_codel limit 800 quantum 300 ecn",
						up_dev, id + 2, id + 2);
	}

	return rc;
}

int
tc_detach_client(char *down_dev, int download_limit, char *up_dev, int upload_limit, int idx)
{
	int rc = 0, n;
	int id = 3 * idx + 10;

	if (download_limit > 0) {
		for (n=2;n>=0;n--)
			rc |= tc_do_command("filter del dev %s parent 1: prio %d", down_dev, id + n);
		for (n=2;n>=1;n--)
			rc |= tc_do_command("qdisc del dev %s parent 1:%d", down_dev, id + n);
		for (n=2;n>=0;n--)
			rc |= tc_do_command("class del dev %s parent 1: classid 1:%d", down_dev, id + n);
	}
	if (upload_limit > 0) {
		for (n=2;n>=0;n--)
			rc |= tc_do_command("filter del dev %s parent 1: prio %d", up_dev, id + n);
		for (n=2;n>=1;n--)
			rc |= tc_do_command("qdisc del dev %s parent 1:%d", up_dev, id + n);
		for (n=2;n>=0;n--)
			rc |= tc_do_command("class del dev %s parent 1: classid 1:%d", up_dev, id + n);
	}

	return rc;
}

/*
 * dev is name of device to attach qdisc to (typically an IFB)
 * upload_limit is in kbits/s
 * Some ideas here from Rudy's qos-scripts
 * http://forum.openwrt.org/viewtopic.php?id=4112&p=1
 */
static int
tc_attach_upload_qdisc(char *dev, char *ifb_dev, int upload_limit)
{
	int rc = 0;

	/* clear rules just in case */
	tc_do_command("qdisc del dev %s root", ifb_dev);
	tc_do_command("qdisc del dev %s ingress", dev);

	/* main upload qdisc */
	rc |= tc_do_command("qdisc add dev %s root handle 1: hfsc default 2", ifb_dev);
	rc |= tc_do_command("class add dev %s parent 1: classid 1:1 hfsc sc rate %dkbit ul rate %dkbit",
						ifb_dev, upload_limit, upload_limit);
	/* default class used for preauth clients */
	rc |= tc_do_command("class add dev %s parent 1:1 classid 1:2 hfsc sc rate %dkbit ul rate %dkbit",
						ifb_dev, upload_limit / 10, upload_limit / 10);
	/* redirect ingress from main interface to ifb interface */
	rc |= tc_do_command("qdisc add dev %s ingress", dev);
	rc |= tc_do_command("filter add dev %s parent ffff: protocol ip prio 1 u32 match u32 0 0 flowid 1:1 action connmark action mirred egress redirect dev %s",
						dev, ifb_dev);

	return rc;
}

/*
 * dev is name of device to attach qdisc to
 * download_limit is in kbits/s
 * Some ideas here from Rudy's qos-scripts
 * http://forum.openwrt.org/viewtopic.php?id=4112&p=1
 */
static int
tc_attach_download_qdisc(char *dev, char *ifb_dev, int download_limit)
{
	int rc = 0;

	/* clear rules just in case */
	tc_do_command("qdisc del dev %s root", dev);

	/* main download qdisc */
	rc |= tc_do_command("qdisc add dev %s root handle 1: hfsc default 2", dev);
	rc |= tc_do_command("class add dev %s parent 1: classid 1:1 hfsc sc rate %dkbit ul rate %dkbit",
						dev, download_limit, download_limit);
	/* default class used for preauth clients */
	rc |= tc_do_command("class add dev %s parent 1:1 classid 1:2 hfsc sc rate %dkbit ul rate %dkbit",
						dev, download_limit / 10, download_limit / 10);


	return rc;
}

/**
 * Bring up intermediate queueing devices, and attach qdiscs to them.
 * PRE: mangle table chains CHAIN_INCOMING, CHAIN_OUTGOING must exist;
 * see fw_iptables.c
 */
int
tc_init_tc()
{
	int upload_limit, download_limit;
	int upload_ifb, download_ifb;
	char *upload_ifbname, *cmd;
	s_config *config;
	int rc = 0, ret = 0;

	config = config_get_config();
	download_limit = config->download_limit;
	upload_limit = config->upload_limit;
	upload_ifb = config->upload_ifb;

	safe_asprintf(&upload_ifbname,"ifb%d",upload_ifb);  /* must free */

	tc_quiet = 0;

	if(download_limit > 0) {
		rc |= tc_attach_download_qdisc(config->gw_interface,NULL,download_limit);
	}
	if(upload_limit > 0) {
		safe_asprintf(&cmd,"ip link set %s up", upload_ifbname);
		ret = execute(cmd ,tc_quiet);
		free(cmd);
		if( ret != 0 ) {
			debug(LOG_ERR, "Could not set %s up. Upload limiting will not work",
				  upload_ifbname);
			rc = -1;
		} else {
			rc |= tc_attach_upload_qdisc(config->gw_interface,upload_ifbname,upload_limit);
		}
	}

	free(upload_ifbname);
}


/**
 * Remove qdiscs from intermediate queueing devices, and bring IFB's down
 */
int
tc_destroy_tc()
{
	int rc = 0, old_tc_quiet;

	old_tc_quiet = tc_quiet;
	tc_quiet = 1;
	s_config *config;
	char *upload_ifbname, *cmd;

	config = config_get_config();
	safe_asprintf(&upload_ifbname,"ifb%d",config->upload_ifb);  /* must free */

	/* remove qdiscs from ifb's */
	rc |= tc_do_command("qdisc del dev %s root",config->gw_interface);
	rc |= tc_do_command("qdisc del dev %s root",upload_ifbname);
	/* bring down ifb's */
	safe_asprintf(&cmd,"ip link set %s down", upload_ifbname);
	debug(LOG_DEBUG, "Executing command: %s", cmd);
	rc |= execute(cmd,tc_quiet);
	free(cmd);

	free(upload_ifbname);

	tc_quiet = old_tc_quiet;

	return rc;
}
