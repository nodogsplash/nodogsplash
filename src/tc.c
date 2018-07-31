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


int
tc_attach_client(const char down_dev[], int download_limit, const char up_dev[], int upload_limit, int idx, int fw_mark)
{
	int burst;
	int mtu = MTU + 40;
	int rc = 0;

	burst = download_limit * 1000 / 8 / HZ; /* burst (buffer size) in bytes */
	burst = burst < mtu ? mtu : burst; /* but burst should be at least mtu */

	rc |= execute("tc class add dev %s parent 1:1 classid 1:%i htb rate %dkbit ceil %dkbit burst %d cburst %d mtu %d prio 1",
						down_dev, idx + 10, download_limit, download_limit, burst*10, burst, mtu);
	rc |= execute("tc filter add dev %s protocol ip parent 1: handle 0x%x%x fw flowid 1:%i",
						down_dev, idx + 10, fw_mark, idx + 10);

	burst = upload_limit * 1000 / 8 / HZ; /* burst (buffer size) in bytes */
	burst = burst < mtu ? mtu : burst; /* but burst should be at least mtu */

	rc |= execute("tc class add dev %s parent 1:1 classid 1:%i htb rate %dkbit ceil %dkbit burst %d cburst %d mtu %d prio 1",
						up_dev, idx + 10, upload_limit, upload_limit, burst*10, burst, mtu);
	rc |= execute("tc filter add dev %s protocol ip parent 1: handle 0x%x%x fw flowid 1:%i",
						up_dev, idx + 10, fw_mark, idx + 10);
	return rc;

}

int
tc_detach_client(const char down_dev[], const char up_dev[], int idx)
{
	int rc = 0;

	rc |= execute("tc class del dev %s parent 1: classid 1:%i", down_dev, idx + 10);
	rc |= execute("tc class del dev %s parent 1: classid 1:%i", up_dev, idx + 10);

	return rc;
}

/* Use HTB as a upload qdisc.
 * dev is name of device to attach qdisc to (typically an IMQ)
 * upload_limit is in kbits/s
 * Some ideas here from Rudy's qos-scripts
 * http://forum.openwrt.org/viewtopic.php?id=4112&p=1
 */
static int
tc_attach_upload_qdisc(const char dev[], int upload_limit)
{
	int rc = 0;
	int burst;
	int mtu = MTU + 40;

	burst = upload_limit * 1000 / 8 / HZ; /* burst (buffer size) in bytes */
	burst = burst < mtu ? mtu : burst; /* but burst should be at least mtu */

	rc |= execute("tc qdisc add dev %s root handle 1: htb default 2 r2q %d", dev, 1700);
	rc |= execute("tc class add dev %s parent 1: classid 1:1 htb rate 100Mbps ceil 100Mbps burst %d cburst %d mtu %d",
		dev, burst*10, burst, mtu);
	rc |= execute("tc class add dev %s parent 1:1 classid 1:2 htb rate %dkbit ceil %dkbit burst %d cburst %d mtu %d prio 1",
		dev, upload_limit, upload_limit, burst*10, burst, mtu);

	return rc;
}

/* Use HTB as a download qdisc.
 * dev is name of device to attach qdisc to (typically an IMQ)
 * download_limit is in kbits/s
 * Some ideas here from Rudy's qos-scripts
 * http://forum.openwrt.org/viewtopic.php?id=4112&p=1
 */
static int
tc_attach_download_qdisc(const char dev[], int download_limit)
{
	int rc = 0;
	int burst;
	int mtu = MTU + 40;

	burst = download_limit * 1000 / 8 / HZ; /* burst (buffer size) in bytes */
	burst = burst < mtu ? mtu : burst; /* but burst should be at least mtu */

	rc |= execute("tc qdisc add dev %s root handle 1: htb default 2 r2q %d", dev, 1700);
	rc |= execute("tc class add dev %s parent 1: classid 1:1 htb rate 100Mbps ceil 100Mbps burst %d cburst %d mtu %d",
		dev, burst*10, burst, mtu);
	rc |= execute("tc class add dev %s parent 1:1 classid 1:2 htb rate %dkbit ceil %dkbit burst %d cburst %d mtu %d prio 1",
		dev, download_limit, download_limit, burst*10, burst, mtu);

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
	int upload_imq, download_imq;
	char *download_imqname = NULL;
	char *upload_imqname = NULL;
	s_config *config;
	int rc = 0;
	int ret = 0;

	config = config_get_config();
	download_limit = config->download_limit;
	upload_limit = config->upload_limit;
	download_imq = config->download_imq;
	upload_imq = config->upload_imq;

	safe_asprintf(&download_imqname,"imq%d", download_imq); /* must free */
	safe_asprintf(&upload_imqname,"imq%d", upload_imq);  /* must free */

	if (download_limit > 0) {
		ret = execute("ip link set %s up", download_imqname);
		if (ret != 0) {
			debug(LOG_ERR, "Could not set %s up. Download limiting will not work", download_imqname);
		} else {
			/* jump to the imq in mangle CHAIN_INCOMING */
			rc |= iptables_do_command("-t mangle -A " CHAIN_INCOMING " -j IMQ --todev %d ", download_imq);
			/* attach download shaping qdisc to this imq */
			rc |= tc_attach_download_qdisc(download_imqname, download_limit);
		}
	}

	if (upload_limit > 0) {
		ret = execute("ip link set %s up", upload_imqname);
		if (ret != 0) {
			debug(LOG_ERR, "Could not set %s up. Upload limiting will not work", upload_imqname);
			rc = -1;
		} else {
			/* jump to the imq in mangle CHAIN_OUTGOING */
			rc |= iptables_do_command("-t mangle -A " CHAIN_OUTGOING " -j IMQ --todev %d ", upload_imq);
			/* attach upload shaping qdisc to this imq */
			rc |= tc_attach_upload_qdisc(upload_imqname, upload_limit);
		}
	}

	free(download_imqname);
	free(upload_imqname);

	return rc;
}


/**
 * Remove qdiscs from intermediate queueing devices, and bring IMQ's down
 */
int
tc_destroy_tc()
{
	s_config *config;
	int rc = 0;

	config = config_get_config();

	/* remove qdiscs from imq's */
	rc |= execute("tc qdisc del dev imq%d root &> /dev/null", config->download_imq);
	rc |= execute("tc qdisc del dev imq%d root &> /dev/null", config->upload_imq);

	/* bring down imq's */
	rc |= execute("ip link set imq%d down &> /dev/null", config->download_imq);
	rc |= execute("ip link set imq%d down &> /dev/null", config->upload_imq);

	return rc;
}
