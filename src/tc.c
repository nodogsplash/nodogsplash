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
#include "auth.h"
#include "fw_iptables.h"
#include "firewall.h"
#include "debug.h"
#include "util.h"
#include "client_list.h"
#include "tc.h"


/**
 * Make nonzero to supress the error output during destruction.
 */ 
static int tc_quiet = 0;


/** @internal */
static int
tc_do_command(char *format, ...) {
  va_list vlist;
  char *fmt_cmd,
    *cmd;
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


/* Use HTB as a upload qdisc.
 * dev is name of device to attach qdisc to (typically an IMQ)
 * upload_limit is in kbits/s
 * Some ideas here from Rudy's qos-scripts 
 * http://forum.openwrt.org/viewtopic.php?id=4112&p=1
 */
int
tc_attach_upload_qdisc(char *dev, int upload_limit) {
  int burst;
  int mtu = MTU + 40;
  int rc = 0;

  burst = upload_limit * 1000 / 8 / HZ; /* burst (buffer size) in bytes */
  burst = burst < mtu ? mtu : burst; /* but burst should be at least mtu */

  rc |= tc_do_command("qdisc add dev %s root handle 1: htb default 1", dev);
  rc |= tc_do_command("class add dev %s parent 1: classid 1:1 htb rate %dkbit ceil %dkbit burst %d cburst %d mtu %d prio 1",
		      dev, upload_limit, upload_limit, burst*2, burst, mtu);

  
  return rc;

}

/* Use HTB as a download qdisc.
 * dev is name of device to attach qdisc to (typically an IMQ)
 * download_limit is in kbits/s
 * Some ideas here from Rudy's qos-scripts 
 * http://forum.openwrt.org/viewtopic.php?id=4112&p=1
 */
int
tc_attach_download_qdisc(char *dev, int download_limit) {
  int burst;
  int mtu = MTU + 40;
  int rc = 0;

  burst = download_limit * 1000 / 8 / HZ; /* burst (buffer size) in bytes */
  burst = burst < mtu ? mtu : burst; /* but burst should be at least mtu */
  

  rc |= tc_do_command("qdisc add dev %s root handle 1: htb default 1", dev);
  rc |= tc_do_command("class add dev %s parent 1: classid 1:1 htb rate %dkbit ceil %dkbit burst %d cburst %d mtu %d prio 1",
		      dev, download_limit, download_limit, burst*2, burst, mtu);
  return rc;

}


/** Remove qdiscs from interfaces, and bring interfaces down
 *  as appropriate.
 */
int
tc_destroy_tc() {
  int rc = 0;
  tc_quiet = 1;
  s_config *config;
  char *download_imqname, *upload_imqname, *cmd;

  config = config_get_config();
  safe_asprintf(&download_imqname,"imq%d",config->download_imq); /* must free */
  safe_asprintf(&upload_imqname,"imq%d",config->upload_imq);  /* must free */


  /* remove qdiscs from imq's */
  rc |= tc_do_command("qdisc del dev %s root",download_imqname);
  rc |= tc_do_command("qdisc del dev %s root",upload_imqname);
  /* bring down imq's */
  safe_asprintf(&cmd,"ip link set %s down", download_imqname);
  rc |= execute(cmd,tc_quiet);
  free(cmd);
  safe_asprintf(&cmd,"ip link set %s down", upload_imqname);
  rc |= execute(cmd,tc_quiet);
  free(cmd);

  free(upload_imqname);
  free(download_imqname);

  tc_quiet = 0;

  return rc;
  
}
