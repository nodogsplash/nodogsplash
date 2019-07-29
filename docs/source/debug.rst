Debugging NoDogSplash
#####################

Syslog Logging
**************

NoDogSplash supports four levels of debugging to syslog.

  * debuglevel 0 : Silent (only LOG_ERR and LOG_EMERG messages will be seen, otherwise there will be no logging.)
  * debuglevel 1 : LOG_ERR, LOG_EMERG, LOG_WARNING and LOG_NOTICE (this is the default level).
  * debuglevel 2 : debuglevel 1 + LOG_INFO
  * debuglevel 3 : debuglevel 2 + LOG_DEBUG

  All other levels are undefined and will result in debug level 3 being set.

 To see maximally verbose debugging output from NoDogSplash, set log level to 3. This can be done in the UCI configuration file on OpenWrt adding the line:

  ``option debuglevel '3'``

 Restart or reboot. Debug messages are logged to syslog. You can view messages with the logread command. 

 The default level of logging is 1, and is more appropriate for routine use.

 Logging level can also be set using ndsctl.

Firewall Cleanup
****************

 When stopped, NoDogSplash deletes its iptables rules, attempting to leave the router's firewall in its original state. If not (for example, if NoDogSplash crashes instead of exiting cleanly) subsequently starting and stopping NoDogSplash should remove its rules.

 On OpenWrt, restarting the firewall will overwrite NoDogSplash's iptables rules, so when the firewall is restarted it will automatically restart NoDogSplash if it is running.

Packet Marking
**************

 NoDogSplash operates by marking packets. Many packages, such as mwan3 and SQM scripts, also mark packets.

 By default, NoDogSplash marks its packets in such a way that conflicts are unlikely to occur but the masks used by NoDogSplash can be changed if necessary in the configuration file.

IPtables Conflicts
******************

 Potential conflicts may be investigated by looking at your overall iptables setup. To list all the rules in all the chains, run

    ``iptables -L``

 For extensive suggestions on debugging iptables, see for example, Oskar Andreasson's tutorial at:

 https://www.frozentux.net/iptables-tutorial/iptables-tutorial.html

