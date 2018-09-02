Debugging Nodogsplash
#####################


 To see maximally verbose debugging output from nodogsplash, set log level to 7. This can be done in the UCI configuration file on OpenWrt adding the line:

  ``option debuglevel '7'``

 or by editing the file

  ``/etc/init.d/nodogsplash``

 and setting the OPTIONS variable to the flags "-s -d 7".

 Restart or reboot, and view messages with logread. Debug messages are logged to syslog.

 The default level of logging is 5, LOG_NOTICE, and is more appropriate for routine use.

 Logging level can also be set using ndsctl.

 When stopped, nodogsplash deletes its iptables rules, attempting to leave the router's firewall in its original state. If not (for example, if nodogsplash crashes instead of exiting cleanly) subsequently starting and stopping nodogsplash should remove its rules.

 On OpenWrt, restarting the firewall will overwrite Nodogsplash's iptables rules, so when the firewall is restarted it will automatically restart Nodogsplash if it is running.

 Nodogsplash operates by marking packets. Many packages, such as mwan3 and SQM scripts, also mark packets.

 By default, Nodogsplash marks its packets in such a way that conficts are unlikely to occur but the masks used by Nodogsplash can be changed if necessary in the configuration file.

 Potential conflicts may be investigated by looking at your overall iptables setup. To list all the rules in all the chains, run

    ``iptables -L``

 For extensive suggestions on debugging iptables, see for example, Oskar Andreasson's tutorial at:

 https://www.frozentux.net/iptables-tutorial/iptables-tutorial.html

