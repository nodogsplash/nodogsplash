Debugging nodogsplash
#####################


* To see maximally verbose debugging output from nodogsplash, edit the
  /etc/init.d/nodogsplash file to set the OPTIONS variable to the flags "-s -d 7",
  restart or reboot, and view messages with logread. The -s flag logs to
  syslog; the -d 7 flag sets level 7, LOG_DEBUG, for debugging messages
  (see syslog.h). You don't want to run with these flags routinely, as it will
  quickly fill the syslog circular buffer, unless you enable remote logging. A
  lower level of logging, for example level 5, LOG_NOTICE, is more appropriate
  for routine use (this is the default). Logging level can also be set using
  ndsctl as shown above.
  Alternatively, you can set the flag -f instead of -s, and restart.
  This will run nodogsplash in the foreground, logging to stdout.
* When stopped, nodogsplash deletes its iptables rules, attempting to leave the
  router's firewall in its original state. If not (for example, if nodogsplash
  crashes instead of exiting cleanly) subsequently starting and stopping
  nodogsplash should remove its rules.
* Nodogsplash operates by marking packets (and, if traffic control is enabled,
  passing packets through intermediate queueing devices). Most QOS packages
  will also mark packets and use IMQ's. Therefore one or both of Nodogsplash and
  a QOS package may malfunction if used together. Potential conflicts may be
  investigated by looking at your overall iptables setup. To check to see all
  the rules in, for example, the mangle table chains, run

    ``iptables -t mangle -v -n -L``

  For extensive suggestions on debugging iptables, see for example Oskar
  Andreasson's_tutorial.

