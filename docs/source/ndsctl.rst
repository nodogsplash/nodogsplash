Using ndsctl
############

A nodogsplash install includes ndsctl, a separate application which provides some control over a running nodogsplash process by communicating with it over a unix socket. Some command line options:

* To print to stdout some information about your nodogsplash process:

    ``/usr/bin/ndsctl status``

* To print to stdout the list of clients in human readable format:

    ``/usr/bin/ndsctl clients``

* To print to stdout the list of clients and trusted devices in json format:

    ``/usr/bin/ndsctl json``

* To print to stdout the details of a particular client in json format (This is particularly useful if called from a FAS or Binauth script.):

    ``/usr/bin/ndsctl json [mac|ip|token]``

* To block a MAC address, when the MAC mechanism is block:

    ``/usr/bin/ndsctl block MAC``

* To unblock a MAC address, when the MAC mechanism is block:

    ``/usr/bin/ndsctl unblock MAC``

* To allow a MAC address, when the MAC mechanism is allow:

    ``/usr/bin/ndsctl allow MAC``

* To unallow a MAC address, when the MAC mechanism is allow:

    ``/usr/bin/ndsctl unallow MAC``

* To deauthenticate a currently authenticated user given their IP or MAC
  address:

    ``/usr/bin/ndsctl deauth IP|MAC``

* To set the verbosity of logged messages to n:

    ``/usr/bin/ndsctl debuglevel n``

  * debuglevel 0 : Silent (only LOG_ERR and LOG_EMERG messages will be seen, otherwise there will be no logging.)
  * debuglevel 1 : LOG_ERR, LOG_EMERG, LOG_WARNING and LOG_NOTICE (this is the default level).
  * debuglevel 2 : debuglevel 1 + LOG_INFO
  * debuglevel 3 : debuglevel 2 + LOG_DEBUG

  All other levels are undefined and will result in debug level 3 being set.


For more options, run ndsctl -h. (Note that if you want the effect of ndsctl commands to to persist across nodogsplash restarts, you have to edit the configuration file.)

