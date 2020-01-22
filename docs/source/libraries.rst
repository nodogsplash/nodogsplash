Library Utilities
=================

Overview
********

A number of library utilities are included. These may be used by NDS itself, FAS, Preauth and BinAuth. These may in the future, be enhanced, have additional functionality added.

By default, library utilities will be installed in the folder

``/usr/lib/nodogsplash/``

List of Library Utilities
*************************

get_client_token.sh
###################
This utility allows the unique token of a client to be determined from the client ip address.

It can be used in BinAuth, PreAuth and local FAS scripts.

  Usage: get_client_token.sh [clientip]

  Returns: [client token]

  Where:
    [client token] is the unique client token string.

get_client_interface.sh
#######################
This utility allows the interface a client is using to be determined from the client mac address.

It is used by NDS when fas secure level 2 is set. Its output is sent to FAS in the encrypted query string as the variable "clientif"

  Usage: get_client_interface.sh [clientmac]

  Returns: [local_interface] [meshnode_mac] [local_mesh_interface]

  Where:

    [local_interface] is the local interface the client is using.

    [meshnode_mac] is the mac address of the 802.11s meshnode the client is using (null if mesh not present).

    [local_mesh_interface] is the local 802.11s interface the client is using (null if mesh not present).

unescape.sh
###########
This utility allows an input string to be unescaped. It currently only supports url-decoding.

It is used by NDS as the unescape callback for libmicrohttpd.

  Usage: unescape.sh [-option] [escapedstring]

  Returns: [unescapedstring]

  Where:
  
    [-option] is unescape type, currently -url only
