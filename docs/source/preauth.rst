PreAuth Option
=================

Overview
********

PreAuth is a means to provide a Forwarding Authentication Service (FAS) for Nodogsplash (NDS) utilising NDS's built in web server.

This means a FAS can be implemented without the resource utilisation of a separate web server, particularly useful for legacy devices with limited flash and RAM capacity.

To use PreAuth, NDS FAS configuration is set to point to a virtual URL in the NDS web root instead of an external FAS server. In addition, NDS is configured with the location of the PreAuth script or program.

The PreAuth script can be a shell script or any other script type that an interpreter is available for (for example, PHP-cli, Python etc.).

It could also be, for example, a compiled program written in C or any other language that has a compiler available for the platform.


Using PreAuth
*************
PreAuth is set up using the standard NDS configuration for FAS
(See the **Forwarding Authentication Service (FAS)** section of this documentation).

In addition a single PreAuth configuration option is required to inform NDS of the location of the PreAuth script or program.

In summary, the following configuration options should be set:
 1. **fasport**. This enables FAS and *must* be set to the same value as the gateway port.
 2. **faspath**. This *must* be set to the PreAuth virtual url, "/nodogsplash_preauth/" by default.

The remaining FAS configuration options must be left unset at the default values.

ie:
 1. **fasremoteip**. Not set (defaults to the gateway ip address).
 2. **fas_secure_enable**. Not set (defaults to enabled).

**Finally** the Preauth configuration must be set.
In OpenWrt this will be of the form
option preauth /etc/nodogsplash/demo-preauth.sh
For other Linux distributions this is set in the nodogsplash.conf file.

Using The Example PreAuth Script
********************************

An example PreAuth script is provided along with the FAS examples and should be copied to a convenient location on your router eg "/etc/nodogsplash/", remembering to flag as executable.


