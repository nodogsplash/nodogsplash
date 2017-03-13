DnsSpoofing Option
====================

**Required:**

Key: DnsSpoofing

Value: 1 / 0

**Optional:**

Key: DnsSpoofingPort

Default Value: 5353

This is a more complex solution providing offline mode
support and dns tunneling protection. You need a
dnsmasq server or any other dns server providing similar features.
This is an example configuration how to use this feature
in conjunction with LEDE/OpenWRT. The first dns server listens
on port 53 on all interfaces and serves internet for authenticated
clients and the OS. The second dns server offers a service for
non-authenticated client which will be directly redirected to
the splashpage address.

**Example DNSMASQ Configuration:**

.. code-block:: bash

  config dnsmasq 'guest'
          option port 5353  # <- Port must match with DnsSpoofing feature in nodogsplash
          option domainneeded '1'
          option boguspriv '1'
          option filterwin2k '0'
          option nonwildcard '1'
          option localise_queries '1'
          option rebind_protection '1'
          option rebind_localhost '1'
          option local '/wifi/'
          option domain 'wifi'
          option expandhosts '1'
          option nonegcache '0'
          option authoritative '1'
          option readethers '1'
          option leasefile '/tmp/dhcp.leases.guest'
          option resolvfile '/tmp/resolv.conf.guest'
          option localservice '1'
          list interface 'wifi'
          list notinterface 'loopback'
          list address '/#/192.168.1.2' # <- Change that to your splashpage address

  config dnsmasq 'main'
          option domainneeded '1'
          option boguspriv '1'
          option filterwin2k '0'
          option nonwildcard '1'
          option localise_queries '1'
          option rebind_protection '1'
          option rebind_localhost '1'
          option local '/lan/'
          option domain 'lan'
          option expandhosts '1'
          option nonegcache '0'
          option authoritative '1'
          option readethers '1'
          option leasefile '/tmp/dhcp.leases.main'
          option resolvfile '/tmp/resolv.conf.main'
          option localservice '1'
          list server '8.8.8.8'
          list server '8.8.4.4'
          list interface 'lxc'
          list interface 'wifi'  # <- You must listen on both interfaces so that after the nodogsplash authentication the internet can be reached

  config dhcp 'wifi'
          option instance 'guest'
          option interface 'wifi'
          option start '2'
          option limit '253'
          option leasetime '2h'
          list 'dhcp_option' '6,192.168.2.1'

  config dhcp 'lxc'
          option instance 'main'
          option interface 'lxc'
          option start '2'
          option limit '253'
          option leasetime '2h'
          list 'dhcp_option' '6,192.168.1.1'

**Example NODOGSPLASH Configuration:**

.. code-block:: bash

  GatewayName Example
  GatewayInterface wlan0
  GatewayAddress 192.168.2.1
  GatewayPort 1250
  SplashAddress 192.168.1.2
  MaxClients 100
  BinVoucher /etc/nodogsplash/get_access.sh
  CheckInterval 3
  DnsSpoofing 1

  FirewallRuleSet users-to-router {
    FirewallRule allow icmp
    FirewallRule allow udp port 67
    FirewallRule allow tcp port 5353 to 192.168.2.1 # <- Only second dns server is allowed
    FirewallRule allow udp port 5353 to 192.168.2.1
  }

  FirewallRuleSet preauthenticated-users {
    FirewallRule allow tcp port 5353 to 192.168.2.1
    FirewallRule allow udp port 5353 to 192.168.2.1 # <- Only second dns server is allowed
    FirewallRule allow tcp port 1250 to 192.168.2.1
    FirewallRule allow tcp port 80 to 192.168.1.2
  }

  FirewallRuleSet authenticated-users {
    FirewallRule allow tcp port 53
    FirewallRule allow udp port 53 # <- First dns server is now allowd and firewall rule is purged
    FirewallRule allow tcp port 80
    FirewallRule allow tcp port 443
    FirewallRule allow icmp
  }
