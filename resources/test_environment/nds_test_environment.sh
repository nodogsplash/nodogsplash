#!/usr/bin/env sh

# A script to set up a test environment for NoDogSplash.
#
# ---------------
# | nds-client1 |
# --------------- \
#                  \                 --------------
#                   [nds-bridge] --- | nds-natbox | --- Internet
#                  /                 --------------
# --------------- /
# | nds-client2 |
# ---------------

print_help() {
  echo "Setup a virtual environment to test Nodgosplash."
  echo
  echo "Usage: $0 [create|destroy|help]"
  echo
  echo "After creation, start Nodgosplash in the Linux network namespace called natbox:"
  echo "  sudo ip netns exec nds-natbox ./nodogsplash -d 3 -f -r ./resources/ -c ./resources/nodogsplash.conf"
  echo
  echo "Then start a browser (e.g. Firefox) in one of the two client namespaces:"
  echo "  sudo ip netns exec nds-client1 sudo -u \$USER firefox -P -no-remote --new-instance"
}

if [ "$1" = "create" ]; then
  if [ $(id -u) -ne 0 ]; then
    echo "You must be root to run this script."
    exit 1
  fi

  INTERNET_IFACE=$(ip r | awk '/default/{print($5);exit}')
  echo "INTERNET_IFACE: $INTERNET_IFACE"

  # Create a network namespace for each client.
  ip netns add "nds-natbox"
  ip netns add "nds-client1"
  ip netns add "nds-client2"

  # Bridge for client1, client2 and natbox.
  ip link add name "nds-bridge" type bridge
  ip link set dev "nds-bridge" up

  # Disable iptables processing for bridges so rules don't block traffic.
  # This is necessary only if the br_netfilter module is enabled.
  sysctl -w net.bridge.bridge-nf-call-iptables=0

  # Connect client1 to the bridge with a veth pair and assign IP address 192.168.99.1
  ip link add dev "vethclient1" type veth peer name "eth0" netns "nds-client1"
  ip link set "vethclient1" master "nds-bridge"
  ip link set "vethclient1" up
  ip -n "nds-client1" addr add dev "eth0" "192.168.99.1/24"
  ip -n "nds-client1" link set dev "eth0" up

  # Same for client2, with IP address 192.168.99.2
  ip link add dev "vethclient2" type veth peer name "eth0" netns "nds-client2"
  ip link set "vethclient2" master "nds-bridge"
  ip link set "vethclient2" up
  ip -n "nds-client2" addr add dev "eth0" "192.168.99.2/24"
  ip -n "nds-client2" link set dev "eth0" up

  # Connect natbox with the bridge
  ip link add dev "vethnatbox" type veth peer name "br-lan" netns "nds-natbox"
  ip link set "vethnatbox" master "nds-bridge"
  ip link set "vethnatbox" up
  ip -n "nds-natbox" addr add dev "br-lan" "192.168.99.3/24"
  ip -n "nds-natbox" link set dev "br-lan" up

  # Connect natbox with host system (for Internet access)
  ip link add dev "wan1" type veth peer name "wan0" netns "nds-natbox"
  ip -n "nds-natbox" addr add dev "wan0" "10.0.100.2/24"
  ip -n "nds-natbox" link set dev "wan0" up
  ip addr add dev "wan1" "10.0.100.1/24"
  ip link set dev "wan1" up

  ip netns exec "nds-client1" ip route add default via 192.168.99.3
  ip netns exec "nds-client2" ip route add default via 192.168.99.3
  ip netns exec "nds-natbox" ip route add default via 10.0.100.1

  # Allow client1 and client2 Internet acces through natbox
  ip netns exec "nds-natbox" sysctl -w "net.ipv4.ip_forward=1"
  ip netns exec "nds-natbox" iptables -t nat -A POSTROUTING -o "wan0" -j MASQUERADE

  # Give natbox Internet access
  sysctl -w "net.ipv4.ip_forward=1"
  iptables -t nat -A POSTROUTING -s "10.0.100.2/24" -o "$INTERNET_IFACE" -j MASQUERADE
  iptables -A FORWARD -i "$INTERNET_IFACE" -o "wan1" -j ACCEPT
  iptables -A FORWARD -o "$INTERNET_IFACE" -i "wan1" -j ACCEPT

elif [ "$1" = "destroy" ]; then
  if [ $(id -u) -ne 0 ]; then
    echo "You must be root to run this script."
    exit 1
  fi

  ip link delete "nds-bridge" type bridge
  ip netns exec "nds-client1" ip link del "eth0"
  ip netns exec "nds-client2" ip link del "eth0"
  ip netns exec "nds-natbox" ip link del "wan0"
  ip netns del "nds-client1"
  ip netns del "nds-client2"
  ip netns del "nds-natbox"
elif [ "$1" = "help" ]; then
  print_help
else
  print_help
  exit 1
fi
