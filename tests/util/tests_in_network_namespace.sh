#!/bin/sh

unshare --user --net --map-root-user bash << 'EOF'
	ip link set lo up
	ip link add dev dummy0 type dummy
	ip link set dummy0 up

	# single address
	ip -4 neigh add 192.168.1.100 lladdr 00:bb:cc:dd:ee:ff dev dummy0

	# two different addresses with same mac
	ip -4 neigh add 192.168.1.101 lladdr 11:bb:cc:dd:ee:ff dev dummy0
	ip -4 neigh add 192.168.1.102 lladdr 11:bb:cc:dd:ee:ff dev dummy0

	# single address
	ip -6 neigh add 2001:db8::100 lladdr 22:bb:cc:dd:ee:ff dev dummy0

	# two different addresses with same mac
	ip -6 neigh add 2001:db8::101 lladdr 33:bb:cc:dd:ee:ff dev dummy0
	ip -6 neigh add 2001:db8::102 lladdr 33:bb:cc:dd:ee:ff dev dummy0

	./test_utils
EOF

