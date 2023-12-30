#!/bin/bash

# sudo apt install iperf3 dante-server
# sudo systemctl stop danted

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo $SCRIPT_DIR

netns="test"
dante="danted"
tun2socks5="${SCRIPT_DIR}/../target/release/examples/tun2socks5"

ip netns add "$netns"

ip link add veth0 type veth peer name veth0 netns "$netns"

# Configure veth0 in default ns
ip addr add 10.0.0.2/24 dev veth0
ip link set dev veth0 up

# Configure veth0 in child ns
ip netns exec "$netns" ip addr add 10.0.0.3/24 dev veth0
ip netns exec "$netns" ip addr add 10.0.0.4/24 dev veth0
ip netns exec "$netns" ip link set dev veth0 up

# Configure lo interface in child ns
ip netns exec "$netns" ip addr add 127.0.0.1/8 dev lo
ip netns exec "$netns" ip link set dev lo up

echo "Starting Dante in background ..."
ip netns exec "$netns" "$dante" -f ${SCRIPT_DIR}/dante.conf &

# Start rperf server in netns
ip netns exec "$netns" rperf -s -B 10.0.0.4 &

sleep 1

# Prepare tun2socks5
ip tuntap add name tun0 mode tun
ip link set tun0 up
ip route add 10.0.0.4 dev tun0
"$tun2socks5" --proxy socks5://10.0.0.3:10800 -v off &

sleep 3

# Run iperf client through tun2socks5
rperf -c 10.0.0.4 -v off -P 1 -r

sleep 3

rperf -c 10.0.0.4 -v off -P 1

sleep 3

rperf -c 10.0.0.4 -v off -P 1 -u

sleep 3

rperf -c 10.0.0.4 -v trace -P 1 -u -r


# Clean up
# sudo sh -c "pkill tun2socks5; pkill rperf; pkill danted; ip link del tun0; ip netns del test"