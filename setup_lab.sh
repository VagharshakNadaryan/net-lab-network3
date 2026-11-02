#!/usr/bin/env bash
# Builds: pc1 -- d1 == mitm(bridge) == d2 -- pc2
set -euo pipefail
[ "$EUID" -eq 0 ] || { echo "run as root"; exit 1; }
PORT=${PORT:-5001}

for n in pc1 d1 mitm d2 pc2; do
    ip netns add $n
    ip -n $n link set lo up
done

# link NS_A IF_A NS_B IF_B
link() {
    ip link add "t-$1-$2" type veth peer name "t-$3-$4"
    ip link set "t-$1-$2" netns "$1" name "$2"
    ip link set "t-$3-$4" netns "$3" name "$4"
}
link pc1  eth0 d1   eth0
link d1   eth1 mitm eth0
link mitm eth1 d2   eth1
link d2   eth0 pc2  eth0

# addresses
ip -n pc1 addr add 10.0.1.1/24  dev eth0
ip -n d1  addr add 10.0.1.254/24 dev eth0
ip -n d1  addr add 10.0.12.1/24 dev eth1
ip -n d2  addr add 10.0.12.2/24 dev eth1
ip -n d2  addr add 10.0.2.254/24 dev eth0
ip -n pc2 addr add 10.0.2.1/24  dev eth0

# mitm = transparent L2 bridge (sees every frame between D1 and D2)
ip -n mitm link add br0 type bridge
ip -n mitm link set eth0 master br0
ip -n mitm link set eth1 master br0

# up + offloads off (NFQUEUE needs real checksums and no GRO/GSO/TSO merging)
for pair in pc1:eth0 d1:eth0 d1:eth1 mitm:eth0 mitm:eth1 d2:eth1 d2:eth0 pc2:eth0; do
    ns=${pair%%:*}; ifc=${pair##*:}
    ip -n $ns link set $ifc up
    ip netns exec $ns ethtool -K $ifc gro off gso off tso off tx off rx off >/dev/null 2>&1 || true
done
ip -n mitm link set br0 up

# routes
ip -n pc1 route add default via 10.0.1.254
ip -n pc2 route add default via 10.0.2.254
ip -n d1  route add 10.0.2.0/24 via 10.0.12.2
ip -n d2  route add 10.0.1.0/24 via 10.0.12.1
for d in d1 d2; do ip netns exec $d sysctl -qw net.ipv4.ip_forward=1; done

# gateway rules (eth0 = host side -> queue 0 encrypt, eth1 = other device -> queue 1 decrypt)
for d in d1 d2; do
    ip netns exec $d iptables -t raw    -A PREROUTING -p tcp -m multiport --ports $PORT -j CT --notrack
    ip netns exec $d iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -m multiport --ports $PORT -j TCPMSS --set-mss 1400
    ip netns exec $d iptables -A FORWARD -i eth0 -p tcp -m multiport --ports $PORT -j NFQUEUE --queue-num 0
    ip netns exec $d iptables -A FORWARD -i eth1 -p tcp -m multiport --ports $PORT -j NFQUEUE --queue-num 1
done
echo "lab ready: pc1 10.0.1.1 | d1 10.0.12.1 | d2 10.0.12.2 | pc2 10.0.2.1 | port $PORT"
