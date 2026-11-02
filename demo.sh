#!/usr/bin/env bash
# usage: demo.sh pass|replay|corrupt
[ "$EUID" -eq 0 ] || { echo "run as root"; exit 1; }
MODE=${1:-pass}; PORT=5001
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN=$ROOT/build/network3; PY=$ROOT/scripts
W=$(mktemp -d); echo "work dir: $W"

# 3 MB test file with a readable marker, so we can grep the wire for plaintext
{ for i in $(seq 1 2000); do echo "SECRET-PLAINTEXT-MARKER-$i"; done
  head -c 3000000 /dev/urandom; } > $W/in.bin

ip netns exec d2   $BIN $PORT responder > $W/d2.log 2>&1 & D2=$!
sleep 1
ip netns exec d1   $BIN $PORT initiator 10.0.12.2 > $W/d1.log 2>&1 & D1=$!
for i in $(seq 1 20); do
    grep -q "session established" $W/d1.log 2>/dev/null && grep -q "session established" $W/d2.log 2>/dev/null && break
    sleep 1
done
grep -q "session established" $W/d1.log || { echo "handshake failed"; cat $W/d1.log $W/d2.log; kill -INT $D1 $D2; exit 1; }

# attacker behaviour on the D1 -> D2 direction
case $MODE in
    replay)  ip netns exec mitm tc qdisc add dev eth1 root netem duplicate 100% ;;
    corrupt) ip netns exec mitm tc qdisc add dev eth1 root netem corrupt 3% ;;
esac

ip netns exec mitm tcpdump -q -n -i br0 -w $W/mitm.pcap "tcp port $PORT" 2>/dev/null & T1=$!
ip netns exec d1   tcpdump -q -n -i eth0 -w $W/pc1side.pcap "tcp port $PORT" 2>/dev/null & T2=$!
sleep 1

ip netns exec pc2 python3 $PY/recvfile.py $W/out.bin $PORT & RX=$!
sleep 1
ip netns exec pc1 python3 $PY/sendfile.py $W/in.bin 10.0.2.1 $PORT
wait $RX

sleep 1; kill $T1 $T2 2>/dev/null; kill -INT $D1 $D2; sleep 1; wait 2>/dev/null

echo "---- mode: $MODE"
echo "sha256 in : $(sha256sum < $W/in.bin)"
echo "sha256 out: $(sha256sum < $W/out.bin)"
echo "marker seen on PC1 side : $(grep -ac SECRET-PLAINTEXT-MARKER $W/pc1side.pcap) hits"
echo "marker seen by attacker : $(grep -ac SECRET-PLAINTEXT-MARKER $W/mitm.pcap) hits"
echo "D1: $(tail -1 $W/d1.log)"
echo "D2: $(tail -1 $W/d2.log)"
