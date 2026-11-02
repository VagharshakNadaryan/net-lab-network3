#!/usr/bin/env bash
[ "$EUID" -eq 0 ] || { echo "run as root"; exit 1; }
pkill -INT -x network3 2>/dev/null
pkill -x tcpdump 2>/dev/null
for n in pc1 d1 mitm d2 pc2; do ip netns del $n 2>/dev/null; done
echo "lab removed"
