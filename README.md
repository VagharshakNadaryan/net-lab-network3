# netns-lab (network3)

Two gateways encrypt the TCP payload of one port with AES-256-GCM. Everything runs on one machine with network namespaces.

```
 PC1 --eth0 [ D1 ] eth1 ==== [ MITM ] ==== eth1 [ D2 ] eth0-- PC2
10.0.1.1    encrypt   10.0.12.1   sniff/dup/corrupt   10.0.12.2   decrypt   10.0.2.1
```
D1 = initiator, D2 = responder. Traffic goes both ways; each gateway encrypts what leaves the host side and decrypts what arrives from the other gateway.

## Files

| File | Role |
|------|------|
| `src/network3.c` | the whole gateway: DH handshake, NFQUEUE callbacks, AES-GCM, checksum rebuild |
| `scripts/setup_lab.sh` | 5 namespaces, 4 veth pairs, bridge in `mitm`, routes, offloads off, iptables rules on D1/D2 |
| `scripts/demo.sh` | automatic demo: `pass`, `replay`, `corrupt` |
| `scripts/sendfile.py`, `recvfile.py` | plain TCP file sender (PC1) / receiver (PC2) |
| `scripts/teardown_lab.sh` | removes everything |

## Build and run

```
sudo apt install -y build-essential libssl-dev libnetfilter-queue-dev iproute2 iptables ethtool tcpdump python3
make                                  # -> build/network3
sudo scripts/setup_lab.sh
sudo scripts/demo.sh pass             # sha256 equal, marker NOT visible to attacker
sudo scripts/demo.sh replay           # attacker duplicates every packet -> D2 drop counter rises
sudo scripts/demo.sh corrupt          # attacker flips bits in 3% of packets -> drops, TCP retransmits
sudo scripts/teardown_lab.sh
```

Manual (start D2 first; one terminal each):

```
sudo ip netns exec mitm tcpdump -n -i br0 -X "tcp port 5001"
sudo ip netns exec d2  build/network3 5001 responder
sudo ip netns exec d1  build/network3 5001 initiator 10.0.12.2
sudo ip netns exec pc2 python3 scripts/recvfile.py out.bin 5001
sudo ip netns exec pc1 python3 scripts/sendfile.py in.bin 10.0.2.1 5001
sha256sum in.bin out.bin
```
Ctrl-C on a gateway prints `enc= dec= pass= drop=`.

## Protocol summary

- **Handshake** on a separate TCP connection D1 -> D2 (port 9000), fixed sizes: DH public values (2048-bit RFC 3526 group, 256 B each), then a 32 B HMAC-SHA256 confirmation each way. Key, salt and confirmation key come from SHA256(label | secret | SHA256(both publics)).
- **Data path**: iptables sends TCP packets of the chosen port to NFQUEUE (queue 0 = encrypt, queue 1 = decrypt). Payload becomes `ciphertext | tag(16)`; headers stay in the clear. Packets with no payload (SYN, ACK, FIN) pass untouched.
- **Nonce** = 4-byte salt | 64-bit counter. Last salt bit is the direction (initiator 1, responder 0), the other 31 bits come from the DH secret, so the two directions never share a nonce. Counter is +1 per packet and **not sent on the wire**.
- **Receiver** tries the next 1024 counters; the GCM tag selects the right one. Failed tag => packet dropped, counter unchanged. This also kills replays and duplicates.
- **AAD** = src IP, dst IP, sport, dport, seq, ack (20 B). Changing any of them breaks the tag.
- **Overhead**: IP total length +16, IP and TCP checksums recomputed. MSS clamped to 1400 so the larger packets still fit the MTU.

## Limits

IPv4 only, no fragments. DH is unauthenticated (an active attacker present during the handshake can sit in the middle; a PSK or certificates would fix it). No rekeying (session ends at 2^32 packets). Out-of-order delivery makes the late packet fail (counter already passed) and TCP retransmits it. Each forged packet costs up to 1024 tag checks (CPU DoS). Flags and window are not in the AAD, and payload-less packets are not authenticated. One handshake per process start.
