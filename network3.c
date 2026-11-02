/* network3.c - compact AES-GCM TCP payload gateway
 *
 * PC1 -> Device1 -> Device2 -> PC2
 *
 * usage:  network3 PORT responder
 *         network3 PORT initiator PEER_IP
 *
 * build:  gcc -O2 -Wall -Wextra -fno-strict-aliasing -o network3 network3.c \
 *             -lnetfilter_queue -lcrypto
 *
 * Device2: sudo ./network3 5001 responder
 * Device1: sudo ./network3 5001 initiator 10.0.12.2
 *
 * iptables on both devices (eth0 = host side, eth1 = other device):
 *   iptables -t raw    -A PREROUTING -p tcp -m multiport --ports 5001 -j CT --notrack
 *   iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -m multiport --ports 5001 -j TCPMSS --set-mss 1400
 *   iptables -A FORWARD -i eth0 -p tcp -m multiport --ports 5001 -j NFQUEUE --queue-num 0   (encrypt)
 *   iptables -A FORWARD -i eth1 -p tcp -m multiport --ports 5001 -j NFQUEUE --queue-num 1   (decrypt)
 * plus ip_forward=1, routes, gro/gso/tso off. Never use --queue-bypass.
 *
 * Handshake on TCP port 9000 (fixed sizes, no framing):
 *   I -> R : DH public (256 B)       R -> I : DH public (256 B)
 *   I -> R : confirm (32 B)          R -> I : confirm (32 B)
 * Data path: TCP payload -> AES-256-GCM, 16-byte tag appended, headers kept.
 *
 * Nonce = 4-byte salt | 64-bit counter.  The last bit of the salt is the
 * direction (initiator sends with 1, responder with 0), the other 31 bits
 * come from the DH secret.  Counter +1 per packet => never repeats.
 * The receiver tries the next WIN counters, the tag picks the right one.
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#define CTRL_PORT 9000
#define TAG       16
#define IVL       12
#define AADL      20
#define MAXP      65535
#define WIN       1024
#define LIMIT     0xffffffffULL
#define PUBL      256

/* ---- state ---- */
static int      is_init;
static uint16_t port;
static uint8_t  key[32], salt_tx[4], salt_rx[4];
static uint64_t ctr_tx, ctr_rx;
static EVP_CIPHER_CTX *c_enc, *c_dec;
static unsigned long n_enc, n_dec, n_pass, n_drop;
static volatile sig_atomic_t stop;
static uint8_t wbuf[MAXP + 64] __attribute__((aligned(8)));
static uint8_t pbuf[MAXP + 64] __attribute__((aligned(8)));
static const int DIR_ENC = 1, DIR_DEC = 0;      /* passed as queue "arg" */

/* ---- socket io ---- */
static int wr(int fd, const void *b, size_t n)
{
    const uint8_t *p = b;
    while (n) {
        ssize_t r = send(fd, p, n, MSG_NOSIGNAL);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return -1;
        p += r; n -= (size_t)r;
    }
    return 0;
}

static int rd(int fd, void *b, size_t n)
{
    uint8_t *p = b;
    while (n) {
        ssize_t r = recv(fd, p, n, 0);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return -1;
        p += r; n -= (size_t)r;
    }
    return 0;
}

static int ctrl_open(const char *ip)
{
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(CTRL_PORT) };
    int fd, one = 1;

    if (inet_pton(AF_INET, ip, &a.sin_addr) != 1) return -1;
    if (is_init) {
        for (int i = 0; i < 30 && !stop; i++) {
            if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) return -1;
            if (!connect(fd, (struct sockaddr *)&a, sizeof a)) return fd;
            close(fd);
            sleep(1);
        }
        return -1;
    }
    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) return -1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (bind(fd, (struct sockaddr *)&a, sizeof a) || listen(fd, 1)) { close(fd); return -1; }
    one = accept(fd, NULL, NULL);
    close(fd);
    return one;
}

/* ---- key exchange ---- */

/* out = SHA256(label | 0 | secret | transcript) */
static void derive(const char *label, const uint8_t *z, const uint8_t *tr, uint8_t out[32])
{
    uint8_t in[32 + PUBL + 32];
    size_t l = strlen(label) + 1;

    memcpy(in, label, l);
    memcpy(in + l, z, PUBL);
    memcpy(in + l + PUBL, tr, 32);
    SHA256(in, l + PUBL + 32, out);
    OPENSSL_cleanse(in, sizeof in);
}

static int proof(const uint8_t k[32], char who, const uint8_t tr[32], uint8_t out[32])
{
    uint8_t m[33];
    unsigned n = 0;

    memcpy(m, tr, 32);
    m[32] = (uint8_t)who;
    return HMAC(EVP_sha256(), k, 32, m, 33, out, &n) ? 0 : -1;
}

static int handshake(int fd)
{
    BN_CTX *bn = BN_CTX_new();
    BIGNUM *p = BN_get_rfc3526_prime_2048(NULL), *g = BN_new(), *x = BN_new();
    BIGNUM *gx = BN_new(), *gy = NULL, *s = BN_new(), *pm1 = BN_new();
    uint8_t mine[PUBL], theirs[PUBL], z[PUBL], both[2 * PUBL], tr[32];
    uint8_t k_key[32], k_salt[32], k_cf[32], f_me[32], f_they[32], f_want[32];
    int rc = -1;

    if (!bn || !p || !g || !x || !gx || !s || !pm1) goto end;
    BN_set_word(g, 2);
    if (!BN_rand(x, 256, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY)) goto end;
    if (!BN_mod_exp(gx, g, x, p, bn) || BN_bn2binpad(gx, mine, PUBL) != PUBL) goto end;

    if (is_init) { if (wr(fd, mine, PUBL) || rd(fd, theirs, PUBL)) goto end; }
    else         { if (rd(fd, theirs, PUBL) || wr(fd, mine, PUBL)) goto end; }

    gy = BN_bin2bn(theirs, PUBL, NULL);
    BN_copy(pm1, p);
    BN_sub_word(pm1, 1);
    if (!gy || BN_cmp(gy, BN_value_one()) <= 0 || BN_cmp(gy, pm1) >= 0) goto end;
    if (!BN_mod_exp(s, gy, x, p, bn) || BN_bn2binpad(s, z, PUBL) != PUBL) goto end;

    memcpy(both,        is_init ? mine : theirs, PUBL);
    memcpy(both + PUBL, is_init ? theirs : mine, PUBL);
    SHA256(both, sizeof both, tr);
    derive("gw8 key", z, tr, k_key);
    derive("gw8 salt", z, tr, k_salt);
    derive("gw8 confirm", z, tr, k_cf);

    if (proof(k_cf, is_init ? 'I' : 'R', tr, f_me) || proof(k_cf, is_init ? 'R' : 'I', tr, f_want)) goto end;
    if (is_init) {
        if (wr(fd, f_me, 32) || rd(fd, f_they, 32)) goto end;
    } else {
        if (rd(fd, f_they, 32) || CRYPTO_memcmp(f_they, f_want, 32) || wr(fd, f_me, 32)) goto end;
    }
    if (CRYPTO_memcmp(f_they, f_want, 32)) goto end;

    memcpy(key, k_key, 32);
    memcpy(salt_tx, k_salt, 4);
    memcpy(salt_rx, k_salt, 4);
    salt_tx[3] = (uint8_t)((salt_tx[3] & 0xfe) | (is_init ? 1 : 0));
    salt_rx[3] = (uint8_t)((salt_rx[3] & 0xfe) | (is_init ? 0 : 1));
    c_enc = EVP_CIPHER_CTX_new();
    c_dec = EVP_CIPHER_CTX_new();
    if (!c_enc || !c_dec) goto end;
    if (!EVP_EncryptInit_ex(c_enc, EVP_aes_256_gcm(), NULL, NULL, NULL) ||
        !EVP_DecryptInit_ex(c_dec, EVP_aes_256_gcm(), NULL, NULL, NULL))
        goto end;
    rc = 0;
end:
    OPENSSL_cleanse(z, sizeof z);
    OPENSSL_cleanse(k_key, sizeof k_key);
    OPENSSL_cleanse(k_cf, sizeof k_cf);
    BN_clear_free(x); BN_clear_free(s);
    BN_free(gx); BN_free(gy); BN_free(g); BN_free(p); BN_free(pm1);
    BN_CTX_free(bn);
    return rc;
}

/* ---- checksums ---- */
static uint32_t csum_part(const void *data, size_t n, uint32_t sum)
{
    const uint8_t *p = data;
    uint16_t w;

    for (; n > 1; p += 2, n -= 2) { memcpy(&w, p, 2); sum += ntohs(w); }
    if (n) sum += (uint32_t)*p << 8;
    return sum;
}

static uint16_t csum_fin(uint32_t sum)
{
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return htons((uint16_t)~sum);
}

/* ---- packet ---- */
struct pk {
    struct iphdr *ip;
    struct tcphdr *tcp;
    uint8_t *data;
    size_t ihl, tot, dlen;
};

/* 1 = work on it, 0 = let it pass, -1 = drop */
static int inspect(uint8_t *b, size_t n, struct pk *k)
{
    struct iphdr *ip = (struct iphdr *)b;
    struct tcphdr *t;
    size_t ihl, thl, tot;

    if (n < sizeof *ip) return -1;
    if (ip->version != 4) return 0;
    ihl = ip->ihl * 4u;
    if (ihl < sizeof *ip || ihl > n) return -1;
    if (ip->protocol != IPPROTO_TCP) return 0;
    tot = ntohs(ip->tot_len);
    if (tot > n || tot < ihl + sizeof *t) return -1;
    if (ntohs(ip->frag_off) & (IP_MF | IP_OFFMASK)) return -1;
    t = (struct tcphdr *)(b + ihl);
    thl = t->doff * 4u;
    if (thl < sizeof *t || ihl + thl > tot) return -1;
    if (ntohs(t->source) != port && ntohs(t->dest) != port) return 0;

    k->ip = ip; k->tcp = t; k->ihl = ihl; k->tot = tot;
    k->data = b + ihl + thl; k->dlen = tot - ihl - thl;
    return k->dlen ? 1 : 0;
}

/* new length + both checksums */
static void reseal(struct pk *k, size_t new_tot)
{
    size_t tl = new_tot - k->ihl;
    uint32_t s;

    k->ip->tot_len = htons((uint16_t)new_tot);
    k->ip->check = 0;
    k->ip->check = csum_fin(csum_part(k->ip, k->ihl, 0));
    k->tcp->check = 0;
    s = csum_part(&k->ip->saddr, 8, 0) + IPPROTO_TCP + (uint32_t)tl;
    k->tcp->check = csum_fin(csum_part(k->tcp, tl, s));
}

/* aad = saddr daddr sport dport seq ack */
static void aad_of(const struct pk *k, uint8_t a[AADL])
{
    memcpy(a,      &k->ip->saddr, 4);
    memcpy(a + 4,  &k->ip->daddr, 4);
    memcpy(a + 8,  &k->tcp->source, 2);
    memcpy(a + 10, &k->tcp->dest, 2);
    memcpy(a + 12, &k->tcp->seq, 4);
    memcpy(a + 16, &k->tcp->ack_seq, 4);
}

static void iv_of(uint8_t iv[IVL], const uint8_t salt[4], uint64_t c)
{
    memcpy(iv, salt, 4);
    for (int i = 0; i < 8; i++) iv[4 + i] = (uint8_t)(c >> (56 - 8 * i));
}

static int do_enc(struct pk *k)
{
    uint8_t aad[AADL], iv[IVL];
    int a = 0, b = 0;

    if (ctr_tx >= LIMIT || k->tot + TAG > MAXP) return -1;
    aad_of(k, aad);
    iv_of(iv, salt_tx, ++ctr_tx);
    if (!EVP_EncryptInit_ex(c_enc, NULL, NULL, key, iv) ||
        !EVP_EncryptUpdate(c_enc, NULL, &a, aad, AADL) ||
        !EVP_EncryptUpdate(c_enc, k->data, &a, k->data, (int)k->dlen) ||
        !EVP_EncryptFinal_ex(c_enc, k->data + a, &b) ||
        !EVP_CIPHER_CTX_ctrl(c_enc, EVP_CTRL_GCM_GET_TAG, TAG, k->data + k->dlen))
        return -1;
    reseal(k, k->tot + TAG);
    return (int)(k->tot + TAG);
}

static int tag_ok(const uint8_t iv[IVL], const uint8_t aad[AADL], const struct pk *k, size_t cl)
{
    int a = 0, b = 0;

    return EVP_DecryptInit_ex(c_dec, NULL, NULL, key, iv) &&
           EVP_DecryptUpdate(c_dec, NULL, &a, aad, AADL) &&
           EVP_DecryptUpdate(c_dec, pbuf, &a, k->data, (int)cl) &&
           EVP_CIPHER_CTX_ctrl(c_dec, EVP_CTRL_GCM_SET_TAG, TAG, (void *)(k->data + cl)) &&
           EVP_DecryptFinal_ex(c_dec, pbuf + a, &b) > 0;
}

static int do_dec(struct pk *k)
{
    uint8_t aad[AADL], iv[IVL];
    size_t cl;

    if (k->dlen <= TAG) return -1;
    cl = k->dlen - TAG;
    aad_of(k, aad);
    for (uint64_t c = ctr_rx + 1; c <= ctr_rx + WIN; c++) {
        iv_of(iv, salt_rx, c);
        if (tag_ok(iv, aad, k, cl)) {
            memcpy(k->data, pbuf, cl);
            ctr_rx = c;
            reseal(k, k->tot - TAG);
            return (int)(k->tot - TAG);
        }
    }
    return -1;
}

/* one callback for both queues; "arg" says which direction this queue is */
static int on_pkt(struct nfq_q_handle *qh, struct nfgenmsg *m, struct nfq_data *nfa, void *arg)
{
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    int encrypt = *(const int *)arg;
    unsigned char *raw = NULL;
    struct pk k;
    uint32_t id;
    int n, w, out;

    (void)m;
    if (!ph) return -1;
    id = ntohl(ph->packet_id);
    n = nfq_get_payload(nfa, &raw);
    if (n <= 0 || n > MAXP) goto bad;
    memcpy(wbuf, raw, (size_t)n);

    w = inspect(wbuf, (size_t)n, &k);
    if (w < 0) goto bad;
    if (w == 0) { n_pass++; return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL); }

    out = encrypt ? do_enc(&k) : do_dec(&k);
    if (out < 0) goto bad;
    if (encrypt) n_enc++; else n_dec++;
    return nfq_set_verdict(qh, id, NF_ACCEPT, (uint32_t)out, wbuf);
bad:
    n_drop++;
    return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
}

static void on_sig(int s) { (void)s; stop = 1; }

int main(int argc, char **argv)
{
    static char rxb[0x20000] __attribute__((aligned(8)));
    struct sigaction sa = { .sa_handler = on_sig };
    struct nfq_handle *h;
    struct nfq_q_handle *q0, *q1;
    int cfd, nfd, rcv = 4 << 20;
    const char *peer = "0.0.0.0";

    if (argc < 3 || atoi(argv[1]) <= 0 || atoi(argv[1]) > 65535 ||
        (strcmp(argv[2], "initiator") && strcmp(argv[2], "responder")) ||
        (argv[2][0] == 'i' && argc < 4)) {
        fprintf(stderr, "usage: %s PORT responder | %s PORT initiator PEER_IP\n", argv[0], argv[0]);
        return 2;
    }
    port = (uint16_t)atoi(argv[1]);
    is_init = argv[2][0] == 'i';
    if (is_init) peer = argv[3];

    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    if ((cfd = ctrl_open(peer)) < 0) { fprintf(stderr, "no control connection\n"); return 1; }
    if (handshake(cfd)) { fprintf(stderr, "handshake failed\n"); return 1; }
    fprintf(stderr, "session established (%s)\n", argv[2]);

    if (!(h = nfq_open())) return 1;
    q0 = nfq_create_queue(h, 0, on_pkt, (void *)&DIR_ENC);
    q1 = nfq_create_queue(h, 1, on_pkt, (void *)&DIR_DEC);
    if (!q0 || !q1 || nfq_set_mode(q0, NFQNL_COPY_PACKET, 0xffff) < 0 ||
        nfq_set_mode(q1, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "cannot bind NFQUEUE 0 and 1\n");
        return 1;
    }
    nfq_set_queue_maxlen(q0, 8192);
    nfq_set_queue_maxlen(q1, 8192);
    nfd = nfq_fd(h);
    if (setsockopt(nfd, SOL_SOCKET, SO_RCVBUFFORCE, &rcv, sizeof rcv) < 0)
        setsockopt(nfd, SOL_SOCKET, SO_RCVBUF, &rcv, sizeof rcv);

    while (!stop) {
        struct pollfd pf[2] = { { nfd, POLLIN, 0 }, { cfd, POLLIN, 0 } };
        if (poll(pf, 2, -1) < 0) { if (errno == EINTR) continue; break; }
        if (pf[1].revents) { fprintf(stderr, "peer closed the control connection\n"); break; }
        if (pf[0].revents & POLLIN) {
            ssize_t n = recv(nfd, rxb, sizeof rxb, 0);
            if (n >= 0) nfq_handle_packet(h, rxb, (int)n);
            else if (errno != EINTR && errno != ENOBUFS) break;
        }
    }
    fprintf(stderr, "enc=%lu dec=%lu pass=%lu drop=%lu\n", n_enc, n_dec, n_pass, n_drop);
    nfq_destroy_queue(q0);
    nfq_destroy_queue(q1);
    nfq_close(h);
    close(cfd);
    return 0;
}
