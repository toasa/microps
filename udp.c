#include <string.h>

#include "ip.h"
#include "udp.h"
#include "util.h"

// For UDP's checksum calculation
struct pseudo_hdr {
    uint32_t src;
    uint32_t dst;
    uint8_t zero;
    uint8_t proto;
    uint16_t len;
};

struct udp_hdr {
    uint16_t src;
    uint16_t dst;
    uint16_t len;
    uint16_t chksum;
};

static void udp_dump(const uint8_t *data, size_t len) {
    struct udp_hdr *hdr = (struct udp_hdr *)data;

    flockfile(stderr);
    fprintf(stderr, "        src: %u\n", ntoh16(hdr->src));
    fprintf(stderr, "        dst: %u\n", ntoh16(hdr->dst));
    fprintf(stderr, "        len: %u\n", ntoh16(hdr->len));
    fprintf(stderr, "      cksum: 0x%04x\n", ntoh16(hdr->chksum));
#ifdef HEXDUMP
    hexdump(srderr, data, len);
#endif
    funlockfile(stderr);
}

static void udp_input(const uint8_t *data, size_t len, ip_addr_t src,
                      ip_addr_t dst, struct ip_iface *iface) {
    if (len < sizeof(struct udp_hdr)) {
        errorf("too short");
        return;
    }

    struct udp_hdr *hdr = (struct udp_hdr *)data;
    if (len != ntoh16(hdr->len)) {
        errorf("length mismatch: len=%zu, hdr->len=%u", len, ntoh16(hdr->len));
        return;
    }

    struct pseudo_hdr phdr = {
        .src = src,
        .dst = dst,
        .zero = 0,
        .proto = IP_PROTO_UDP,
        .len = hton16(len),
    };
    // 擬似ヘッダのチェックサムを計算した後で、残りのUDPパケット
    // （UDPヘッダ＋UDPペイロード） のチェックサムを計算するため、
    // 擬似ヘッダの計算結果はビット反転しておく。
    uint16_t cksum = ~cksum16((uint16_t *)&phdr, sizeof(phdr), 0);
    if (cksum16((uint16_t *)hdr, len, cksum) != 0) {
        errorf("checksum error");
        return;
    }
}

ssize_t udp_output(struct ip_endpoint *src, struct ip_endpoint *dst,
                   const uint8_t *data, size_t len) {
    if (IP_PAYLOAD_SIZE_MAX - sizeof(struct udp_hdr) < len) {
        errorf("too long");
        return -1;
    }

    uint16_t udp_datagram_len = sizeof(struct udp_hdr) + len;

    // Create pseudo header for UDP checksum calculation.
    struct pseudo_hdr phdr = {
        .src = src->addr,
        .dst = dst->addr,
        .zero = 0,
        .proto = IP_PROTO_UDP,
        .len = hton16(udp_datagram_len),
    };
    uint16_t cksum = ~cksum16((uint16_t *)&phdr, sizeof(struct pseudo_hdr), 0);

    // Create UDP Header and datagram.
    uint8_t buf[IP_PAYLOAD_SIZE_MAX] = {};
    struct udp_hdr *hdr = (struct udp_hdr *)buf;
    hdr->src = src->port;
    hdr->dst = dst->port;
    hdr->len = hton16(udp_datagram_len);
    memcpy(buf + sizeof(struct udp_hdr), data, len);

    // Calculate remaining checksum (for UDP header and datagram).
    hdr->chksum = cksum16((uint16_t *)hdr, udp_datagram_len, cksum);

    char ep1[IP_ENDPOINT_STR_LEN];
    char ep2[IP_ENDPOINT_STR_LEN];
    debugf("%s => %s, len=%zu, (payload=%zu)",
           ip_endpoint_ntop(src, ep1, sizeof(ep1)),
           ip_endpoint_ntop(dst, ep2, sizeof(ep2)), udp_datagram_len, len);
    udp_dump((uint8_t *)hdr, udp_datagram_len);

    ip_output(IP_PROTO_UDP, buf, udp_datagram_len, src->addr, dst->addr);

    return len;
}

int udp_init(void) {
    if (ip_proto_register(IP_PROTO_UDP, udp_input) == -1) {
        errorf("ip_proto_register() failure");
        return -1;
    }

    return 0;
}