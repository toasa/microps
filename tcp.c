#include <stdio.h>

#include "ip.h"
#include "tcp.h"
#include "util.h"

#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_URG 0x20

#define TCP_FLAG_IS(x, y) ((x & 0x3f) == (y))
#define TCP_FLAG_ISSET(x, y) ((x & 0x3f) & (y) ? 1 : 0)

struct pseudo_hdr {
    uint32_t src;
    uint32_t dst;
    uint8_t zero;
    uint8_t proto;
    uint16_t len;
};

struct tcp_hdr {
    uint16_t src;
    uint16_t dst;
    uint32_t seqno;
    uint32_t ackno;
    uint8_t off;
    uint8_t flag;
    uint16_t wnd;
    uint16_t cksum;
    uint16_t urgp;
};

static char *tcp_flag_ntoa(uint8_t flag) {
    static char str[9];

    snprintf(str, sizeof(str), "--%c%c%c%c%c%c",
             TCP_FLAG_ISSET(flag, TCP_FLAG_URG) ? 'U' : '-',
             TCP_FLAG_ISSET(flag, TCP_FLAG_ACK) ? 'A' : '-',
             TCP_FLAG_ISSET(flag, TCP_FLAG_PSH) ? 'P' : '-',
             TCP_FLAG_ISSET(flag, TCP_FLAG_RST) ? 'R' : '-',
             TCP_FLAG_ISSET(flag, TCP_FLAG_SYN) ? 'S' : '-',
             TCP_FLAG_ISSET(flag, TCP_FLAG_FIN) ? 'F' : '-');

    return str;
}

static void tcp_dump(const uint8_t *data, size_t len) {
    struct tcp_hdr *hdr = (struct tcp_hdr *)data;

    flockfile(stderr);
    fprintf(stderr, "        src: %u\n", ntoh16(hdr->src));
    fprintf(stderr, "        dst: %u\n", ntoh16(hdr->dst));
    fprintf(stderr, "      seqno: %u\n", ntoh32(hdr->seqno));
    fprintf(stderr, "      ackno: %u\n", ntoh32(hdr->ackno));
    fprintf(stderr, "        off: 0x%02x (%d)\n", hdr->off,
            (hdr->off >> 4) << 2);
    fprintf(stderr, "       flag: 0x%02x (%s)\n", hdr->flag,
            tcp_flag_ntoa(hdr->flag));
    fprintf(stderr, "        wnd: %u\n", ntoh16(hdr->wnd));
    fprintf(stderr, "      cksum: 0x%04x\n", ntoh16(hdr->cksum));
    fprintf(stderr, "       urgp: %u\n", ntoh16(hdr->urgp));
#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

static void tcp_input(const uint8_t *data, size_t len, ip_addr_t src,
                      ip_addr_t dst, struct ip_iface *iface) {
    if (len < sizeof(struct tcp_hdr)) {
        errorf("too short");
        return;
    }

    if (src == IP_ADDR_BROADCAST || dst == IP_ADDR_BROADCAST) {
        errorf("unicast IP address only support");
        return;
    }

    uint16_t cksum = ~cksum16((uint16_t *)data, len, 0);
    struct pseudo_hdr p_hdr = {
        .src = src,
        .dst = dst,
        .zero = 0,
        .proto = IP_PROTO_TCP,
        .len = hton16(len),
    };
    if (cksum16((uint16_t *)&p_hdr, sizeof(struct pseudo_hdr), cksum) != 0) {
        errorf("checksum invalid");
        return;
    }

    struct tcp_hdr *hdr = (struct tcp_hdr *)data;

    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];
    debugf("%s:%d => %s:%d, len=%zu (payload=%zu)",
           ip_addr_ntop(src, addr1, sizeof(addr1)), ntoh16(hdr->src),
           ip_addr_ntop(dst, addr2, sizeof(addr2)), ntoh16(hdr->dst), len,
           len - sizeof(struct tcp_hdr));
    tcp_dump(data, len);
}

int tcp_init(void) {
    if (ip_proto_register(IP_PROTO_TCP, tcp_input) == -1) {
        errorf("ip_proto_register() failure");
        return -1;
    }

    return 0;
}