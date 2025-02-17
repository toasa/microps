#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "ip.h"
#include "net.h"
#include "util.h"

struct ip_hdr {
    uint8_t vhl;     /* Version / Header length */
    uint8_t tos;     /* Type of service */
    uint16_t total;  /* Total length */
    uint16_t id;     /* Identification */
    uint16_t offset; /* Fragment offset */
    uint8_t ttl;     /* Time to live */
    uint8_t proto;   /* Protocol */
    uint16_t chksum; /* Header checksum */

    ip_addr_t src;
    ip_addr_t dst;

    uint8_t options[];
};

#define IPV4_VERSION(hdr) ((hdr->vhl & 0xf0) >> 4)
#define IPV4_IHL(hdr) (hdr->vhl & 0x0f)
#define IPV4_HEADER_LEN(hdr) (IPV4_IHL(hdr) << 2)

const ip_addr_t IP_ADDR_ANY = 0x00000000;       /* 0.0.0.0 */
const ip_addr_t IP_ADDR_BROADCAST = 0xffffffff; /* 255.255.255.255 */

int ip_addr_pton(const char *src, ip_addr_t *dst) {
    char *sp = (char *)src;

    for (int idx = 0; idx < 4; idx++) {
        char *ep;
        long ret = strtol(sp, &ep, 10);
        if (ret < 0 || ret > 255)
            return -1;
        if (ep == sp)
            return -1;
        if ((idx == 3 && *ep != '\0') || (idx != 3 && *ep != '.'))
            return -1;

        ((uint8_t *)dst)[idx] = ret;
        sp = ep + 1;
    }

    return 0;
}

char *ip_addr_ntop(ip_addr_t src, char *dst, size_t size) {
    uint8_t *u8 = (uint8_t *)&src;
    snprintf(dst, size, "%d.%d.%d.%d", u8[0], u8[1], u8[2], u8[3]);
    return dst;
}

static void ip_dump(const uint8_t *data, size_t len) {
    flockfile(stderr);

    struct ip_hdr *hdr = (struct ip_hdr *)data;

    uint16_t total = ntoh16(hdr->total);
    uint16_t offset = ntoh16(hdr->offset);
    char addr[IP_ADDR_STR_LEN];

    fprintf(stderr, "        vhl: 0x%02x [v: %u, hlen: %u]\n", hdr->vhl,
            IPV4_VERSION(hdr), IPV4_HEADER_LEN(hdr));
    fprintf(stderr, "        tos: 0x%02x\n", hdr->tos);
    fprintf(stderr, "      total: %u (payload: %u)\n", total,
            total - IPV4_HEADER_LEN(hdr));
    fprintf(stderr, "         id: %u\n", ntoh16(hdr->id));
    fprintf(stderr, "     offset: 0x%04x [flags=%x, offset=%u]\n", offset,
            (offset & 0xe000) >> 13, offset & 0x1fff);
    fprintf(stderr, "        ttl: %u\n", hdr->ttl);
    fprintf(stderr, "   protocol: %u\n", hdr->proto);
    fprintf(stderr, "      cksum: 0x%04x\n", ntoh16(hdr->chksum));
    fprintf(stderr, "        src: %s\n",
            ip_addr_ntop(hdr->src, addr, sizeof(addr)));
    fprintf(stderr, "        dst: %s\n",
            ip_addr_ntop(hdr->dst, addr, sizeof(addr)));

#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif

    funlockfile(stderr);
}

static void ip_input(const uint8_t *data, size_t len, struct net_device *dev) {
    if (len < IP_HDR_SIZE_MIN) {
        errorf("too short");
        return;
    }

    struct ip_hdr *hdr = (struct ip_hdr *)data;
    uint16_t total = ntoh16(hdr->total);

    if (IPV4_VERSION(hdr) != IP_VERSION_IPV4) {
        errorf("only support IPv4");
        return;
    }
    if (len < IPV4_HEADER_LEN(hdr)) {
        errorf("too short IP header");
        return;
    }
    if (len < total) {
        errorf("too short IP total length");
        return;
    }
    if (cksum16((uint16_t *)data, len, 0)) {
        errorf("invalid check sum");
        return;
    }

    debugf("dev=%s, protocol=%u, total=%u", dev->name, hdr->proto, total);
    ip_dump(data, len);
}

int ip_init(void) {
    if (net_protocol_register(NET_PROTOCOL_TYPE_IP, ip_input) == -1) {
        errorf("net_protocol_register() failure");
        return -1;
    }

    return 0;
}