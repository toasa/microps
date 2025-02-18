#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "ip.h"
#include "net.h"
#include "platform.h"
#include "util.h"

#define IPV4_VERSION(hdr) ((hdr->vhl & 0xf0) >> 4)
#define IPV4_IHL(hdr) (hdr->vhl & 0x0f)
#define IPV4_HEADER_LEN(hdr) (IPV4_IHL(hdr) << 2)

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

struct ip_protocol {
    struct ip_protocol *next;
    uint8_t type;
    ip_proto_handler_t handler;
};

const ip_addr_t IP_ADDR_ANY = 0x00000000;       /* 0.0.0.0 */
const ip_addr_t IP_ADDR_BROADCAST = 0xffffffff; /* 255.255.255.255 */

// NOTE: If you want to add/delete the entries after net_run(), you need to
// protect these lists with a mutex.
static struct ip_iface *ifaces;
static struct ip_protocol *protocols;

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

    fprintf(stderr, "        vhl: 0x%02x [v: %u, ihl: %u(%uB)]\n", hdr->vhl,
            IPV4_VERSION(hdr), IPV4_IHL(hdr), IPV4_HEADER_LEN(hdr));
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

struct ip_iface *ip_iface_alloc(const char *unicast, const char *netmask) {
    struct ip_iface *iface = memory_alloc(sizeof(struct ip_iface));
    if (!iface) {
        errorf("memory_alloc() failure");
        return NULL;
    }

    NET_IFACE(iface)->family = NET_IFACE_FAMILY_IP;
    if (ip_addr_pton(unicast, &iface->unicast) == -1) {
        errorf("ip_addr_pton failure: unicast(%s)", unicast);
        memory_free(iface);
        return NULL;
    }
    if (ip_addr_pton(netmask, &iface->netmask) == -1) {
        errorf("ip_addr_pton failure: netmask(%s)", netmask);
        memory_free(iface);
        return NULL;
    }
    iface->broadcast = iface->unicast | (~iface->netmask);

    return iface;
}

// NOTE: Must not be call after net_run().
int ip_iface_register(struct net_device *dev, struct ip_iface *iface) {
    if (net_device_add_iface(dev, NET_IFACE(iface)) == -1) {
        errorf("net_device_add_iface() failure");
        return -1;
    }

    iface->next = ifaces;
    ifaces = iface;

    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];
    char addr3[IP_ADDR_STR_LEN];
    infof("registered: dev=%s, unicast=%s, netmask=%s, broadcast=%s", dev->name,
          ip_addr_ntop(iface->unicast, addr1, sizeof(addr1)),
          ip_addr_ntop(iface->netmask, addr2, sizeof(addr2)),
          ip_addr_ntop(iface->broadcast, addr3, sizeof(addr3)));

    return 0;
}

struct ip_iface *ip_iface_select(ip_addr_t addr) {
    for (struct ip_iface *i = ifaces; i; i = i->next) {
        if (i->unicast == addr)
            return i;
    }

    return NULL;
}

// NOTE: Must not be call after net_run().
int ip_protocol_register(uint8_t type, ip_proto_handler_t handler){
    for (struct ip_protocol *p = protocols; p; p = p->next) {
        if (p->type == type) {
            errorf("already registered, type=0x%04x", type);
            return -1;
        }
    }

    struct ip_protocol *p = memory_alloc(sizeof(struct ip_protocol));
    if (!p) {
        errorf("memory_alloc() failure");
        return -1;
    }

    p->type = type;
    p->handler = handler;
    p->next = protocols;
    protocols = p;

    infof("registered, type=%u", p->type);

    return 0;
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

    struct ip_iface *iface = ip_iface_select(hdr->src);
    if (iface == NULL) {
        errorf("ip_iface_select() failure: %s", hdr->src);
        return;
    }

    if (!(hdr->dst == iface->unicast || hdr->dst == IP_ADDR_BROADCAST ||
          hdr->dst == iface->broadcast))
        // Destination is for other hosts.
        return;

    char addr[IP_ADDR_STR_LEN];
    debugf("dev=%s, iface=%s, protocol=%u, total=%u", dev->name,
           ip_addr_ntop(iface->unicast, addr, sizeof(addr)), hdr->proto, total);
    ip_dump(data, len);

    for (struct ip_protocol *p = protocols; p; p = p->next) {
        if (p->type == hdr->proto) {
            p->handler(data+IPV4_HEADER_LEN(hdr), total-IPV4_HEADER_LEN(hdr), hdr->src, hdr->dst, iface);
            return;
        }
    }

    // Unsupported protocol
}

static int ip_output_device(struct ip_iface *iface, const uint8_t *data,
                            size_t len, ip_addr_t dst) {
    uint8_t hwaddr[NET_DEVICE_ADDR_LEN] = {};
    if (NET_IFACE(iface)->dev->flags & NET_DEVICE_FLAG_NEEDARP) {
        if (dst == iface->broadcast || dst == IP_ADDR_BROADCAST) {
            memcpy(hwaddr, NET_IFACE(iface)->dev->broadcast,
                   NET_IFACE(iface)->dev->alen);
        } else {
            errorf("ARP does not implement");
            return -1;
        }
    }

    return net_device_output(NET_IFACE(iface)->dev, NET_PROTOCOL_TYPE_IP, data,
                             len, &dst);
}

static ssize_t ip_output_core(struct ip_iface *iface, uint8_t proto,
                              const uint8_t *data, size_t len, ip_addr_t src,
                              ip_addr_t dst, uint16_t id, uint16_t offset) {
    uint8_t buf[IP_TOTAL_SIZE_MAX];

    uint16_t hlen = IP_HDR_SIZE_MIN;
    uint16_t total = len + IP_HDR_SIZE_MIN;

    struct ip_hdr *hdr = (struct ip_hdr *)buf;
    hdr->vhl = (IP_VERSION_IPV4 << 4) | (hlen >> 2);
    hdr->tos = 0;
    hdr->total = hton16(total);
    hdr->id = hton16(id);
    hdr->offset = 0;
    hdr->ttl = 255;
    hdr->proto = proto;
    hdr->chksum = 0; /* Set 0 to calculate check sum. */
    hdr->src = src;
    hdr->dst = dst;
    hdr->chksum = cksum16((uint16_t *)buf, hlen, 0);

    memcpy(buf + hlen, data, len);

    char addr[IP_ADDR_STR_LEN];
    debugf("dev=%s, dst=%s, proto=%u, len=%u", NET_IFACE(iface)->dev->name,
           ip_addr_ntop(dst, addr, sizeof(addr)), proto, total);
    ip_dump(buf, total);

    return ip_output_device(iface, buf, total, dst);
}

static uint16_t ip_generate_id(void) {
    static mutex_t mutex = MUTEX_INITIALIZER;
    static uint16_t id = 128;

    mutex_lock(&mutex);
    uint16_t ret = id++;
    mutex_unlock(&mutex);

    return ret;
}

ssize_t ip_output(uint8_t proto, const uint8_t *data, size_t len, ip_addr_t src,
                  ip_addr_t dst) {
    if (src == IP_ADDR_ANY) {
        errorf("ip routing does not implement");
        return -1;
    }

    char addr[IP_ADDR_STR_LEN];
    struct ip_iface *iface = ip_iface_select(src);
    if (!iface) {
        errorf("ip_iface_select failure: %s",
               ip_addr_ntop(src, addr, sizeof(addr)));
        return -1;
    }

    ip_addr_t mask = iface->netmask;
    if (!((src & mask) == (dst & mask) || dst == IP_ADDR_BROADCAST)) {
        errorf("invalid dst addr: %s", ip_addr_ntop(dst, addr, sizeof(addr)));
        return -1;
    }

    if (NET_IFACE(iface)->dev->mtu < IP_HDR_SIZE_MIN + len) {
        errorf("too large, dev=%s, mtu=%u < %zu", NET_IFACE(iface)->dev->name,
               NET_IFACE(iface)->dev->mtu, IP_HDR_SIZE_MIN + len);
        return -1;
    }

    uint16_t id = ip_generate_id();
    if (ip_output_core(iface, proto, data, len, iface->unicast, dst, id, 0) ==
        -1) {
        errorf("ip_output_core() failure");
        return -1;
    }

    return len;
}

int ip_init(void) {
    if (net_protocol_register(NET_PROTOCOL_TYPE_IP, ip_input) == -1) {
        errorf("net_protocol_register() failure");
        return -1;
    }

    return 0;
}