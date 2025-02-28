#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "arp.h"
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

struct ip_proto {
    struct ip_proto *next;
    uint8_t type;
    ip_proto_handler_t handler;
};

struct ip_route {
    struct ip_route *next;
    ip_addr_t network;
    ip_addr_t netmask;
    ip_addr_t nexthop;
    struct ip_iface *iface;
};

const ip_addr_t IP_ADDR_ANY = 0x00000000;       /* 0.0.0.0 */
const ip_addr_t IP_ADDR_BROADCAST = 0xffffffff; /* 255.255.255.255 */

// NOTE: If you want to add/delete the entries after net_run(), you need to
// protect these lists with a mutex.
static struct ip_iface *ifaces;
static struct ip_proto *protos;
static struct ip_route *routes;

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
    fprintf(stderr, "      proto: %u\n", hdr->proto);
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

// NOTE: Must not be call after net_run().
static struct ip_route *ip_route_add(ip_addr_t network, ip_addr_t netmask,
                                     ip_addr_t nexthop,
                                     struct ip_iface *iface) {
    struct ip_route *r = mem_alloc(sizeof(struct ip_route));
    if (!r) {
        errorf("mem_alloc() failure");
        return NULL;
    }

    r->network = network;
    r->netmask = netmask;
    r->nexthop = nexthop;
    r->iface = iface;

    r->next = routes;
    routes = r;

    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];
    char addr3[IP_ADDR_STR_LEN];
    char addr4[IP_ADDR_STR_LEN];
    infof("route added: network=%s, netmask=%s, nexthop=%s, iface=%s, dev=%s",
          ip_addr_ntop(r->network, addr1, sizeof(addr1)),
          ip_addr_ntop(r->netmask, addr2, sizeof(addr2)),
          ip_addr_ntop(r->nexthop, addr3, sizeof(addr3)),
          ip_addr_ntop(r->iface->unicast, addr4, sizeof(addr4)),
          NET_IFACE(iface)->dev->name);

    return r;
}

static struct ip_route *ip_route_lookup(ip_addr_t dst) {
    struct ip_route *candidate = NULL;
    for (struct ip_route *r = routes; r; r = r->next) {
        if ((dst & r->netmask) == r->network) {
            // サブネットマスクがより長く一致する経路を選ぶ (Longest match)
            if (!candidate || ntoh32(candidate->netmask) < ntoh32(r->netmask))
                candidate = r;
        }
    }
    return candidate;
}

// NOTE: Must not be call after net_run().
int ip_route_set_default_gateway(struct ip_iface *iface, const char *gateway) {
    ip_addr_t gw;
    if (ip_addr_pton(gateway, &gw) == -1) {
        errorf("ip_addr_pton() failure, addr=%s", gateway);
        return -1;
    }

    if (!ip_route_add(IP_ADDR_ANY, IP_ADDR_ANY, gw, iface)) {
        errorf("ip_route_add() failure");
        return -1;
    }

    return 0;
}

struct ip_iface *ip_route_get_iface(ip_addr_t dst) {
    struct ip_route *r = ip_route_lookup(dst);
    if (!r)
        return NULL;
    return r->iface;
}

struct ip_iface *ip_iface_alloc(const char *unicast, const char *netmask) {
    struct ip_iface *iface = mem_alloc(sizeof(struct ip_iface));
    if (!iface) {
        errorf("mem_alloc() failure");
        return NULL;
    }

    NET_IFACE(iface)->family = NET_IFACE_FAMILY_IP;
    if (ip_addr_pton(unicast, &iface->unicast) == -1) {
        errorf("ip_addr_pton failure: unicast(%s)", unicast);
        mem_free(iface);
        return NULL;
    }
    if (ip_addr_pton(netmask, &iface->netmask) == -1) {
        errorf("ip_addr_pton failure: netmask(%s)", netmask);
        mem_free(iface);
        return NULL;
    }
    iface->broadcast = iface->unicast | (~iface->netmask);

    return iface;
}

// NOTE: Must not be call after net_run().
int ip_iface_register(struct net_dev *dev, struct ip_iface *iface) {
    if (net_dev_add_iface(dev, NET_IFACE(iface)) == -1) {
        errorf("net_dev_add_iface() failure");
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
int ip_proto_register(uint8_t type, ip_proto_handler_t handler) {
    for (struct ip_proto *p = protos; p; p = p->next) {
        if (p->type == type) {
            errorf("already registered, type=0x%04x", type);
            return -1;
        }
    }

    struct ip_proto *p = mem_alloc(sizeof(struct ip_proto));
    if (!p) {
        errorf("mem_alloc() failure");
        return -1;
    }

    p->type = type;
    p->handler = handler;
    p->next = protos;
    protos = p;

    infof("registered, type=%u", p->type);

    return 0;
}

static void ip_input(const uint8_t *data, size_t len, struct net_dev *dev) {
    if (len < IP_HDR_SIZE_MIN) {
        errorf("too short");
        return;
    }

    struct ip_hdr *hdr = (struct ip_hdr *)data;
    size_t hdr_len = IPV4_HEADER_LEN(hdr);
    uint16_t total = ntoh16(hdr->total);

    if (IPV4_VERSION(hdr) != IP_VERSION_IPV4) {
        errorf("only support IPv4");
        return;
    }
    if (len < hdr_len) {
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

    struct ip_iface *iface =
        (struct ip_iface *)net_dev_get_iface(dev, NET_IFACE_FAMILY_IP);
    if (iface == NULL) {
        errorf("net_dev_get_iface() failure: %s", hdr->src);
        return;
    }

    if (!(hdr->dst == iface->unicast || hdr->dst == IP_ADDR_BROADCAST ||
          hdr->dst == iface->broadcast))
        // Destination is for other hosts.
        return;

    char addr[IP_ADDR_STR_LEN];
    debugf("dev=%s, iface=%s, proto=%u, total=%u", dev->name,
           ip_addr_ntop(iface->unicast, addr, sizeof(addr)), hdr->proto, total);
    ip_dump(data, len);

    for (struct ip_proto *p = protos; p; p = p->next) {
        if (p->type == hdr->proto) {
            p->handler(data + hdr_len, total - hdr_len, hdr->src, hdr->dst,
                       iface);
            return;
        }
    }

    // Unsupported protocol
}

static int ip_output_dev(struct ip_iface *iface, const uint8_t *data,
                         size_t len, ip_addr_t dst) {
    uint8_t hwaddr[NET_DEV_ADDR_LEN] = {};
    if (NET_IFACE(iface)->dev->flags & NET_DEV_FLAG_NEEDARP) {
        if (dst == iface->broadcast || dst == IP_ADDR_BROADCAST) {
            memcpy(hwaddr, NET_IFACE(iface)->dev->broadcast,
                   NET_IFACE(iface)->dev->alen);
        } else {
            int ret = arp_resolve(NET_IFACE(iface), dst, hwaddr);
            if (ret != ARP_RESOLVE_FOUND)
                return ret;
        }
    }

    return net_dev_output(NET_IFACE(iface)->dev, NET_PROTO_TYPE_IP, data, len,
                          hwaddr);
}

static ssize_t ip_output_core(struct ip_iface *iface, uint8_t proto,
                              const uint8_t *data, size_t len, ip_addr_t src,
                              ip_addr_t dst, ip_addr_t nexthop, uint16_t id,
                              uint16_t offset) {
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

    return ip_output_dev(iface, buf, total, nexthop);
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
    if (src == IP_ADDR_ANY && dst == IP_ADDR_BROADCAST) {
        errorf("source address is required for broadcast addresses");
        return -1;
    }

    char addr[IP_ADDR_STR_LEN];
    struct ip_route *route = ip_route_lookup(dst);
    if (!route) {
        errorf("no route to host, addr=%s",
               ip_addr_ntop(dst, addr, sizeof(addr)));
        return -1;
    }

    struct ip_iface *iface = route->iface;
    if (src != IP_ADDR_ANY && src != iface->unicast) {
        errorf("unable to output with specified source address, addr=%s",
               ip_addr_ntop(src, addr, sizeof(addr)));
        return -1;
    }

    ip_addr_t nexthop = (route->nexthop != IP_ADDR_ANY) ? route->nexthop : dst;

    if (NET_IFACE(iface)->dev->mtu < IP_HDR_SIZE_MIN + len) {
        errorf("too large, dev=%s, mtu=%u < %zu", NET_IFACE(iface)->dev->name,
               NET_IFACE(iface)->dev->mtu, IP_HDR_SIZE_MIN + len);
        return -1;
    }

    uint16_t id = ip_generate_id();
    if (ip_output_core(iface, proto, data, len, iface->unicast, dst, nexthop,
                       id, 0) == -1) {
        errorf("ip_output_core() failure");
        return -1;
    }

    return len;
}

int ip_init(void) {
    if (net_proto_register(NET_PROTO_TYPE_IP, ip_input) == -1) {
        errorf("net_proto_register() failure");
        return -1;
    }

    return 0;
}