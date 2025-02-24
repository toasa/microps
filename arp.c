#include <stdint.h>
#include <string.h>
#include <sys/time.h>

#include "arp.h"
#include "eth.h"
#include "ip.h"
#include "platform.h"
#include "util.h"

// See https://www.iana.org/assignments/arp-parameters/arp-parameters.txt
#define ARP_HWTYPE_ETH 0x0001
#define ARP_PROTO_IP ETH_TYPE_IP

#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY 2

#define ARP_CACHE_SIZE 32

#define ARP_CACHE_STATE_FREE 0
#define ARP_CACHE_STATE_INCOMP 1
#define ARP_CACHE_STATE_RESOLVED 2
#define ARP_CACHE_STATE_STATIC 3

struct arp_hdr {
    uint16_t htype; // HW Type
    uint16_t ptype; // Protocol Type
    uint8_t hlen;   // HW Address Size
    uint8_t plen;   // Protocol Address Size
    uint16_t op;    // Operation
};

struct arp_cache {
    unsigned char state;
    ip_addr_t pa;
    uint8_t ha[ETH_ADDR_LEN];
    struct timeval timestamp;
};

static mutex_t mutex = MUTEX_INITIALIZER;
static struct arp_cache caches[ARP_CACHE_SIZE];

struct arp_eth_ip {
    struct arp_hdr hdr;
    uint8_t sha[ETH_ADDR_LEN]; // Sender HW Address
    uint8_t spa[IP_ADDR_LEN];  // Sender Protocol Address
    uint8_t tha[ETH_ADDR_LEN]; // Target HW Address
    uint8_t tpa[IP_ADDR_LEN];  // Target Protocol Address
};

static char *arp_opcode_ntoa(uint16_t opcode) {
    switch (ntoh16(opcode)) {
    case ARP_OP_REQUEST:
        return "Request";
    case ARP_OP_REPLY:
        return "Reply";
    }
    return "Unknown";
}

static void arp_dump(const uint8_t *data, size_t len) {
    struct arp_eth_ip *msg = (struct arp_eth_ip *)data;
    char addr[128];

    flockfile(stderr);
    fprintf(stderr, "        htype: 0x%04x\n", ntoh16(msg->hdr.htype));
    fprintf(stderr, "        ptype: 0x%04x\n", ntoh16(msg->hdr.ptype));
    fprintf(stderr, "         hlen: %u\n", msg->hdr.hlen);
    fprintf(stderr, "         plen: %u\n", msg->hdr.plen);
    fprintf(stderr, "           op: %u (%s)\n", ntoh16(msg->hdr.op),
            arp_opcode_ntoa(msg->hdr.op));
    fprintf(stderr, "          sha: %s\n",
            eth_addr_ntop(msg->sha, addr, sizeof(addr)));
    fprintf(stderr, "          spa: %s\n",
            ip_addr_ntop(*(ip_addr_t *)msg->spa, addr, sizeof(addr)));
    fprintf(stderr, "          tha: %s\n",
            eth_addr_ntop(msg->tha, addr, sizeof(addr)));
    fprintf(stderr, "          tpa: %s\n",
            ip_addr_ntop(*(ip_addr_t *)msg->tpa, addr, sizeof(addr)));
#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

// Arp Cache
//
// NOTE: ARP Cache functions must be called after mutex locked

static void arp_cache_delete(struct arp_cache *cache) {
    char addr1[IP_ADDR_STR_LEN];
    char addr2[ETH_ADDR_STR_LEN];
    debugf("DELETE: pa=%s, ha=%s",
           ip_addr_ntop(cache->pa, addr1, sizeof(addr1)),
           eth_addr_ntop(cache->ha, addr2, sizeof(addr2)));

    cache->state = ARP_CACHE_STATE_FREE;
    cache->pa = 0;
    memset(cache->ha, 0, sizeof(cache->ha));
    timerclear(&cache->timestamp);
}

static struct arp_cache *arp_cache_alloc(void) {
    struct arp_cache *oldest = NULL;
    for (struct arp_cache *c = caches; c < tailof(caches); c++) {
        if (c->state == ARP_CACHE_STATE_FREE)
            return c;
        if (!oldest || timercmp(&c->timestamp, &oldest->timestamp, <))
            oldest = c;
    }

    arp_cache_delete(oldest);

    return oldest;
}

static struct arp_cache *arp_cache_select(ip_addr_t pa) {
    for (struct arp_cache *c = caches; c < tailof(caches); c++) {
        if (c->state != ARP_CACHE_STATE_FREE && c->pa == pa)
            return c;
    }

    return NULL;
}

static struct arp_cache *arp_cache_update(ip_addr_t pa, const uint8_t *ha) {
    struct arp_cache *c = arp_cache_select(pa);
    if (!c)
        return NULL;

    c->state = ARP_CACHE_STATE_RESOLVED;
    memcpy(c->ha, ha, sizeof(c->ha));
    gettimeofday(&c->timestamp, NULL);

    char addr1[IP_ADDR_STR_LEN];
    char addr2[ETH_ADDR_STR_LEN];

    debugf("UPDATE: pa=%s, ha=%s", ip_addr_ntop(pa, addr1, sizeof(addr1)),
           eth_addr_ntop(ha, addr2, sizeof(addr2)));
    return c;
}

static struct arp_cache *arp_cache_insert(ip_addr_t pa, const uint8_t *ha) {
    struct arp_cache *c = arp_cache_alloc();
    if (!c)
        return NULL;

    c->state = ARP_CACHE_STATE_RESOLVED;
    c->pa = pa;
    memcpy(c->ha, ha, sizeof(c->ha));
    gettimeofday(&c->timestamp, NULL);

    char addr1[IP_ADDR_STR_LEN];
    char addr2[ETH_ADDR_STR_LEN];
    debugf("INSERT: pa=%s, ha=%s", ip_addr_ntop(c->pa, addr1, sizeof(addr1)),
           eth_addr_ntop(c->ha, addr2, sizeof(addr2)));

    return c;
}

static int arp_reply(struct net_iface *iface, const uint8_t *tha, ip_addr_t tpa,
                     const uint8_t *dst) {
    struct arp_hdr hdr = {
        .htype = hton16(ARP_HWTYPE_ETH),
        .ptype = hton16(ARP_PROTO_IP),
        .hlen = ETH_ADDR_LEN,
        .plen = IP_ADDR_LEN,
        .op = hton16(ARP_OP_REPLY),
    };

    struct arp_eth_ip reply = {};
    memcpy(reply.tha, tha, sizeof(reply.tha));
    memcpy(reply.tpa, &tpa, sizeof(reply.tpa));
    memcpy(reply.sha, iface->dev->addr, sizeof(reply.sha));
    memcpy(reply.spa, &IP_IFACE(iface)->unicast, sizeof(reply.spa));
    reply.hdr = hdr;

    debugf("dev=%s, len=%zu", iface->dev->name, sizeof(struct arp_eth_ip));
    arp_dump((uint8_t *)&reply, sizeof(reply));

    return net_dev_output(iface->dev, ETH_TYPE_ARP, (uint8_t *)&reply,
                          sizeof(reply), dst);
}

static void arp_input(const uint8_t *data, size_t len, struct net_dev *dev) {
    if (len < sizeof(struct arp_eth_ip)) {
        errorf("too short");
        return;
    }

    struct arp_eth_ip *msg = (struct arp_eth_ip *)data;
    struct arp_hdr hdr = msg->hdr;

    if (ntoh16(hdr.htype) != ARP_HWTYPE_ETH || msg->hdr.hlen != ETH_ADDR_LEN) {
        errorf("my arp supports only eth");
        return;
    }
    if (ntoh16(hdr.ptype) != ARP_PROTO_IP || msg->hdr.plen != IP_ADDR_LEN) {
        errorf("my arp supports only IP");
        return;
    }

    debugf("dev=%s, len=%zu", dev->name, len);
    arp_dump(data, len);

    ip_addr_t spa, tpa;
    memcpy(&spa, msg->spa, sizeof(spa));
    memcpy(&tpa, msg->tpa, sizeof(tpa));

    int marge = 0;
    mutex_lock(&mutex);
    if (arp_cache_update(spa, msg->sha))
        marge = 1;
    mutex_unlock(&mutex);

    struct net_iface *iface = net_dev_get_iface(dev, NET_IFACE_FAMILY_IP);
    if (iface && IP_IFACE(iface)->unicast == tpa) {
        if (!marge) {
            mutex_lock(&mutex);
            arp_cache_insert(spa, msg->sha);
            mutex_unlock(&mutex);
        }

        arp_reply(iface, (uint8_t *)msg->sha, spa, msg->sha);
    }
}

int arp_resolve(struct net_iface *iface, ip_addr_t pa, uint8_t *ha) {
    if (iface->dev->type != NET_DEV_TYPE_ETHERNET) {
        debugf("unsupported hardware address type");
        return ARP_RESOLVE_ERROR;
    }
    if (iface->family != NET_IFACE_FAMILY_IP) {
        debugf("unsupported protocol address type");
        return ARP_RESOLVE_ERROR;
    }

    char addr1[IP_ADDR_STR_LEN];
    char addr2[ETH_ADDR_STR_LEN];

    mutex_lock(&mutex);
    struct arp_cache *c = arp_cache_select(pa);
    if (!c) {
        debugf("arp cache not found, pa=%s",
               ip_addr_ntop(pa, addr1, sizeof(addr1)));
        mutex_unlock(&mutex);
        return ARP_RESOLVE_ERROR;
    }
    memcpy(ha, c->ha, ETH_ADDR_LEN);
    mutex_unlock(&mutex);

    debugf("arp resolved, pa=%s, ha=%s", ip_addr_ntop(pa, addr1, sizeof(addr1)),
           eth_addr_ntop(ha, addr2, sizeof(addr2)));
    return ARP_RESOLVE_FOUND;
}

int arp_init(void) {
    if (net_proto_register(NET_PROTO_TYPE_ARP, arp_input) == -1) {
        errorf("net_proto_register() failure");
        return -1;
    }

    return 0;
}