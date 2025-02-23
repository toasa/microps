#include <stdint.h>
#include <string.h>

#include "arp.h"
#include "eth.h"
#include "ip.h"
#include "util.h"

// See https://www.iana.org/assignments/arp-parameters/arp-parameters.txt
#define ARP_HWTYPE_ETH 0x0001
#define ARP_PROTO_IP ETH_TYPE_IP

#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY 2

struct arp_hdr {
    uint16_t htype; // HW Type
    uint16_t ptype; // Protocol Type
    uint8_t hlen;   // HW Address Size
    uint8_t plen;   // Protocol Address Size
    uint16_t op;    // Operation
};

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

    if (ntoh16(hdr.op) != ARP_OP_REQUEST)
        // Do nothing except arp request.
        return;

    ip_addr_t tpa;
    memcpy(&tpa, msg->tpa, sizeof(tpa));

    struct net_iface *iface = net_dev_get_iface(dev, NET_IFACE_FAMILY_IP);
    if (iface && IP_IFACE(iface)->unicast == tpa)
        arp_reply(iface, (uint8_t *)msg->sha, *(ip_addr_t *)msg->spa, msg->sha);
}

int arp_init(void) {
    if (net_proto_register(NET_PROTO_TYPE_ARP, arp_input) == -1) {
        errorf("net_proto_register() failure");
        return -1;
    }

    return 0;
}