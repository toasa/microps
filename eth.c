#include <stdlib.h>
#include <string.h>

#include "eth.h"
#include "net.h"
#include "util.h"

struct eth_hdr {
    uint8_t dst[ETH_ADDR_LEN];
    uint8_t src[ETH_ADDR_LEN];
    uint16_t type;
};

const uint8_t ETH_ADDR_ANY[ETH_ADDR_LEN] = "\x00\x00\x00\x00\x00\x00";
const uint8_t ETH_ADDR_BROADCAST[ETH_ADDR_LEN] = "\xff\xff\xff\xff\xff\xff";

int eth_addr_pton(const char *p, uint8_t *n) {
    if (!p || !n)
        return -1;

    int i;
    char *ep;
    for (i = 0; i < ETH_ADDR_LEN; i++) {
        long val = strtol(p, &ep, 16);
        if (ep == p || val < 0 || val > 0xff ||
            (i < ETH_ADDR_LEN - 1 && *ep != ':'))
            break;
        n[i] = (uint8_t)val;
        p = ep + 1;
    }

    if (i != ETH_ADDR_LEN || *ep != '\0')
        return -1;

    return 0;
}

char *eth_addr_ntop(const uint8_t *n, char *p, size_t size) {
    if (!n || !p)
        return NULL;

    snprintf(p, size, "%02x:%02x:%02x:%02x:%02x:%02x", n[0], n[1], n[2], n[3],
             n[4], n[5]);
    return p;
}

static void eth_dump(const uint8_t *frame, size_t flen) {
    struct eth_hdr *hdr = (struct eth_hdr *)frame;
    char addr[ETH_ADDR_STR_LEN];

    flockfile(stderr);
    fprintf(stderr, "        src: %s\n",
            eth_addr_ntop(hdr->src, addr, sizeof(addr)));
    fprintf(stderr, "        dst: %s\n",
            eth_addr_ntop(hdr->dst, addr, sizeof(addr)));
    fprintf(stderr, "       type: 0x%04x\n", ntoh16(hdr->type));

#ifdef HEXDUMP
    hexdump(stderr, frame, flen);
#endif

    funlockfile(stderr);
}

int eth_tx_helper(struct net_dev *dev, uint16_t type, const uint8_t *data,
                  size_t len, const void *dst, eth_tx_t tx) {
    uint8_t frame[ETH_FRAME_SIZE_MAX] = {};

    struct eth_hdr *hdr = (struct eth_hdr *)frame;
    memcpy(hdr->dst, dst, ETH_ADDR_LEN);
    memcpy(hdr->src, dev->addr, ETH_ADDR_LEN);
    hdr->type = hton16(type);
    memcpy(hdr + 1, data, len);

    size_t pad = 0;
    if (len < ETH_PAYLOAD_SIZE_MIN)
        pad = ETH_PAYLOAD_SIZE_MIN - len;

    size_t flen = sizeof(struct eth_hdr) + len + pad;

    debugf("dev=%s, type=0x%04x, len=%zu", dev->name, type, flen);
    eth_dump(frame, flen);

    return tx(dev, frame, flen) == (ssize_t)flen ? 0 : -1;
}

int eth_rx_helper(struct net_dev *dev, eth_rx_t rx) {
    uint8_t frame[ETH_FRAME_SIZE_MAX];
    ssize_t flen = rx(dev, frame, sizeof(frame));
    if (flen < (ssize_t)sizeof(struct eth_hdr)) {
        errorf("too short");
        return -1;
    }

    struct eth_hdr *hdr = (struct eth_hdr *)frame;
    if (memcmp(dev->addr, hdr->dst, ETH_ADDR_LEN) != 0) {
        if (memcmp(ETH_ADDR_BROADCAST, hdr->dst, ETH_ADDR_LEN) != 0)
            // For other host, drop frame
            return -1;
    }

    uint16_t type = ntoh16(hdr->type);

    debugf("dev=%s, type=0x%04x, len=%zd", dev->name, type, flen);
    eth_dump(frame, flen);

    return net_input_handler(type, (uint8_t *)(hdr + 1),
                             flen - sizeof(struct eth_hdr), dev);
}

void eth_setup_helper(struct net_dev *dev) {
    dev->type = NET_DEV_TYPE_ETHERNET;
    dev->mtu = ETH_PAYLOAD_SIZE_MAX;
    dev->flags = (NET_DEV_FLAG_BROADCAST | NET_DEV_FLAG_NEEDARP);
    dev->hlen = ETH_HDR_SIZE;
    dev->alen = ETH_ADDR_LEN;
    memcpy(dev->broadcast, ETH_ADDR_BROADCAST, ETH_ADDR_LEN);
}