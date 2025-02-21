#ifndef ETH_H
#define ETH_H

#include <sys/types.h>

#include "net.h"

#define ETH_ADDR_LEN 6
#define ETH_ADDR_STR_LEN 18 /* "xx:xx:xx:xx:xx:xx\0" */

#define ETH_HDR_SIZE 14
#define ETH_FRAME_SIZE_MIN 60   /* without FCS */
#define ETH_FRAME_SIZE_MAX 1514 /* without FCS */
#define ETH_PAYLOAD_SIZE_MIN (ETH_FRAME_SIZE_MIN - ETH_HDR_SIZE)
#define ETH_PAYLOAD_SIZE_MAX (ETH_FRAME_SIZE_MAX - ETH_HDR_SIZE)

// See https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.txt
#define ETH_TYPE_IP 0x0800
#define ETH_TYPE_ARP 0x0806
#define ETH_TYPE_IPV6 0x08DD

extern const uint8_t ETH_ADDR_ANY[ETH_ADDR_LEN];
extern const uint8_t ETH_ADDR_BROADCAST[ETH_ADDR_LEN];

extern int eth_addr_pton(const char *p, uint8_t *n);
extern char *eth_addr_ntop(const uint8_t *n, char *p, size_t size);

typedef ssize_t (*eth_tx_t)(struct net_dev *dev, const uint8_t *data,
                            size_t len);
typedef ssize_t (*eth_rx_t)(struct net_dev *dev, uint8_t *buf, size_t size);
extern int eth_tx_helper(struct net_dev *dev, uint16_t type,
                         const uint8_t *payload, size_t plen, const void *dst,
                         eth_tx_t tx);
extern int eth_rx_helper(struct net_dev *dev, eth_rx_t rx);

extern void eth_setup_helper(struct net_dev *dev);

#endif