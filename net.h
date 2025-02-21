#ifndef NET_H
#define NET_H

#include <stddef.h>
#include <stdint.h>

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

#define NET_DEV_TYPE_DUMMY    0x0000
#define NET_DEV_TYPE_LOOPBACK 0x0001
#define NET_DEV_TYPE_ETHERNET 0x0002

#define NET_DEV_FLAG_UP        0x0001
#define NET_DEV_FLAG_LOOPBACK  0x0010
#define NET_DEV_FLAG_BROADCAST 0x0020
#define NET_DEV_FLAG_P2P       0x0040
#define NET_DEV_FLAG_NEEDARP   0x0100

#define NET_DEV_ADDR_LEN 16

#define NET_DEV_IS_UP(x) ((x)->flags & NET_DEV_FLAG_UP)
#define NET_DEV_STATE(x) (NET_DEV_IS_UP(x) ? "up" : "down")

// NOTE: Use same values as the Ethernet types.
#define NET_PROTO_TYPE_IP   0x0800
#define NET_PROTO_TYPE_ARP  0x0806
#define NET_PROTO_TYPE_IPV6 0x86DD

#define NET_IFACE_FAMILY_IP   1
#define NET_IFACE_FAMILY_IPV6 2

#define NET_IFACE(x) ((struct net_iface *)(x))

struct net_dev {
    struct net_dev *next;

    // If you want to add/delete the entries after net_run(), you need to
    // protect ifaces with a mutex.
    struct net_iface *ifaces;

    unsigned int index;
    char name[IFNAMSIZ];
    uint16_t type;
    uint16_t mtu;
    uint16_t flags;
    uint16_t hlen; /* header length */
    uint16_t alen; /* address length */
    uint8_t addr[NET_DEV_ADDR_LEN];
    union {
        uint8_t peer[NET_DEV_ADDR_LEN];
        uint8_t broadcast[NET_DEV_ADDR_LEN];
    };
    struct net_dev_ops *ops;
    void *priv;
};

struct net_dev_ops {
    int (*open)(struct net_dev *dev);
    int (*close)(struct net_dev *dev);
    int (*tx)(struct net_dev *dev, uint16_t type, const uint8_t *data,
              size_t len, const void *dst);
};

struct net_iface {
    struct net_iface *next;
    struct net_dev *dev; /* back pointer to parent */
    int family;
};

extern struct net_dev *net_dev_alloc(void);
extern int net_dev_register(struct net_dev *dev);
extern int net_dev_add_iface(struct net_dev *dev, struct net_iface *iface);
extern struct net_iface *net_dev_get_iface(struct net_dev *dev, int family);
extern int net_dev_output(struct net_dev *dev, uint16_t type,
                          const uint8_t *data, size_t len, const void *dst);

typedef void (*proto_handler_t)(const uint8_t *data, size_t len,
                                struct net_dev *dev);
extern int net_proto_register(uint16_t type, proto_handler_t hadnler);

// デバイスが受信したパケットを適切なプロトコルスタックへ渡す
extern int net_input_handler(uint16_t type, const uint8_t *data, size_t len,
                             struct net_dev *dev);
extern int net_softirq_handler(void);

extern int net_run(void);
extern void net_shutdown(void);
extern int net_init(void);

#endif