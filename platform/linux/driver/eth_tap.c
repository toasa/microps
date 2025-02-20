#define _GNU_SOURCE // for F_SETSIG

#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/poll.h>

#include "driver/eth_tap.h"
#include "eth.h"
#include "net.h"
#include "platform.h"
#include "util.h"

#define CLONE_DEVICE "/dev/net/tun"

#define ETH_TAP_IRQ (INTR_IRQ_BASE + 2)

struct eth_tap {
    char name[IFNAMSIZ];
    int fd;
    unsigned int irq;
};

#define PRIV(x) ((struct eth_tap *)x->priv)

static int eth_tap_addr(struct net_device *dev) {
    // ioctl(sock, SIOCGIFHWADDR) でハードウェアアドレスを取得するために、
    // ソケットをオープンする。
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1) {
        errorf("socket: %s, dev=%s", strerror(errno), dev->name);
        return -1;
    }

    struct ifreq ifr = {};
    strncpy(ifr.ifr_name, PRIV(dev)->name, sizeof(struct ifreq) - 1);

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) == -1) {
        errorf("ioctl [SIOCGIFHWADDR]: %s, dev=%s", strerror(errno), dev->name);
        close(sock);
        return -1;
    }

    memcpy(dev->addr, ifr.ifr_hwaddr.sa_data, ETH_ADDR_LEN);
    close(sock);

    return 0;
}

static int eth_tap_open(struct net_device *dev) {
    struct eth_tap *tap = PRIV(dev);
    tap->fd = open(CLONE_DEVICE, O_RDWR);
    if (tap->fd == -1) {
        errorf("open: %s, dev=%s", strerror(errno), dev->name);
        return -1;
    }

    struct ifreq ifr = {};
    strncpy(ifr.ifr_name, tap->name, sizeof(ifr.ifr_name) - 1);
    // IFF_TAP: TAP モード, IFF_NO_PI: パケット情報ヘッダをつけない
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    if (ioctl(tap->fd, TUNSETIFF, &ifr) == -1) {
        errorf("ioctl [TUNSETIFF]: %s, dev=%s", strerror(errno), dev->name);
        close(tap->fd);
        return -1;
    }

    // Set Asynchronous I/O signal delivery destination.
    if (fcntl(tap->fd, F_SETOWN, getpid()) == -1) {
        errorf("fcntl(F_SETOWN): %s, dev=%s", strerror(errno), dev->name);
        close(tap->fd);
        return -1;
    }
    // Enable Asynchronous I/O.
    if (fcntl(tap->fd, F_SETFL, O_ASYNC) == -1) {
        errorf("fcntl(F_SETFL): %s, dev=%s", strerror(errno), dev->name);
        close(tap->fd);
        return -1;
    }
    // Use other signal instead of SIGIO.
    if (fcntl(tap->fd, F_SETSIG, tap->irq) == -1) {
        errorf("fcntl(F_SETFL): %s, dev=%s", strerror(errno), dev->name);
        close(tap->fd);
        return -1;
    }

    if (memcmp(dev->addr, ETH_ADDR_ANY, ETH_ADDR_LEN) == 0) {
        if (eth_tap_addr(dev) == -1) {
            errorf("eth_tap_addr() failure, dev=%s", dev->name);
            close(tap->fd);
            return -1;
        }
    }

    return 0;
}

static int eth_tap_close(struct net_device *dev) {
    close(PRIV(dev)->fd);
    return 0;
}

static ssize_t eth_tap_write(struct net_device *dev, const uint8_t *frame,
                             size_t flen) {
    return write(PRIV(dev)->fd, frame, flen);
}

static int eth_tap_tx(struct net_device *dev, uint16_t type, const uint8_t *buf,
                      size_t len, const void *dst) {
    return eth_tx_helper(dev, type, buf, len, dst, eth_tap_write);
}

static ssize_t eth_tap_read(struct net_device *dev, uint8_t *buf, size_t size) {
    ssize_t len = read(PRIV(dev)->fd, buf, size);
    if (len <= 0) {
        if (len == -1 && errno != EINTR)
            errorf("read: %s, dev=%s", strerror(errno), dev->name);

        return -1;
    }

    return len;
}

static int eth_tap_isr(unsigned int irq, void *id) {
    struct net_device *dev = (struct net_device *)id;
    struct pollfd pfd = {
        .fd = PRIV(dev)->fd,
        .events = POLLIN,
    };

    while (1) {
        int ret = poll(&pfd, 1, 0);
        if (ret == -1) {
            if (errno == EINTR)
                continue;

            errorf("poll: %s, dev=%s", strerror(errno), dev->name);
            return -1;
        } else if (ret == 0) {
            // No frames to input immediately
            break;
        }

        eth_rx_helper(dev, eth_tap_read);
    }

    return 0;
}

static struct net_device_ops eth_tap_ops = {
    .open = eth_tap_open,
    .close = eth_tap_close,
    .tx = eth_tap_tx,
};

struct net_device *eth_tap_init(const char *name, const char *addr) {
    struct net_device *dev = net_device_alloc();
    if (!dev) {
        errorf("net_device_alloc() failure");
        return NULL;
    }

    eth_setup_helper(dev);
    if (addr) {
        if (eth_addr_pton(addr, dev->addr) == -1) {
            errorf("invalid address, addr=%s", addr);
            return NULL;
        }
    }
    dev->ops = &eth_tap_ops;

    struct eth_tap *tap = memory_alloc(sizeof(struct eth_tap));
    if (!tap) {
        errorf("memory_alloc() failure");
        return NULL;
    }

    strncpy(tap->name, name, sizeof(tap->name) - 1);
    tap->fd = -1;
    tap->irq = ETH_TAP_IRQ;
    dev->priv = tap;

    if (net_device_register(dev) == -1) {
        errorf("net_device_register() failure");
        memory_free(tap);
        return NULL;
    }

    intr_register_irq(tap->irq, eth_tap_isr, INTR_IRQ_SHARED, dev->name, dev);

    infof("eth device initialized, dev=%s", dev->name);

    return dev;
}