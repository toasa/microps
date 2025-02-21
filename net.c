#include <string.h>

#include "icmp.h"
#include "ip.h"
#include "net.h"
#include "platform.h"
#include "util.h"

struct net_proto {
    struct net_proto *next;
    uint16_t type;
    struct queue input_queue;
    proto_handler_t handler;
};

struct net_proto_queue_entry {
    struct net_dev *dev;
    size_t len;
    uint8_t data[];
};

// NOTE: If you want to add/delete the entries after net_run(),
// you need to protect these lists with a mutex.
static struct net_dev *devs;
static struct net_proto *protos;

struct net_dev *net_dev_alloc(void) {
    struct net_dev *dev = memory_alloc(sizeof(struct net_dev));

    if (!dev) {
        errorf("failure");
        return NULL;
    }

    return dev;
}

// NOTE: Must not be call after net_run().
int net_dev_register(struct net_dev *dev) {
    static unsigned int index = 0;

    dev->index = index++;
    snprintf(dev->name, sizeof(dev->name), "net%d", dev->index);

    dev->next = devs;
    devs = dev;

    infof("registered, dev=%s, type=0x%04x", dev->name, dev->type);

    return 0;
}

static int net_dev_open(struct net_dev *dev) {
    if (NET_DEV_IS_UP(dev)) {
        errorf("already opend, dev=%s", dev->name);
        return -1;
    }

    if (dev->ops->open) {
        if (dev->ops->open(dev) == -1) {
            errorf("failure, dev=%s", dev->name);
            return -1;
        }
    }

    dev->flags |= NET_DEV_FLAG_UP;
    infof("dev=%s, state=%s", dev->name, NET_DEV_STATE(dev));

    return 0;
}

static int net_dev_close(struct net_dev *dev) {
    if (!NET_DEV_IS_UP(dev)) {
        errorf("not opened, dev=%s", dev->name);
        return -1;
    }

    if (dev->ops->close) {
        if (dev->ops->close(dev) == -1) {
            errorf("failure, dev=%s", dev->name);
            return -1;
        }
    }

    dev->flags &= ~NET_DEV_FLAG_UP;
    infof("dev=%s, state=%s", dev->name, NET_DEV_STATE(dev));

    return 0;
}

// NOTE: Must not be call after net_run().
int net_dev_add_iface(struct net_dev *dev, struct net_iface *iface) {
    for (struct net_iface *i = dev->ifaces; i; i = i->next) {
        if (i->family == iface->family) {
            // NOTE: For simplicity, only one iface can be added per family.
            errorf("already exists, dev=%s, family=%d", dev->name, i->family);
            return -1;
        }
    }

    iface->dev = dev;
    iface->next = dev->ifaces;
    dev->ifaces = iface;

    return 0;
}

struct net_iface *net_dev_get_iface(struct net_dev *dev, int family) {
    for (struct net_iface *i = dev->ifaces; i; i = i->next) {
        if (i->family == family)
            return i;
    }

    return NULL;
}

int net_dev_output(struct net_dev *dev, uint16_t type, const uint8_t *data,
                   size_t len, const void *dst) {
    if (!NET_DEV_IS_UP(dev)) {
        errorf("not linkup, dev=%s", dev->name);
        return -1;
    }

    if (len > dev->mtu) {
        errorf("too large, dev=%s, mtu=%u, len=%zu", dev->name, dev->mtu, len);
        return -1;
    }

    debugf("dev=%s, type=0x%04x, len=%zu", dev->name, type, len);
    debugdump(data, len);

    if (dev->ops->tx(dev, type, data, len, dst) == -1) {
        errorf("device tx failure, dev=%s, len=%zu", dev->name, len);
        return -1;
    }

    return 0;
}

// NOTE: Must not be call after net_run()
int net_proto_register(uint16_t type, proto_handler_t handler) {
    struct net_proto *proto;
    for (proto = protos; proto; proto = proto->next) {
        if (type == proto->type) {
            errorf("aflready registered, type=0x%04x", type);
            return -1;
        }
    }

    proto = memory_alloc(sizeof(struct net_proto));
    if (!proto) {
        errorf("memory_alloc() failure");
        return -1;
    }

    proto->type = type;
    proto->handler = handler;
    queue_init(&proto->input_queue);

    proto->next = protos;
    protos = proto;

    infof("registered, type=0x%04x", type);

    return 0;
}

int net_input_handler(uint16_t type, const uint8_t *data, size_t len,
                      struct net_dev *dev) {
    for (struct net_proto *proto = protos; proto; proto = proto->next) {
        if (proto->type == type) {
            struct net_proto_queue_entry *entry =
                memory_alloc(sizeof(struct net_proto_queue_entry) + len);
            if (!entry) {
                errorf("memory_alloc() failure");
                return -1;
            }

            entry->dev = dev;
            entry->len = len;
            memcpy(entry->data, data, len);

            queue_push(&proto->input_queue, entry);

            debugf("queue pushed (num:%u), dev=%s, type=0x%04x, len=%zu",
                   proto->input_queue.len, dev->name, type, len);
            debugdump(data, len);

            intr_raise_irq(INTR_IRQ_SOFTIRQ);

            return 0;
        }
    }

    warnf("unsupported protocol type=0x%04x", type);

    return 0;
}

int net_softirq_handler(void) {
    for (struct net_proto *proto = protos; proto; proto = proto->next) {
        while (1) {
            struct net_proto_queue_entry *entry =
                queue_pop(&proto->input_queue);
            if (!entry)
                break;

            debugf("queue poped (num:%u), dev=%s, type=0x%04x, len=%zu",
                   proto->input_queue.len, entry->dev->name, proto->type,
                   entry->len);
            debugdump(entry->data, entry->len);

            proto->handler(entry->data, entry->len, entry->dev);

            memory_free(entry);
        }
    }

    return 0;
}

int net_run(void) {
    if (intr_run() == -1) {
        errorf("intr_run() failrue");
        return -1;
    }

    debugf("open all devices...");
    for (struct net_dev *dev = devs; dev; dev = dev->next)
        net_dev_open(dev);

    debugf("running...");

    return 0;
}

void net_shutdown(void) {
    debugf("close all devices...");
    for (struct net_dev *dev = devs; dev; dev = dev->next)
        net_dev_close(dev);

    intr_shutdown();

    debugf("shutdown");
}

int net_init(void) {
    if (intr_init() == -1) {
        errorf("intr_init() failure");
        return -1;
    }

    if (ip_init() == -1) {
        errorf("ip_init() failure");
        return -1;
    }

    if (icmp_init() == -1) {
        errorf("icmp_init() failure");
        return -1;
    }

    infof("initialized");

    return 0;
}