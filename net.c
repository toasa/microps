#include <string.h>

#include "ip.h"
#include "net.h"
#include "platform.h"
#include "util.h"

struct net_protocol {
    struct net_protocol *next;
    uint16_t type;
    struct queue input_queue;
    protocol_handler_t handler;
};

struct net_protocol_queue_entry {
    struct net_device *dev;
    size_t len;
    uint8_t data[];
};

// NOTE: If you want to add/delete the entries after net_run(),
// you need to protect these lists with a mutex.
static struct net_device *devices;
static struct net_protocol *protocols;

struct net_device *net_device_alloc(void) {
    struct net_device *dev = memory_alloc(sizeof(struct net_device));

    if (!dev) {
        errorf("failure");
        return NULL;
    }

    return dev;
}

// NOTE: Must not be call after net_run().
int net_device_register(struct net_device *dev) {
    static unsigned int index = 0;

    dev->index = index++;
    snprintf(dev->name, sizeof(dev->name), "net%d", dev->index);

    dev->next = devices;
    devices = dev;

    infof("registered, dev=%s, type=0x%04x", dev->name, dev->type);

    return 0;
}

static int net_device_open(struct net_device *dev) {
    if (NET_DEVICE_IS_UP(dev)) {
        errorf("already opend, dev=%s", dev->name);
        return -1;
    }

    if (dev->ops->open) {
        if (dev->ops->open(dev) == -1) {
            errorf("failure, dev=%s", dev->name);
            return -1;
        }
    }

    dev->flags |= NET_DEVICE_FLAG_UP;
    infof("dev=%s, state=%s", dev->name, NET_DEVICE_STATE(dev));

    return 0;
}

static int net_device_close(struct net_device *dev) {
    if (!NET_DEVICE_IS_UP(dev)) {
        errorf("not opened, dev=%s", dev->name);
        return -1;
    }

    if (dev->ops->close) {
        if (dev->ops->close(dev) == -1) {
            errorf("failure, dev=%s", dev->name);
            return -1;
        }
    }

    dev->flags &= ~NET_DEVICE_FLAG_UP;
    infof("dev=%s, state=%s", dev->name, NET_DEVICE_STATE(dev));

    return 0;
}

int net_device_output(struct net_device *dev, uint16_t type,
                      const uint8_t *data, size_t len, const void *dst) {
    if (!NET_DEVICE_IS_UP(dev)) {
        errorf("not linkup, dev=%s", dev->name);
        return -1;
    }

    if (len > dev->mtu) {
        errorf("too large, dev=%s, mtu=%u, len=%zu", dev->name, dev->mtu, len);
        return -1;
    }

    debugf("dev=%s, type=0x%04x, len=%zu", dev->name, type, len);
    debugdump(data, len);

    if (dev->ops->transmit(dev, type, data, len, dst) == -1) {
        errorf("device transmit failure, dev=%s, len=%zu", dev->name, len);
        return -1;
    }

    return 0;
}

// NOTE: Must not be call after net_run()
int net_protocol_register(uint16_t type, protocol_handler_t handler) {
    struct net_protocol *proto;
    for (proto = protocols; proto; proto = proto->next) {
        if (type == proto->type) {
            errorf("aflready registered, type=0x%04x", type);
            return -1;
        }
    }

    proto = memory_alloc(sizeof(struct net_protocol));
    if (!proto) {
        errorf("memory_alloc() failure");
        return -1;
    }

    proto->type = type;
    proto->handler = handler;
    queue_init(&proto->input_queue);

    proto->next = protocols;
    protocols = proto;

    infof("registered, type=0x%04x", type);

    return 0;
}

int net_input_handler(uint16_t type, const uint8_t *data, size_t len,
                      struct net_device *dev) {
    for (struct net_protocol *proto = protocols; proto; proto = proto->next) {
        if (proto->type == type) {
            struct net_protocol_queue_entry *entry =
                memory_alloc(sizeof(struct net_protocol_queue_entry) + len);
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

            return 0;
        }
    }

    warnf("unsupported protocol type=0x%04x", type);

    return 0;
}

int net_run(void) {
    if (intr_run() == -1) {
        errorf("intr_run() failrue");
        return -1;
    }

    debugf("open all devices...");
    for (struct net_device *dev = devices; dev; dev = dev->next)
        net_device_open(dev);

    debugf("running...");

    return 0;
}

void net_shutdown(void) {
    debugf("close all devices...");
    for (struct net_device *dev = devices; dev; dev = dev->next)
        net_device_close(dev);

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

    infof("initialized");

    return 0;
}