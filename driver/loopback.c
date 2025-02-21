#include <string.h>

#include "net.h"
#include "platform.h"
#include "util.h"

#define LOOPBACK_MTU UINT16_MAX
#define LOOPBACK_QUEUE_LIMIT 16
#define LOOPBACK_IRQ (INTR_IRQ_BASE + 1)

#define PRIV(x) ((struct loopback *)x->priv)

struct loopback {
    int irq;
    mutex_t mutex;
    struct queue queue;
};

struct loopback_queue_entry {
    uint16_t type;
    size_t len;
    uint8_t data[];
};

static int loopback_tx(struct net_dev *dev, uint16_t type, const uint8_t *data,
                       size_t len, const void *dst) {
    mutex_lock(&PRIV(dev)->mutex);
    {
        if (PRIV(dev)->queue.len >= LOOPBACK_QUEUE_LIMIT) {
            mutex_unlock(&PRIV(dev)->mutex);
            errorf("queue is full.");
            return -1;
        }

        struct loopback_queue_entry *entry =
            memory_alloc(sizeof(struct loopback_queue_entry) + len);
        if (!entry) {
            mutex_unlock(&PRIV(dev)->mutex);
            errorf("memory_alloc() failure");
            return -1;
        }

        entry->type = type;
        entry->len = len;
        memcpy(entry->data, data, len);

        queue_push(&PRIV(dev)->queue, entry);
    }
    mutex_unlock(&PRIV(dev)->mutex);

    debugf("queue pushed (num: %u), dev=%s, type=0x%04x, len=%zd",
           PRIV(dev)->queue.len, dev->name, type, len);
    debugdump(data, len);

    intr_raise_irq(PRIV(dev)->irq);

    return 0;
}

static int loopback_isr(unsigned int irq, void *id) {
    struct net_dev *dev = (struct net_dev *)id;
    mutex_lock(&PRIV(dev)->mutex);

    while (1) {
        struct loopback_queue_entry *entry = queue_pop(&PRIV(dev)->queue);
        if (!entry)
            break;

        debugf("queue popped (num:%u), dev=%s, type=0x%04x, len=%zd",
               PRIV(dev)->queue.len, dev->name, entry->type, entry->len);
        debugdump(entry->data, entry->len);

        net_input_handler(entry->type, entry->data, entry->len, dev);

        memory_free(entry);
    }

    mutex_unlock(&PRIV(dev)->mutex);

    return 0;
}

static struct net_dev_ops loopback_ops = {
    .tx = loopback_tx,
};

struct net_dev *loopback_init(void) {
    struct net_dev *dev = net_dev_alloc();
    if (!dev) {
        errorf("net_dev_alloc() failure");
        return NULL;
    }

    dev->type = NET_DEV_TYPE_LOOPBACK;
    dev->mtu = LOOPBACK_MTU;
    dev->hlen = 0; /* non header */
    dev->alen = 0; /* non address */
    dev->flags = NET_DEV_FLAG_LOOPBACK;
    dev->ops = &loopback_ops;

    struct loopback *lo = memory_alloc(sizeof(struct loopback));
    if (!lo) {
        errorf("memory_alloc() failure");
        return NULL;
    }

    lo->irq = LOOPBACK_IRQ;
    mutex_init(&lo->mutex);
    queue_init(&lo->queue);

    dev->priv = lo;

    if (net_dev_register(dev) == -1) {
        errorf("net_dev_register() failure");
        return NULL;
    }

    intr_register_irq(LOOPBACK_IRQ, loopback_isr, INTR_IRQ_SHARED, dev->name,
                      dev);

    debugf("initialized, dev=%s", dev->name);

    return dev;
}