#include "net.h"
#include "platform.h"
#include "util.h"

#define DUMMY_MTU UINT16_MAX
#define DUMMY_IRQ INTR_IRQ_BASE

static int dummy_tx(struct net_dev *dev, uint16_t type, const uint8_t *data,
                    size_t len, const void *dst) {
    debugf("dev=%s, type=0x%04x, len=%zu", dev->name, type, len);
    debugdump(data, len);

    /* drop data*/
    intr_raise_irq(DUMMY_IRQ);

    return 0;
}

// ダミー用の割り込みハンドラ
static int dummy_isr(unsigned int irq, void *id) {
    debugf("irq=%u, dev=%s", irq, ((struct net_dev *)id)->name);
    return 0;
}

static struct net_dev_ops dummy_ops = {
    .tx = dummy_tx,
};

struct net_dev *dummy_init(void) {
    struct net_dev *dev = net_dev_alloc();
    if (!dev) {
        errorf("net_dev_alloc() failure");
        return NULL;
    }

    dev->type = NET_DEV_TYPE_DUMMY;
    dev->mtu = DUMMY_MTU;
    dev->hlen = 0; /* non header */
    dev->alen = 0; /* non address */
    dev->ops = &dummy_ops;
    if (net_dev_register(dev) == -1) {
        errorf("net_dev_register() failure");
        return NULL;
    }

    intr_register_irq(DUMMY_IRQ, dummy_isr, INTR_IRQ_SHARED, dev->name, dev);

    debugf("initialized, dev=%s", dev->name);

    return dev;
}