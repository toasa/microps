#include <errno.h>
#include <string.h>
#include <time.h>

#include "net.h"
#include "platform.h"
#include "util.h"

struct irq_entry {
    struct irq_entry *next;
    unsigned int irq;
    irq_handler_t handler;
    int flags;
    char name[16];
    void *dev;
};

// NOTE: If you want to add/delete the entries after intr_run(), you need to
// protect these lists with a mutex.
static struct irq_entry *irqs;

static sigset_t sigmask;

static pthread_t tid;
static pthread_barrier_t barrier;

int intr_register_irq(unsigned int irq, irq_handler_t handler, int flags,
                      const char *name, void *dev) {
    debugf("irq=%u, flags=%d, name=%s", irq, flags, name);

    struct irq_entry *entry;
    for (entry = irqs; entry; entry = entry->next) {
        if (entry->irq == irq) {
            if (entry->flags ^ INTR_IRQ_SHARED || flags ^ INTR_IRQ_SHARED) {
                errorf("conflicts with already registerd IRQs");
                return -1;
            }
        }
    }

    entry = mem_alloc(sizeof(struct irq_entry));
    if (!entry) {
        errorf("mem_alloc() failure");
        return -1;
    }

    entry->irq = irq;
    entry->handler = handler;
    entry->flags = flags;
    entry->dev = dev;
    strncpy(entry->name, name, sizeof(entry->name) - 1);

    entry->next = irqs;
    irqs = entry;

    sigaddset(&sigmask, irq);

    debugf("registered: irq=%u, name=%s", irq, name);

    return 0;
}

int intr_raise_irq(unsigned int irq) {
    return pthread_kill(tid, (int)irq);
}

static int intr_timer_setup(struct itimerspec *interval) {
    timer_t id;
    if (timer_create(CLOCK_REALTIME, NULL, &id) == -1) {
        errorf("timer_create: %s", strerror(errno));
        return -1;
    }
    if (timer_settime(id, 0, interval, NULL) == -1) {
        errorf("timer_settime: %s", strerror(errno));
        return -1;
    }

    return 0;
}

static void *intr_thread(void *arg) {
    const struct timespec ts = {0, 1000 * 1000}; // 1ms
    struct itimerspec interval = {ts, ts};

    debugf("start...");
    pthread_barrier_wait(&barrier);

    if (intr_timer_setup(&interval) == -1) {
        errorf("intr_timer_setup() failure");
        return NULL;
    }

    int terminate = 0;
    while (!terminate) {
        int sig;
        int err = sigwait(&sigmask, &sig);
        if (err) {
            errorf("sigwait() %s", strerror(err));
            break;
        }

        switch (sig) {
        case SIGHUP:
            terminate = 1;
            break;
        case SIGUSR1:
            net_softirq_handler();
            break;
        case SIGALRM:
            net_timer_handler();
            break;
        default:
            for (struct irq_entry *entry = irqs; entry; entry = entry->next) {
                if (entry->irq == (unsigned int)sig) {
                    debugf("irq=%d, name=%s", entry->irq, entry->name);
                    entry->handler(entry->irq, entry->dev);
                }
            }
        }
    }

    debugf("terminated");
    return NULL;
}

int intr_run(void) {
    int err = pthread_sigmask(SIG_BLOCK, &sigmask, NULL);
    if (err) {
        errorf("pthread_sigmask() %s", strerror(err));
        return -1;
    }

    err = pthread_create(&tid, NULL, intr_thread, NULL);
    if (err) {
        errorf("pthread_create() %s", strerror(err));
        return -1;
    }

    pthread_barrier_wait(&barrier);

    return 0;
}

void intr_shutdown(void) {
    if (pthread_equal(tid, pthread_self()) != 0) {
        /* Thread not created. */
        return;
    }

    pthread_kill(tid, SIGHUP);
    pthread_join(tid, NULL);
}

int intr_init(void) {
    tid = pthread_self();
    pthread_barrier_init(&barrier, NULL, 2);

    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGHUP);
    sigaddset(&sigmask, SIGUSR1);
    sigaddset(&sigmask, SIGALRM);

    return 0;
}