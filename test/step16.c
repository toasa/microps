#include <signal.h>

#include "driver/eth_tap.h"
#include "driver/loopback.h"
#include "icmp.h"
#include "ip.h"
#include "net.h"
#include "test.h"
#include "util.h"

static volatile sig_atomic_t terminate;

static void on_signal(int s) {
    (void)s;
    terminate = 1;
}

static int setup_loopback(void) {
    struct net_dev *dev = loopback_init();
    if (!dev) {
        errorf("loopback_init() failure");
        return -1;
    }

    struct ip_iface *iface = ip_iface_alloc(LOOPBACK_IP_ADDR, LOOPBACK_NETMASK);
    if (!iface) {
        errorf("ip_iface_alloc() failure");
        return -1;
    }

    if (ip_iface_register(dev, iface) == -1) {
        errorf("ip_iface_register() failure");
        return -1;
    }

    return 0;
}

static int setup_ethtap(void) {
    struct net_dev *dev = eth_tap_init(ETHER_TAP_NAME, ETHER_TAP_HW_ADDR);
    if (!dev) {
        errorf("eth_tap_init() failure");
        return -1;
    }

    struct ip_iface *iface =
        ip_iface_alloc(ETHER_TAP_IP_ADDR, ETHER_TAP_NETMASK);
    if (!iface) {
        errorf("ip_iface_alloc() failure");
        return -1;
    }

    if (ip_iface_register(dev, iface) == -1) {
        errorf("ip_iface_register() failure");
        return -1;
    }

    return 0;
}

static int setup(void) {
    signal(SIGINT, on_signal);

    if (net_init() == -1) {
        errorf("net_init() failure");
        return -1;
    }

    if (setup_loopback() == -1) {
        errorf("setup_loopback() failure");
        return -1;
    }
    if (setup_ethtap() == -1) {
        errorf("setup_ethtap() failure");
        return -1;
    }

    if (net_run() == -1) {
        errorf("net_run() failure");
        return -1;
    }

    return 0;
}

static void cleanup(void) { net_shutdown(); }

int main(int argc, char *argv[]) {
    if (setup() == -1) {
        errorf("setup() failure");
        return -1;
    }

    while (!terminate)
        sleep(1);

    cleanup();

    return 0;
}