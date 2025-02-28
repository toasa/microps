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

static struct ip_iface *setup_ethtap(void) {
    struct net_dev *dev = eth_tap_init(ETHER_TAP_NAME, ETHER_TAP_HW_ADDR);
    if (!dev) {
        errorf("eth_tap_init() failure");
        return NULL;
    }

    struct ip_iface *iface =
        ip_iface_alloc(ETHER_TAP_IP_ADDR, ETHER_TAP_NETMASK);
    if (!iface) {
        errorf("ip_iface_alloc() failure");
        return NULL;
    }

    if (ip_iface_register(dev, iface) == -1) {
        errorf("ip_iface_register() failure");
        return NULL;
    }

    return iface;
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

    struct ip_iface *iface = setup_ethtap();
    if (!iface) {
        errorf("setup_ethtap() failure");
        return -1;
    }
    if (ip_route_set_default_gateway(iface, DEFAULT_GATEWAY) == -1) {
        errorf("ip_route_set_default_gateway() failure");
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

    ip_addr_t src = IP_ADDR_ANY;
    ip_addr_t dst;
    ip_addr_pton("8.8.8.8", &dst);
    uint16_t id = getpid() % UINT16_MAX;
    uint16_t seq = 0;
    uint16_t offset = IP_HDR_SIZE_MIN + ICMP_HDR_SIZE;

    while (!terminate) {
        if (icmp_output(ICMP_TYPE_ECHO, 0, hton32(id << 16 | ++seq),
                        test_data + offset, sizeof(test_data) - offset, src,
                        dst) == -1) {
            errorf("icmp_output() failure");
            break;
        }
        sleep(1);
    }

    cleanup();

    return 0;
}