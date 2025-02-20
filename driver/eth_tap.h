#ifndef ETH_TAP_H
#define ETH_TAP_H

#include "net.h"

extern struct net_device *eth_tap_init(const char *name, const char *addr);

#endif