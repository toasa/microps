#include <stdbool.h>
#include <string.h>

#include "ip.h"
#include "platform.h"
#include "udp.h"
#include "util.h"

#define UDP_PCB_SIZE 16

#define UDP_PCB_STATE_FREE    0
#define UDP_PCB_STATE_OPEN    1
#define UDP_PCB_STATE_CLOSING 2

// For UDP's checksum calculation
struct pseudo_hdr {
    uint32_t src;
    uint32_t dst;
    uint8_t zero;
    uint8_t proto;
    uint16_t len;
};

struct udp_hdr {
    uint16_t src;
    uint16_t dst;
    uint16_t len;
    uint16_t chksum;
};

struct udp_pcb {
    int state;
    struct ip_endpoint local;
    struct queue recv_q;
};

struct udp_queue_entry {
    struct ip_endpoint foreign;
    uint16_t len;
    uint8_t data[];
};

static mutex_t mutex = MUTEX_INITIALIZER;
static struct udp_pcb pcbs[UDP_PCB_SIZE];

static void udp_dump(const uint8_t *data, size_t len) {
    struct udp_hdr *hdr = (struct udp_hdr *)data;

    flockfile(stderr);
    fprintf(stderr, "        src: %u\n", ntoh16(hdr->src));
    fprintf(stderr, "        dst: %u\n", ntoh16(hdr->dst));
    fprintf(stderr, "        len: %u\n", ntoh16(hdr->len));
    fprintf(stderr, "      cksum: 0x%04x\n", ntoh16(hdr->chksum));
#ifdef HEXDUMP
    hexdump(srderr, data, len);
#endif
    funlockfile(stderr);
}

/*
 * UDP Protocol Control Block (PCB)
 *
 * NOTE: UDP PCB functions must be called after mutex locked
 */

static struct udp_pcb *udp_pcb_alloc(void) {
    for (struct udp_pcb *pcb = pcbs; pcb < tailof(pcbs); pcb++) {
        if (pcb->state == UDP_PCB_STATE_FREE) {
            pcb->state = UDP_PCB_STATE_OPEN;
            return pcb;
        }
    }
    return NULL;
}

static void udp_pcb_release(struct udp_pcb *pcb) {
    pcb->state = UDP_PCB_STATE_FREE;
    pcb->local.addr = IP_ADDR_ANY;
    pcb->local.port = 0;

    struct queue_entry *e;
    while ((e = queue_pop(&pcb->recv_q)))
        mem_free(e);
}

static struct udp_pcb *udp_pcb_select(ip_addr_t addr, uint16_t port) {
    for (struct udp_pcb *pcb = pcbs; pcb < tailof(pcbs); pcb++) {
        if (pcb->state == UDP_PCB_STATE_OPEN) {
            bool is_ip_match = pcb->local.addr == IP_ADDR_ANY ||
                               addr == IP_ADDR_ANY || pcb->local.addr == addr;
            bool is_port_match = pcb->local.port == port;
            if (is_ip_match && is_port_match)
                return pcb;
        }
    }
    return NULL;
}

static struct udp_pcb *udp_pcb_get(int id) {
    if (id < 0 || (int)countof(pcbs) <= id)
        return NULL;

    struct udp_pcb *pcb = &pcbs[id];
    if (pcb->state != UDP_PCB_STATE_OPEN)
        return NULL;

    return pcb;
}

static int udp_pcb_id(struct udp_pcb *pcb) { return indexof(pcbs, pcb); }

static void udp_input(const uint8_t *data, size_t len, ip_addr_t src,
                      ip_addr_t dst, struct ip_iface *iface) {
    if (len < sizeof(struct udp_hdr)) {
        errorf("too short");
        return;
    }

    struct udp_hdr *hdr = (struct udp_hdr *)data;
    if (len != ntoh16(hdr->len)) {
        errorf("length mismatch: len=%zu, hdr->len=%u", len, ntoh16(hdr->len));
        return;
    }

    struct pseudo_hdr phdr = {
        .src = src,
        .dst = dst,
        .zero = 0,
        .proto = IP_PROTO_UDP,
        .len = hton16(len),
    };
    // 擬似ヘッダのチェックサムを計算した後で、残りのUDPパケット
    // （UDPヘッダ＋UDPペイロード） のチェックサムを計算するため、
    // 擬似ヘッダの計算結果はビット反転しておく。
    uint16_t cksum = ~cksum16((uint16_t *)&phdr, sizeof(phdr), 0);
    if (cksum16((uint16_t *)hdr, len, cksum) != 0) {
        errorf("checksum error");
        return;
    }

    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];
    size_t udp_payload_len = len - sizeof(struct udp_hdr);
    debugf("%s:%d => %s:%d, len=%zu (payload=%zu)",
           ip_addr_ntop(src, addr1, sizeof(addr1)), ntoh16(hdr->src),
           ip_addr_ntop(dst, addr2, sizeof(addr2)), ntoh16(hdr->dst), len,
           udp_payload_len);
    udp_dump(data, len);

    mutex_lock(&mutex);
    struct udp_pcb *pcb = udp_pcb_select(dst, hdr->dst);
    if (!pcb) {
        mutex_unlock(&mutex);
        return;
    }
    struct udp_queue_entry *e =
        mem_alloc(sizeof(struct udp_queue_entry) + udp_payload_len);
    if (!e) {
        errorf("mem_alloc() failure");
        return;
    }
    e->foreign.addr = src;
    e->foreign.port = hdr->src;
    e->len = udp_payload_len;
    memcpy(e->data, hdr + 1, udp_payload_len);
    queue_push(&pcb->recv_q, e);
    debugf("queue pushed: id=%d, num=%d", udp_pcb_id(pcb), pcb->recv_q.len);
    mutex_unlock(&mutex);
}

ssize_t udp_output(struct ip_endpoint *src, struct ip_endpoint *dst,
                   const uint8_t *data, size_t len) {
    if (IP_PAYLOAD_SIZE_MAX - sizeof(struct udp_hdr) < len) {
        errorf("too long");
        return -1;
    }

    uint16_t udp_datagram_len = sizeof(struct udp_hdr) + len;

    // Create pseudo header for UDP checksum calculation.
    struct pseudo_hdr phdr = {
        .src = src->addr,
        .dst = dst->addr,
        .zero = 0,
        .proto = IP_PROTO_UDP,
        .len = hton16(udp_datagram_len),
    };
    uint16_t cksum = ~cksum16((uint16_t *)&phdr, sizeof(struct pseudo_hdr), 0);

    // Create UDP Header and datagram.
    uint8_t buf[IP_PAYLOAD_SIZE_MAX] = {};
    struct udp_hdr *hdr = (struct udp_hdr *)buf;
    hdr->src = src->port;
    hdr->dst = dst->port;
    hdr->len = hton16(udp_datagram_len);
    memcpy(hdr + 1, data, len);

    // Calculate remaining checksum (for UDP header and datagram).
    hdr->chksum = cksum16((uint16_t *)hdr, udp_datagram_len, cksum);

    char ep1[IP_ENDPOINT_STR_LEN];
    char ep2[IP_ENDPOINT_STR_LEN];
    debugf("%s => %s, len=%zu, (payload=%zu)",
           ip_endpoint_ntop(src, ep1, sizeof(ep1)),
           ip_endpoint_ntop(dst, ep2, sizeof(ep2)), udp_datagram_len, len);
    udp_dump((uint8_t *)hdr, udp_datagram_len);

    ip_output(IP_PROTO_UDP, buf, udp_datagram_len, src->addr, dst->addr);

    return len;
}

int udp_init(void) {
    if (ip_proto_register(IP_PROTO_UDP, udp_input) == -1) {
        errorf("ip_proto_register() failure");
        return -1;
    }

    return 0;
}

/*
 * UDP User Commands
 */

int udp_open(void) {
    mutex_lock(&mutex);

    struct udp_pcb *pcb = udp_pcb_alloc();
    if (!pcb) {
        errorf("ubp_pcb_alloc() failure");
        mutex_unlock(&mutex);
        return -1;
    }

    int id = udp_pcb_id(pcb);

    mutex_unlock(&mutex);

    return id;
}

int udp_close(int id) {
    mutex_lock(&mutex);

    struct udp_pcb *pcb = udp_pcb_get(id);
    if (!pcb) {
        errorf("udp_pcb_get() failure, id=%d", id);
        mutex_unlock(&mutex);
        return -1;
    }

    udp_pcb_release(pcb);
    mutex_unlock(&mutex);

    return 0;
}

int udp_bind(int id, struct ip_endpoint *local) {
    mutex_lock(&mutex);

    struct udp_pcb *pcb = udp_pcb_get(id);
    if (!pcb) {
        errorf("pcb not found, id=%d", id);
        mutex_unlock(&mutex);
        return -1;
    }

    char ep1[IP_ENDPOINT_STR_LEN];
    char ep2[IP_ENDPOINT_STR_LEN];

    struct udp_pcb *exist = udp_pcb_select(local->addr, local->port);
    if (exist) {
        errorf("already in use, id=%d, want=%s, exist=%s", id,
               ip_endpoint_ntop(local, ep1, sizeof(ep1)),
               ip_endpoint_ntop(&exist->local, ep2, sizeof(ep2)));
        mutex_unlock(&mutex);
        return -1;
    }

    pcb->local = *local;

    mutex_unlock(&mutex);

    debugf("bound, id=%d, local=%s", id,
           ip_endpoint_ntop(&pcb->local, ep1, sizeof(ep1)));

    return 0;
}