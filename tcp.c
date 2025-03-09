#include <stdio.h>
#include <string.h>

#include "ip.h"
#include "platform.h"
#include "tcp.h"
#include "util.h"

#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_URG 0x20

#define TCP_FLAG_IS(x, y) ((x & 0x3f) == (y))
#define TCP_FLAG_ISSET(x, y) ((x & 0x3f) & (y) ? 1 : 0)

#define TCP_PCB_SIZE 16

#define TCP_PCB_STATE_FREE 0
#define TCP_PCB_STATE_CLOSED 1
#define TCP_PCB_STATE_LISTEN 2
#define TCP_PCB_STATE_SYN_SENT 3
#define TCP_PCB_STATE_SYN_RECEIVED 4
#define TCP_PCB_STATE_ESTABLISHED 5
#define TCP_PCB_STATE_FIN_WAIT1 6
#define TCP_PCB_STATE_FIN_WAIT2 7
#define TCP_PCB_STATE_CLOSING 8
#define TCP_PCB_STATE_TIME_WAIT 9
#define TCP_PCB_STATE_CLOSE_WAIT 10
#define TCP_PCB_STATE_LAST_ACK 11

struct pseudo_hdr {
    uint32_t src;
    uint32_t dst;
    uint8_t zero;
    uint8_t proto;
    uint16_t len;
};

struct tcp_hdr {
    uint16_t src;
    uint16_t dst;
    uint32_t seqno;
    uint32_t ackno;
    uint8_t off;
    uint8_t flag;
    uint16_t wnd;
    uint16_t cksum;
    uint16_t urgp;
};

struct tcp_segment_info {
    uint32_t seq;
    uint32_t ack;
    uint16_t len;
    uint16_t wnd;
    uint16_t urgp;
};

struct tcp_pcb {
    int state;

    struct ip_endpoint local;
    struct ip_endpoint foreign;

    struct {
        uint32_t nxt;  // next
        uint32_t una;  // unacknowledged
        uint16_t wnd;  // window
        uint16_t urgp; // urgent pointer
        uint32_t wl1;  // segment sequence number used for last window update
        uint32_t
            wl2; // segement acknowledgment number used for last window update
    } snd;       // 送信時に必要な情報

    uint32_t iss; // Initial send sequence number

    struct {
        uint32_t nxt;  // next
        uint16_t wnd;  // window
        uint16_t urgp; // urgent pointer
    } rcv;             // 受信時に必要な情報

    uint32_t irs; // Initial receive sequence number

    uint16_t mtu;
    uint16_t mss; // Maximum segment size
    uint8_t recv_buf[65535];

    struct sched_ctx ctx;
};

static mutex_t mutex = MUTEX_INITIALIZER;
static struct tcp_pcb pcbs[TCP_PCB_SIZE];

static char *tcp_flag_ntoa(uint8_t flag) {
    static char str[9];

    snprintf(str, sizeof(str), "--%c%c%c%c%c%c",
             TCP_FLAG_ISSET(flag, TCP_FLAG_URG) ? 'U' : '-',
             TCP_FLAG_ISSET(flag, TCP_FLAG_ACK) ? 'A' : '-',
             TCP_FLAG_ISSET(flag, TCP_FLAG_PSH) ? 'P' : '-',
             TCP_FLAG_ISSET(flag, TCP_FLAG_RST) ? 'R' : '-',
             TCP_FLAG_ISSET(flag, TCP_FLAG_SYN) ? 'S' : '-',
             TCP_FLAG_ISSET(flag, TCP_FLAG_FIN) ? 'F' : '-');

    return str;
}

static void tcp_dump(const uint8_t *data, size_t len) {
    struct tcp_hdr *hdr = (struct tcp_hdr *)data;

    flockfile(stderr);
    fprintf(stderr, "        src: %u\n", ntoh16(hdr->src));
    fprintf(stderr, "        dst: %u\n", ntoh16(hdr->dst));
    fprintf(stderr, "      seqno: %u\n", ntoh32(hdr->seqno));
    fprintf(stderr, "      ackno: %u\n", ntoh32(hdr->ackno));
    fprintf(stderr, "        off: 0x%02x (%d)\n", hdr->off,
            (hdr->off >> 4) << 2);
    fprintf(stderr, "       flag: 0x%02x (%s)\n", hdr->flag,
            tcp_flag_ntoa(hdr->flag));
    fprintf(stderr, "        wnd: %u\n", ntoh16(hdr->wnd));
    fprintf(stderr, "      cksum: 0x%04x\n", ntoh16(hdr->cksum));
    fprintf(stderr, "       urgp: %u\n", ntoh16(hdr->urgp));
#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

/*
 * TCP Protocol Control Block (PCB)
 *
 * NOTE: TCP PCB functions must be called after mutex locked.
 */

static struct tcp_pcb *tcp_pcb_alloc(void) {
    for (struct tcp_pcb *pcb = pcbs; pcb < tailof(pcbs); pcb++) {
        if (pcb->state == TCP_PCB_STATE_FREE) {
            pcb->state = TCP_PCB_STATE_CLOSED;
            sched_ctx_init(&pcb->ctx);
            return pcb;
        }
    }

    return NULL;
}

static void tcp_pcb_release(struct tcp_pcb *pcb) {
    if (sched_ctx_destroy(&pcb->ctx) == -1) {
        sched_wakeup(&pcb->ctx);
        return;
    }

    char ep1[IP_ENDPOINT_STR_LEN];
    char ep2[IP_ENDPOINT_STR_LEN];

    debugf("released, local=%s, foreign=%s",
           ip_endpoint_ntop(&pcb->local, ep1, sizeof(ep1)),
           ip_endpoint_ntop(&pcb->foreign, ep2, sizeof(ep2)));

    memset(pcb, 0, sizeof(struct tcp_pcb));
}

static struct tcp_pcb *tcp_pcb_select(struct ip_endpoint *local,
                                      struct ip_endpoint *foreign) {
    struct tcp_pcb *listen_pcb = NULL;

    for (struct tcp_pcb *pcb = pcbs; pcb < tailof(pcbs); pcb++) {
        if ((pcb->local.addr == IP_ADDR_ANY ||
             pcb->local.addr == local->addr) &&
            pcb->local.port == local->port) {
            if (!foreign)
                return pcb;

            if (pcb->foreign.addr == foreign->addr &&
                pcb->foreign.port == foreign->port)
                return pcb;

            if (pcb->state == TCP_PCB_STATE_LISTEN) {
                if (pcb->foreign.addr == IP_ADDR_ANY && pcb->foreign.port == 0)
                    // 外部アドレスを指定せずに LISTEN
                    // する場合、すべての外部アドレスにマッチする
                    listen_pcb = pcb;
            }
        }
    }

    return listen_pcb;
}

static struct tcp_pcb *tcp_pcb_get(int id) {
    if (id < 0 || (int)countof(pcbs) <= id)
        return NULL;

    struct tcp_pcb *pcb = &pcbs[id];
    if (pcb->state == TCP_PCB_STATE_FREE)
        return NULL;

    return pcb;
}

static int tcp_pcb_id(struct tcp_pcb *pcb) { return indexof(pcbs, pcb); }

static ssize_t tcp_output_segment(uint32_t seq, uint32_t ack, uint8_t flag,
                                  uint16_t wnd, uint8_t *data, size_t len,
                                  struct ip_endpoint *local,
                                  struct ip_endpoint *foreign) {
    size_t hdr_len = sizeof(struct tcp_hdr);

    struct pseudo_hdr p_hdr = {
        .src = local->addr,
        .dst = foreign->addr,
        .proto = IP_PROTO_TCP,
        .len = hton16(hdr_len + len),
    };

    uint16_t cksum = ~cksum16((uint16_t *)&p_hdr, sizeof(struct pseudo_hdr), 0);

    uint8_t buf[IP_PAYLOAD_SIZE_MAX] = {};
    struct tcp_hdr *hdr = (struct tcp_hdr *)buf;
    hdr->src = local->port;
    hdr->dst = foreign->port;
    hdr->seqno = hton32(seq);
    hdr->ackno = hton32(ack);
    hdr->off = (hdr_len >> 2) << 4;
    hdr->flag = flag;
    hdr->wnd = hton16(wnd);
    memcpy(hdr + 1, data, len);

    hdr->cksum = cksum16((uint16_t *)hdr, hdr_len + len, cksum);

    char ep1[IP_ENDPOINT_STR_LEN];
    char ep2[IP_ENDPOINT_STR_LEN];
    debugf("%s => %s, len=%zu (payload=%zu)",
           ip_endpoint_ntop(local, ep1, sizeof(ep1)),
           ip_endpoint_ntop(foreign, ep2, sizeof(ep2)), hdr_len + len, len);
    tcp_dump((uint8_t *)hdr, hdr_len + len);

    ip_output(IP_PROTO_TCP, buf, hdr_len + len, local->addr, foreign->addr);

    return len;
}

static ssize_t tcp_ouput(struct tcp_pcb *pcb, uint8_t flag, uint8_t *data,
                         size_t len) {
    uint32_t seq = pcb->snd.nxt;

    if (TCP_FLAG_ISSET(flag, TCP_FLAG_SYN))
        seq = pcb->iss;

    if (TCP_FLAG_ISSET(flag, TCP_FLAG_SYN | TCP_FLAG_FIN) || len) {
        // TODO: add retransmission queue
    }

    return tcp_output_segment(seq, pcb->rcv.nxt, flag, pcb->rcv.wnd, data, len,
                              &pcb->local, &pcb->foreign);
}

// RFC793- section 3.9 [Event Processing > SEGMENT ARRIVES]
static void tcp_segment_arrives(struct tcp_segment_info *seg, uint8_t flags,
                                uint8_t *data, size_t len,
                                struct ip_endpoint *local,
                                struct ip_endpoint *foreign) {
    struct tcp_pcb *pcb = tcp_pcb_select(local, foreign);
    if (!pcb || pcb->state == TCP_PCB_STATE_CLOSED) {
        if (TCP_FLAG_ISSET(flags, TCP_FLAG_RST))
            return;

        if (TCP_FLAG_ISSET(flags, TCP_FLAG_ACK))
            tcp_output_segment(seg->ack, 0, TCP_FLAG_RST, 0, NULL, 0, local,
                               foreign);
        else
            tcp_output_segment(0, seg->seq + seg->len,
                               TCP_FLAG_RST | TCP_FLAG_ACK, 0, NULL, 0, local,
                               foreign);

        return;
    }

    // Implement later
}

static void tcp_input(const uint8_t *data, size_t len, ip_addr_t src,
                      ip_addr_t dst, struct ip_iface *iface) {
    if (len < sizeof(struct tcp_hdr)) {
        errorf("too short");
        return;
    }

    if (src == IP_ADDR_BROADCAST || dst == IP_ADDR_BROADCAST) {
        errorf("unicast IP address only support");
        return;
    }

    uint16_t cksum = ~cksum16((uint16_t *)data, len, 0);
    struct pseudo_hdr p_hdr = {
        .src = src,
        .dst = dst,
        .zero = 0,
        .proto = IP_PROTO_TCP,
        .len = hton16(len),
    };
    if (cksum16((uint16_t *)&p_hdr, sizeof(struct pseudo_hdr), cksum) != 0) {
        errorf("checksum invalid");
        return;
    }

    struct tcp_hdr *hdr = (struct tcp_hdr *)data;

    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];
    debugf("%s:%d => %s:%d, len=%zu (payload=%zu)",
           ip_addr_ntop(src, addr1, sizeof(addr1)), ntoh16(hdr->src),
           ip_addr_ntop(dst, addr2, sizeof(addr2)), ntoh16(hdr->dst), len,
           len - sizeof(struct tcp_hdr));
    tcp_dump(data, len);

    struct ip_endpoint local = {
        .addr = dst,
        .port = hdr->dst,
    };
    struct ip_endpoint foreign = {
        .addr = src,
        .port = hdr->src,
    };

    uint16_t hdr_len = (hdr->off >> 4) << 2;
    struct tcp_segment_info seg = {
        .seq = ntoh32(hdr->seqno),
        .ack = ntoh32(hdr->ackno),
        .len = len - hdr_len,
        .wnd = ntoh16(hdr->wnd),
        .urgp = hton16(hdr->urgp),
    };
    if (TCP_FLAG_ISSET(hdr->flag, TCP_FLAG_SYN))
        seg.len++; // SYN flag consumes one sequence number
    if (TCP_FLAG_ISSET(hdr->flag, TCP_FLAG_FIN))
        seg.len++; // FIN flag consumes one sequecne number

    mutex_lock(&mutex);
    tcp_segment_arrives(&seg, hdr->flag, (uint8_t *)hdr + hdr_len,
                        len - hdr_len, &local, &foreign);
    mutex_unlock(&mutex);
}

int tcp_init(void) {
    if (ip_proto_register(IP_PROTO_TCP, tcp_input) == -1) {
        errorf("ip_proto_register() failure");
        return -1;
    }

    return 0;
}