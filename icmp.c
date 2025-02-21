#include <string.h>

#include "icmp.h"
#include "ip.h"
#include "util.h"

#define ICMP_BUFSIZ IP_PAYLOAD_SIZE_MAX

struct icmp_hdr {
    uint8_t type;
    uint8_t code;
    uint16_t cksum;
    uint32_t vals;
};

struct icmp_echo {
    uint8_t type;
    uint8_t code;
    uint16_t cksum;
    uint16_t id;
    uint16_t seq;
};

static char *icmp_type_ntoa(uint8_t type) {
    switch (type) {
    case ICMP_TYPE_ECHO_REPLY:
        return "EchoReply";
    case ICMP_TYPE_DST_UNREACH:
        return "DestinationUnreachable";
    case ICMP_TYPE_SRC_QUENCH:
        return "SourceQuench";
    case ICMP_TYPE_REDIRECT:
        return "Redirect";
    case ICMP_TYPE_ECHO:
        return "Echo";
    case ICMP_TYPE_TIME_EXCEEDED:
        return "TimeExceeded";
    case ICMP_TYPE_PARAM_PROBLEM:
        return "ParameterProblem";
    case ICMP_TYPE_TIMESTAMP:
        return "Timestamp";
    case ICMP_TYPE_TIMESTAMP_REPLY:
        return "TimestampReplay";
    case ICMP_TYPE_INFO_REQUEST:
        return "InfomationRequest";
    case ICMP_TYPE_INFO_REPLY:
        return "InfomationReply";
    }

    return "Unkown";
}

static void icmp_dump(const uint8_t *data, size_t len) {
    flockfile(stderr);

    struct icmp_hdr *hdr = (struct icmp_hdr *)data;

    fprintf(stderr, "       type: %u (%s)\n", hdr->type,
            icmp_type_ntoa(hdr->type));
    fprintf(stderr, "       code: %u\n", hdr->code);
    fprintf(stderr, "      cksum: 0x%04x\n", ntoh16(hdr->cksum));
    switch (hdr->type) {
    case ICMP_TYPE_ECHO:
    case ICMP_TYPE_ECHO_REPLY:
        struct icmp_echo *echo = (struct icmp_echo *)hdr;
        fprintf(stderr, "         id: %u\n", ntoh16(echo->id));
        fprintf(stderr, "        seq: %u\n", ntoh16(echo->seq));
        break;
    default:
        fprintf(stderr, "     values: 0x%08x\n", ntoh32(hdr->vals));
        break;
    }

#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif

    funlockfile(stderr);
}

void icmp_input(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst,
                struct ip_iface *iface) {
    if (len < ICMP_HDR_SIZE) {
        errorf("too small datagram, %zu < %zu", len, ICMP_HDR_SIZE);
        return;
    }
    if (cksum16((uint16_t *)data, len, 0)) {
        errorf("invalid checksum");
        return;
    }

    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];
    debugf("%s => %s, len=%zu", ip_addr_ntop(src, addr1, sizeof(addr1)),
           ip_addr_ntop(dst, addr2, sizeof(addr2)), len);
    icmp_dump(data, len);

    struct icmp_hdr *hdr = (struct icmp_hdr *)data;
    switch (hdr->type) {
    case ICMP_TYPE_ECHO:
        // Responds with the address of the received interface.
        icmp_output(ICMP_TYPE_ECHO_REPLY, hdr->code, hdr->vals,
                    data + ICMP_HDR_SIZE, len - ICMP_HDR_SIZE, iface->unicast,
                    src);
        break;
    default:
        // Ignore.
    }
}

int icmp_output(uint8_t type, uint8_t code, uint32_t vals, const uint8_t *data,
                size_t len, ip_addr_t src, ip_addr_t dst) {
    uint8_t buf[ICMP_BUFSIZ];

    struct icmp_hdr *hdr = (struct icmp_hdr *)buf;
    hdr->type = type;
    hdr->code = code;
    hdr->cksum = 0; // Set 0 for checksum calculation.
    hdr->vals = vals;
    memcpy(buf + ICMP_HDR_SIZE, data, len); // Fill the payload.

    size_t msg_len = len + ICMP_HDR_SIZE;
    hdr->cksum = cksum16((uint16_t *)buf, msg_len, 0);

    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];
    debugf("%s => %s, len=%zu", ip_addr_ntop(src, addr1, sizeof(addr1)),
           ip_addr_ntop(dst, addr2, sizeof(addr2)), msg_len);
    icmp_dump(buf, msg_len);

    return ip_output(IP_PROTO_ICMP, buf, msg_len, src, dst);
}

int icmp_init(void) {
    if (ip_proto_register(IP_PROTO_ICMP, icmp_input) == -1) {
        errorf("ip_proto_register() failure");
        return -1;
    }

    return 0;
}