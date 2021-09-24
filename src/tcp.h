#include "subuff.h"

#ifndef ANPNETSTACK_TCP_H
#define ANPNETSTACK_TCP_H


int tcp_rx(struct subuff* sub);

struct tcp {
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seq;
    uint32_t ack;
    uint16_t flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent;
} __attribute__((packed));

struct sock {
    uint32_t fd;
    int domain;
    int type;
    int protocol;
};

// int syn_ack(struct tcp *tcp);



#endif //ANPNETSTACK_ICMP_H
