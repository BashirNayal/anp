#include "subuff.h"
#include "ip.h"
#include "linklist.h"
#ifndef ANPNETSTACK_TCP_H
#define ANPNETSTACK_TCP_H

#define TCP_HLEN                sizeof(struct tcp)
#define TCP_ENCAPSULATING_HLEN  ETH_HLEN + IP_HDR_LEN + TCP_HLEN
#define SERVER_IP               167772165
#define CLIENT_IP               167772164
#define WINDOW_SIZE             0xffff
#define TIMEOUT_VAL             10
#define SYN_F                   0x5002
#define PSH_ACK_F               0x5018
#define ACK_F                   0x5010

int tcp_rx(struct subuff* sub);
void* send_to_socket();
struct subuff * allocate_tcp_buffer(void *sock , uint16_t payload_size , uint16_t flag);

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

#define TCP_HDR_FROM_DATA(_data)    (struct tcp *)(_data->data)

// struct mutex_cond_pair {
//     pthread_mutex_t *mutex;
//     pthread_cond_t *cond;
// };

#endif //ANPNETSTACK_ICMP_H
