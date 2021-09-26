#include "subuff.h"
#include "linklist.h"

#ifndef ANPNETSTACK_SOCK_H
#define ANPNETSTACK_SOCK_H

// typedef enum {CLOSED, SYNSENT, ESTABLISHED}; state;
#define CLOSED 0
#define SYNSENT 1
#define ESTABLISHED 2


struct sock {
    struct list_head list;
    uint32_t fd;
    uint16_t self_port;
    uint16_t peer_port;
    volatile int state;
    uint32_t last_seq;
    uint32_t initial_seq;
    uint32_t current_ack;
    uint32_t current_seq;
    uint32_t next_seq;
    volatile ssize_t last_transmitted;
};
// volatile enum state{CLOSED, SYNSENT, ESTABLISHED};
struct sock *get_sock_with_fd(uint32_t fd);
struct sock *get_sock_with_port(uint16_t port);
uint32_t get_fd();
int add_sock(uint32_t fd);
int init_sock();


#endif //ANPNETSTACK_ICMP_H
