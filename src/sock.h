#include "subuff.h"
#include "linklist.h"

#ifndef ANPNETSTACK_SOCK_H
#define ANPNETSTACK_SOCK_H



struct sock {
    struct list_head list;
    uint32_t fd;
    uint16_t self_port;
    uint16_t peer_port;
    uint8_t connection_state;
};

struct sock *get_sock_with_fd(uint32_t fd);
uint32_t get_fd();
int add_sock(uint32_t fd);
int init_sock();


#endif //ANPNETSTACK_ICMP_H
