#include "linklist.h"
#include "sock.h"
static int count = 1000000;
static bool initialized = false;
static LIST_HEAD(head);

uint32_t get_fd() {
    if(!initialized) {
        init_sock();
        initialized = true;
    }
    add_sock(count++);
    return count - 1;
}

int add_sock(uint32_t fd) {
    struct sock *sock = malloc(sizeof(struct sock));
    list_add(&sock->list , &head);
    sock->fd = fd;
    sock->state = CLOSED;
}

int init_sock() {
    struct sock *sock = malloc(sizeof(struct sock));
    list_init(&sock->list);
}

struct sock *get_sock_with_fd(uint32_t fd) {
    struct list_head *item;
    struct sock *sock = NULL;
    list_for_each(item, &head) {
        sock = list_entry(item, struct sock, list);
        if(sock->fd == fd) return sock;
    }
    return NULL;
}

struct sock *get_sock_with_port(uint16_t port) {
    struct list_head *item;
    struct sock *sock = NULL;
    list_for_each(item, &head) {
        sock = list_entry(item, struct sock, list);
        if(sock->self_port == port) return sock;
    }
    return NULL;    
}