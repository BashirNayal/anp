/*
 * Copyright [2020] [Animesh Trivedi]
 *
 * This code is part of the Advanced Network Programming (ANP) course
 * at VU Amsterdam.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *        http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

//XXX: _GNU_SOURCE must be defined before including dlfcn to get RTLD_NEXT symbols
#define _GNU_SOURCE

#include <dlfcn.h>
#include "systems_headers.h"
#include "linklist.h"
#include "anpwrapper.h"
#include "init.h"
#include "subuff.h"
#include "utilities.h"
#include <pthread.h>
// #include "sys/memfd.h"
#include "tcp.h"
#include "sock.h"

// static LIST_HEAD(head);
#include "queue.h"
#include "sync.h"

static int (*__start_main)(int (*main) (int, char * *, char * *), int argc, \
                           char * * ubp_av, void (*init) (void), void (*fini) (void), \
                           void (*rtld_fini) (void), void (* stack_end));

static ssize_t (*_send)(int fd, const void *buf, size_t n, int flags) = NULL;
static ssize_t (*_recv)(int fd, void *buf, size_t n, int flags) = NULL;

static int (*_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) = NULL;
static int (*_socket)(int domain, int type, int protocol) = NULL;
static int (*_close)(int sockfd) = NULL;
static int is_socket_supported(int domain, int type, int protocol)
{
    if (domain != AF_INET){
        return 0;
    }
    if (!(type & SOCK_STREAM)) {
        return 0;
    }
    if (protocol != 0 && protocol != IPPROTO_TCP) {
        return 0;
    }
    printf("supported socket domain %d type %d and protocol %d \n", domain, type, protocol);
    return 1;
}
//ERROR HANDLING FROM https://www.microfocus.com/documentation/enterprise-developer/ed60/ETS-help/GUID-1872DF9A-0FE4-4093-9A1B-B743BFDDDBA1.html
int socket(int domain, int type, int protocol) {
    if (is_socket_supported(domain, type, protocol)) {
        return get_fd(); //creates a sock entry and return the fd value
    }
    // if this is not what anpnetstack support, let it go, let it go!
    return _socket(domain, type, protocol);
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    struct sock *sock = get_sock_with_fd(sockfd);
    // sleep(3); //to buy time for tcpdump
    if(!sock){
        errno = EBADF;
        return -errno;
    }
    else {
        struct sockaddr_in *sockaddr = (struct sockaddr_in *)addr;
        //The socket is already connected.
        if(sock->state == ESTABLISHED) {
            errno = EISCONN;
            return -errno;
        }
        //A previous connection attempt  has not yet been completed.
        if(sock->state != CLOSED && sock->state!= ESTABLISHED) {
            errno = EALREADY;
            return -errno; 
        }

        time_t t;
        srand((unsigned) time(&t));
        sock->peer_port = (sockaddr->sin_port);
        sock->self_port = htons((rand() % 0xffff - 5000) + 5000); //Client port is generated here. Starts at 5000
        sock->initial_seq = htonl(rand() % 0xffffffff);

        struct subuff *buffer = allocate_tcp_buffer(sock , 0 , SYN_F);
        //Setting up the tcp header.
        struct tcp *tcp = (struct tcp *)buffer->data;
        tcp->ack = 0;
        tcp->seq = sock->initial_seq;
        tcp->checksum = (do_tcp_csum((void *)tcp , TCP_HLEN , IPPROTO_TCP ,  htonl(CLIENT_IP) , (sockaddr->sin_addr.s_addr)));

        //Since syn is sent, the sequence number is incremented by 1.
        sock->next_seq = sock->initial_seq + htonl(1);

        // pthread_mutex_lock(&send_lock);
        sock->send_count = 10; // Try to send 10 times before dropping it.
        sub_queue_tail(send_queue , buffer); //Enqueue the buffer.
        sock->state = SYNSENT;  //This assumes that send_to_sock will succeed at least once.
        pthread_cond_signal(&send_not_empty);
        // pthread_mutex_unlock(&send_lock);
        //Wait till syn_ack is received from the server.
        pthread_cond_wait(&syn_ack_received , &syn_lock);

        if(sock->state == ESTABLISHED) return 0;
        else {
            errno = ENETUNREACH;
            return -errno;
        };
    }
    // the default path
    return _connect(sockfd, addr, addrlen); 
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
    struct sock *sock = get_sock_with_fd(sockfd);
    if(!sock) {
        errno = EBADF;
        return -errno;
    }
    else {
        if(sock->state != ESTABLISHED) { 
            errno = EPIPE;
            return -errno;
        }
        struct subuff *sub = allocate_tcp_buffer(sock , len , PSH_ACK_F);
        memcpy(sub->data + TCP_HLEN , buf , len);
        struct tcp *tcp = (struct tcp*)sub->data;
        tcp->ack = sock->current_ack;
        tcp->seq = sock->next_seq;
        tcp->checksum = (do_tcp_csum((void *)tcp , TCP_HLEN + len, IPPROTO_TCP ,  htonl(CLIENT_IP) , htonl(SERVER_IP)));
        pthread_mutex_lock(&send_lock);
        sock->send_count = 10;
        sub_queue_tail(send_queue , sub);
        sock->last_transmitted = 0;
        pthread_cond_signal(&send_not_empty);
        pthread_mutex_unlock(&send_lock);
        while(sock->last_transmitted == 0)
            timer_add(TIMEOUT_VAL * 3 , (void *)pthread_cond_signal , &done_transmit);
        //done_transmit is signaled by either the timer or send_to_socket().
        //This is updated with the return value of ip_output()
        return sock->last_transmitted;
    }
    // the default path
    return _send(sockfd, buf, len, flags);
}

ssize_t recv (int sockfd, void *buf, size_t len, int flags){
    while(sub_queue_len(recv_queue) == 0) 
        timer_add(TIMEOUT_VAL * 20  , (void *)pthread_cond_signal , &recv_wait_cond);
    
    struct sock *sock = get_sock_with_fd(sockfd);
    struct subuff *sub;
    if(sub_queue_len(recv_queue) == 0) return 0;
    sub = sub_dequeue(recv_queue);
    struct iphdr *iphdr = IP_HDR_FROM_SUB(sub);
    bool is_anp_sockfd = true;
    // IP_HDR_LEN(iphdr)
    if(is_anp_sockfd) {
        struct tcp *tcp = iphdr->data;
        memcpy(buf , iphdr->data + 20 , iphdr->len - 40);
        return iphdr->len - 40;
    }
    // the default path
    return _recv(sockfd, buf, len, flags);
}

int close (int sockfd){
    //FIXME -- you can remember the file descriptors that you have generated in the socket call and match them here
    bool is_anp_sockfd = true;
    printf("close\n");
    // printf("send len: %d\nrecv len: %d\n" , sub_queue_len(send_queue) , sub_queue_len(recv_queue));
    struct sock *sock = get_sock_with_fd(sockfd);
    if(is_anp_sockfd) {
        //TODO: implement your logic here
        struct subuff *sub = allocate_tcp_buffer(sock , 0 , 0x5011);
        struct tcp *tcp = (struct tcp*)sub->data;
        tcp->ack = sock->current_ack;
        tcp->seq = sock->next_seq;
        tcp->checksum = (do_tcp_csum((void*)tcp , TCP_HLEN , IPPROTO_TCP ,  htonl(CLIENT_IP) , htonl(SERVER_IP)));

        ip_output(SERVER_IP , sub);
        sock->state = FIN_WAIT1;
        // sub_queue_tail(send_queue , sub);
        pthread_cond_signal(&send_not_empty);
        // sleep(1);
        // printf("about to wait\n");
        pthread_cond_wait(&close_wait_cond , &syn_lock);
        return 0;
    }
    // the default path
    return _close(sockfd);
}

void _function_override_init()
{
    __start_main = dlsym(RTLD_NEXT, "__libc_start_main");
    _socket = dlsym(RTLD_NEXT, "socket");
    _connect = dlsym(RTLD_NEXT, "connect");
    _send = dlsym(RTLD_NEXT, "send");
    _recv = dlsym(RTLD_NEXT, "recv");
    _close = dlsym(RTLD_NEXT, "close");
}
