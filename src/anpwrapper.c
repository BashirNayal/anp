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




// struct tcp {
//     uint16_t src_port;
//     uint16_t dest_port;
//     uint32_t seq;
//     uint32_t ack;
//     uint16_t flags;
//     uint16_t window_size;
//     uint16_t checksum;
//     uint16_t urgent;
// } __attribute__((packed));


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

// TODO: ANP milestone 3 -- implement the socket, and connect calls
int socket(int domain, int type, int protocol) {
    // printf("\n\n\nI'm here\n\n\n\n");
    // time_t t;
    // srand((unsigned) time(&t));
    // printf("%d\n", rand() % UINT32_MAX);
    if (is_socket_supported(domain, type, protocol)) {

        //TODO: implement your logic here
        // return 32;
        return get_fd();
        return -ENOSYS;
    }
    // if this is not what anpnetstack support, let it go, let it go!
    return _socket(domain, type, protocol);
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{    
    //FIXME -- you can remember the file descriptors that you have generated in the socket call and match them here
    // while(1);
    bool is_anp_sockfd = true;
    if(is_anp_sockfd){
        struct sock *sock = get_sock_with_fd(sockfd);
        if(sock->state != CLOSED) { 
            printf("Error: Cannot send data, connection is not established\n");
            return -1;
        }

        struct sockaddr_in *sockaddr = addr;
        printf("%d\n" , ntohl(sockaddr->sin_addr.s_addr)); //10.0.0.5
        // struct sin_addr
        // sockaddr->sin_addr.s_addr
        int wait_time = 100;
        struct subuff *buffer;
        while (1) { 
            sock->peer_port = ntohs(sockaddr->sin_port);
            sock->self_port = 47891;
            sock->initial_seq = htonl(0xbf6300b1);
            // return 0;
            buffer = alloc_sub(14 + 20 + 20); 
            sub_reserve(buffer , 54);
            sub_push(buffer , 20);
            sleep(3);
            struct tcp *tcp = buffer->data;
            buffer->protocol = IPPROTO_TCP;
            // printf("port: %d\n" , ntohs(sockaddr->sin_port));
            tcp->dest_port =  sockaddr->sin_port; //network order
            tcp->src_port = htons(sock->self_port); //decided by code
            tcp->ack = htonl(0);
            tcp->seq = htonl(sock->initial_seq);
            tcp->flags = htons(20482); 
            tcp->urgent = 0;
            tcp->window_size = htons(64240);
            tcp->checksum = 0;
            tcp->checksum = (do_tcp_csum(tcp , 20 , IPPROTO_TCP ,  htonl(167772164) , (sockaddr->sin_addr.s_addr)));
            int temp = ip_output(ntohl(sockaddr->sin_addr.s_addr) , buffer);
            // usleep(wait_time * 1000); // <- condition variable here
            wait_time *= 2;

            if(temp > 0){ 
                sock->state = SYNSENT;
               break; 
            } 
        free(buffer);
        }
        return 0;
        //TODO: implement your logic here
    // scanf("%s", str2);

        return -ENOSYS;
    }
    // the default path
    return _connect(sockfd, addr, addrlen);
}

// TODO: ANP milestone 5 -- implement the send, recv, and close calls
ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
    //FIXME -- you can remember the file descriptors that you have generated in the socket call and match them here
    bool is_anp_sockfd = true;
    if(is_anp_sockfd) {
        struct sock *sock = get_sock_with_fd(sockfd);
        // if(sock->state != ESTABLISHED) return -1;
        sleep(2);
        struct subuff *sub = alloc_sub(54 + len);
        sub_reserve(sub , 54 + len);
        sub_push(sub , len);
        memcpy(sub->data , buf , len);
        sub_push(sub , 20);
        struct tcp *tcp = sub->data;
        sub->protocol = IPPROTO_TCP;
        

        tcp->dest_port =  htons(sock->peer_port); //network order
        tcp->src_port = htons(sock->self_port); //decided by code
        tcp->ack = htonl(sock->current_ack);
        tcp->seq = htonl(sock->current_seq);
        tcp->flags = htons(0x5018);
        tcp->urgent = 0;
        tcp->window_size = htons(64240);
        tcp->checksum = 0;
        tcp->checksum = (do_tcp_csum(tcp , 20 + len, IPPROTO_TCP ,  htonl(167772164) , htonl(167772165)));

        uint32_t sent = ip_output((167772165) , sub);
        printf("Data sent: %d\n" , sent - 54);
        sleep(3);


        // struct iphdr *iphdr = 
        //TODO: implement your logic here
        return sent - 54;
    }
    // the default path
    return _send(sockfd, buf, len, flags);
}

ssize_t recv (int sockfd, void *buf, size_t len, int flags){
    //FIXME -- you can remember the file descriptors that you have generated in the socket call and match them here
    bool is_anp_sockfd = false;
    if(is_anp_sockfd) {
        //TODO: implement your logic here
        return -ENOSYS;
    }
    // the default path
    return _recv(sockfd, buf, len, flags);
}

int close (int sockfd){
    //FIXME -- you can remember the file descriptors that you have generated in the socket call and match them here
    bool is_anp_sockfd = false;
    if(is_anp_sockfd) {
        //TODO: implement your logic here
        return -ENOSYS;
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


// int send_to_socket() {





// }