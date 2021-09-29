#include "ip.h"
#include "utilities.h"
#include "tcp.h"
#include "sock.h"
#include "sync.h"
#include "queue.h"
// static LIST_HEAD(head);



int rst_ack(struct tcp *tcp) {
    uint16_t flags = ntohs(tcp->flags);
    if((flags & (1 << 2)) && (flags & (1 << 4))) {
        // printf("rst-ack\n");
    }

}
int syn(struct tcp *tcp) {
    uint16_t flags = ntohs(tcp->flags);
    // if((flags & (1 << 2)) && !(flags & (1 << 4))) {
    // }

}
int syn_ack(struct tcp *tcp) {
    uint16_t flags = ntohs(tcp->flags);
    if((flags & (1 << 1)) && (flags & (1 << 4))) {
        // printf("syn-ack\n");
    }
}
int ack(struct tcp *tcp)  {
    uint16_t flags = ntohs(tcp->flags);
    if(!(flags & (1 << 1)) && (flags & (1 << 4))) {
        // printf("ack\n");
    }
}


int tcp_rx(struct subuff * sub) {
    struct iphdr *iphdr = IP_HDR_FROM_SUB(sub);
    struct tcp *tcp = (struct tcp *)iphdr->data;
    struct sock *sock = get_sock_with_port(tcp->dest_port);

    //Packet's port destination is not mapped to any socket, drop the packet.
    if(sock == NULL) return -1;
    
    uint16_t csum = do_tcp_csum((void*)tcp , iphdr->len - IP_HDR_LEN  , IPPROTO_TCP , htonl(iphdr->saddr) , htonl(iphdr->daddr));
    if(csum != 0) {
        printf("Error: invalid TCP checksum, dropping packet\n");
        return -1;
    }

    pthread_mutex_lock(&send_lock);
    //If packet is a syn_ack.
    if(syn_ack(tcp)) {
        if(sock->next_seq != tcp->ack) {
            pthread_mutex_unlock(&send_lock);
            return -1;
        }
        sub = alloc_sub(TCP_ENCAPSULATING_HLEN);
        sub_reserve(sub , TCP_ENCAPSULATING_HLEN);
        sub_push(sub , TCP_HLEN);
        struct tcp *new_tcp = (struct tcp *)sub->data;

        sub->protocol = IPPROTO_TCP;
        new_tcp->dest_port = tcp->src_port;
        new_tcp->src_port = tcp->dest_port;
        new_tcp->urgent = 0;
        new_tcp->window_size = htons(WINDOW_SIZE);

        new_tcp->seq = (sock->next_seq);
        new_tcp->ack = tcp->seq + htonl(1);
        sock->current_ack = (new_tcp->ack);
        new_tcp->flags = htons(ACK_F);

        new_tcp->checksum = 0;
        new_tcp->checksum = (do_tcp_csum((void*)new_tcp , TCP_HLEN , IPPROTO_TCP ,  htonl(CLIENT_IP) , htonl(SERVER_IP)));

        ip_output(SERVER_IP , sub);
        free(sub_dequeue(send_queue));
        sock->state = ESTABLISHED;
        pthread_cond_signal(&syn_ack_received);
    }
    else {
        //An ack packet for the sent data.
        if(sub_queue_len(send_queue) > 0) {
            //Check if the acknowledgement number is for the pending sent packet.
            if(tcp->ack == sock->next_seq) {
                free(sub_dequeue(send_queue));
            }
        }
        //More logic will be added as support to more packets is added.
    }

    pthread_mutex_unlock(&send_lock);
    return 0;
}


void* send_to_socket() {
    while(true) {
        pthread_mutex_lock(&send_lock);
        while((sub_queue_len(send_queue) == 0)) pthread_cond_wait(&send_not_empty , &send_lock);
        struct subuff *sub = sub_peek(send_queue);
        struct tcp *tcp = (struct tcp *)sub->data;
        struct sock *sock = get_sock_with_port((tcp->src_port));
        if(sock->send_count == 0) {
            //Buffer was sent 10 times already, drop it.
            free(sub_dequeue(send_queue));
            pthread_mutex_unlock(&send_lock);
            continue;
        }
        struct subuff *temp = alloc_sub(TCP_ENCAPSULATING_HLEN + sub->dlen);
        sub_reserve(temp , TCP_ENCAPSULATING_HLEN + sub->dlen);
        sub_push(temp , TCP_HLEN + sub->dlen);
        memcpy(temp->data , sub->data , TCP_HLEN + sub->dlen);
        temp->protocol = sub->protocol;
        //Update the sequence only once per packet.
        if(sock->send_count == 10) sock->next_seq += htonl(sub->dlen);
        ip_output(SERVER_IP , temp);
        free(temp);
        sock->send_count--;
        sock->last_transmitted = sub->dlen;
        pthread_cond_signal(&done_transmit);
        pthread_mutex_unlock(&send_lock);


        // usleep(10000); // this should be removed and replaced with timer(?) wait
        pthread_mutex_lock(&send_wait_lock);
        struct mutex_cond_pair *mutex_condition = malloc(sizeof(struct mutex_cond_pair));
        mutex_condition->mutex = &send_wait_lock;
        mutex_condition->cond = &send_wait_cond;
        timer_add(10 , signal_mutex_condition , mutex_condition);
        pthread_cond_wait(&send_wait_cond , &send_wait_lock);
        pthread_mutex_unlock(&send_wait_lock);

    }
} 
void *signal_mutex_condition(struct mutex_cond_pair *mutex_condition) {
    if(!mutex_condition) return;

    pthread_mutex_lock(mutex_condition->mutex);
    pthread_cond_signal(mutex_condition->cond);
    pthread_mutex_unlock(mutex_condition->mutex);
    return;
}