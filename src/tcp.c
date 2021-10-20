#include "ip.h"
#include "utilities.h"
#include "tcp.h"
#include "sock.h"
#include "sync.h"
#include "queue.h"


bool psh(struct tcp *tcp) {
    uint16_t flags = ntohs(tcp->flags);
    return (flags & (1 << 3));
}
bool syn_ack(struct tcp *tcp) {
    uint16_t flags = ntohs(tcp->flags);
    return ((flags & (1 << 1)) && (flags & (1 << 4)));
}
bool ack(struct tcp *tcp)  {
    uint16_t flags = ntohs(tcp->flags);
    return (flags & (1 << 4));
}
bool fin_ack(struct tcp *tcp)  {
    uint16_t flags = ntohs(tcp->flags);
    return ((flags & 1) && (flags & (1 << 4)));
}

int tcp_rx(struct subuff * sub) {
    struct iphdr *iphdr = IP_HDR_FROM_SUB(sub);
    struct tcp *tcp = TCP_HDR_FROM_DATA(iphdr);
    struct sock *sock = get_sock_with_port(tcp->dest_port);

    //Packet's port destination is not mapped to any socket, drop the packet.
    if(sock == NULL) return -1;
    
    uint16_t csum = do_tcp_csum((void*)tcp , iphdr->len - IP_HDR_LEN  , IPPROTO_TCP , htonl(iphdr->saddr) , htonl(iphdr->daddr));
    if(csum != 0) {
        // printf("Error: invalid TCP checksum, dropping packet\n");
        return -1;
    }

    //If packet is a syn_ack.
    if(syn_ack(tcp)) {
        if(sock->next_seq != tcp->ack) {
            pthread_mutex_unlock(&send_lock);
            return -1;
        }
        struct subuff *temp = allocate_tcp_buffer(sock , 0 , ACK_F);
        struct tcp *new_tcp = TCP_HDR_FROM_DATA(temp);

        new_tcp->seq = (sock->next_seq);
        new_tcp->ack = tcp->seq + htonl(1);
        sock->current_ack = (new_tcp->ack);
        new_tcp->checksum = (do_tcp_csum((void*)new_tcp , TCP_HLEN , IPPROTO_TCP ,  htonl(CLIENT_IP) , htonl(SERVER_IP)));
        sock->current_ack = new_tcp->ack;
        pthread_mutex_lock(&send_lock);

        if(!send_out(SERVER_IP, temp, 4)) {
            return -1;
        }
        
        if(!sub_queue_empty(send_queue))free(sub_dequeue(send_queue));
        sock->state = ESTABLISHED;
        sock->window_size = ntohs(tcp->window_size);
        pthread_cond_signal(&syn_ack_received);
        pthread_mutex_unlock(&send_lock);
    }

    else if (fin_ack(tcp)) {
        if(sock->state == FIN_WAIT1) {
            sock->state = CLOSE_WAIT;
            struct subuff *temp = allocate_tcp_buffer(sock , 0 , ACK_F);
            struct tcp *new_tcp = TCP_HDR_FROM_DATA(temp);
            new_tcp->ack = tcp->seq + htonl(1);
            new_tcp->seq = tcp->ack;
            new_tcp->checksum = (do_tcp_csum((void*)new_tcp , TCP_HLEN , IPPROTO_TCP ,  htonl(CLIENT_IP) , htonl(SERVER_IP)));

            if(!send_out(SERVER_IP, temp, 4)) {
                return -1;
            }

            sock->state = CLOSED;
            pthread_cond_signal(&close_wait_cond);
        }
    }

    //Check if the acknowledgement number is for the pending sent packet.
    else if (sub_queue_len(send_queue) > 0 && tcp->ack == sock->next_seq){ //This if statement could be better
        free(sub_dequeue(send_queue));
    }

    else if (iphdr->len > (TCP_HLEN + IP_HDR_LEN)){
        //if the seqeuence number of the incoming packet is what we expect
        if(tcp->seq == sock->current_ack) {
            
            sub_queue_tail(recv_queue, sub);
            struct subuff *temp = alloc_sub(TCP_ENCAPSULATING_HLEN);
            sub_reserve(temp, TCP_ENCAPSULATING_HLEN);
            sub_push(temp, TCP_HLEN);

            struct tcp *new_tcp = TCP_HDR_FROM_DATA(temp);
            // printf("ACK IPHDR len: \n(%d/%d) [%d,%d]\n", iphdr->len, htonl(iphdr->len), iphdr->len - 40, htonl(iphdr->len - 40));
            // printf("prev current ack:\n (%d/%d)\n", ntohl(sock->current_ack), sock->current_ack);
            sock->current_ack = htonl(ntohl(sock->current_ack) + iphdr->len - 40);
            // printf("current ack:\n (%d/%d)\n", ntohl(sock->current_ack), sock->current_ack);
            // printf("current IPHDR len:\n (%d/%d) [%d,%d]\n", iphdr->len, htonl(iphdr->len), iphdr->len - 40, htonl(iphdr->len - 40));
            temp->protocol = IPPROTO_TCP;
            new_tcp->dest_port = tcp->src_port;
            new_tcp->src_port = tcp->dest_port;
            new_tcp->urgent = 0;
            new_tcp->window_size = htons(WINDOW_SIZE);

            new_tcp->seq = (sock->next_seq);
            new_tcp->ack = sock->current_ack;
            //printf("ack: %d\n", ntohl(new_tcp->ack));
            new_tcp->flags = htons(ACK_F);

            new_tcp->checksum = 0;
            new_tcp->checksum = (do_tcp_csum((void*)new_tcp , TCP_HLEN , IPPROTO_TCP ,  htonl(CLIENT_IP) , htonl(SERVER_IP)));
            
            if(!send_out(SERVER_IP, temp, 4)) {
                return -1;
            }

            if(psh(tcp)) pthread_cond_signal(&recv_wait_cond);
            free(temp);
        }
    }
    return 0;
}


void* send_to_socket() {

    while(true) {

        pthread_mutex_lock(&send_lock);
        while((sub_queue_len(send_queue) == 0)) pthread_cond_wait(&send_not_empty , &send_lock);

        struct subuff *sub = sub_peek(send_queue);
        struct tcp *tcp = TCP_HDR_FROM_DATA(sub);
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
        ip_output(SERVER_IP, temp);

        free(temp);
        sock->send_count--;
        sock->last_transmitted = sub->dlen;

        pthread_cond_signal(&done_transmit);
        pthread_mutex_unlock(&send_lock);

        timer_add(TIMEOUT_VAL , (void *)pthread_cond_signal , &send_wait_cond);
        pthread_cond_wait(&send_wait_cond , &send_wait_lock);
    }

} 
struct subuff *allocate_tcp_buffer(void* sock , uint16_t payload_size , uint16_t flag) {
    
    struct subuff *sub = alloc_sub(TCP_ENCAPSULATING_HLEN + payload_size);
    sub_reserve(sub , TCP_ENCAPSULATING_HLEN + payload_size);
    sub_push(sub , TCP_HLEN + payload_size);

    sub->protocol = IPPROTO_TCP;
    sub->dlen = payload_size;

    struct tcp *tcp = TCP_HDR_FROM_DATA(sub);
    tcp->dest_port = ((struct sock*)sock)->peer_port;
    tcp->src_port = ((struct sock*)sock)->self_port; 
    tcp->flags = htons(flag); 
    tcp->urgent = 0;
    tcp->window_size = htons(WINDOW_SIZE);
    tcp->checksum = 0;

    return sub;
}

