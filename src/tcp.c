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
        printf("rst-ack\n");
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
        printf("syn-ack\n");
    }
}
int ack(struct tcp *tcp)  {
    uint16_t flags = ntohs(tcp->flags);
    if(!(flags & (1 << 1)) && (flags & (1 << 4))) {
        printf("ack\n");
    }
}


int tcp_rx(struct subuff * sub) {
    printf("tcp_rx\n");
    //FREE THIS SUB AT THE END
    struct iphdr *iphdr = IP_HDR_FROM_SUB(sub);
    struct tcp *tcp = iphdr->data;
    struct sock *sock = get_sock_with_port(ntohs(tcp->dest_port));
    if(sock == NULL) printf("NULL\n");
    // else printf("sock: %d\n" , sock->self_port);
    // printf("%\n" , (tcp->dest_port));
    uint16_t csum = do_tcp_csum(tcp , 20 , 6 , htonl(iphdr->saddr) , htonl(iphdr->daddr));
    if(csum != 0) { //not working
        printf("Error: invalid ICMP checksum, dropping packet\n");
        // goto drop_pkt;
    }

    if(rst_ack(tcp)) {
        // printf("%d\n" , ntohl(tcp->ack));
            return -10;

        
    }
    if(ack(tcp)) {
        printf("seq of received ack: %x\n" , ntohl(tcp->seq));
        // printf("tcp->ack: %x\n" , ntohl(tcp->ack));
        sock->current_seq = tcp->ack;
        printf("sequence of next packet: %x\n" , ntohl(tcp->seq));
    }
    if(syn_ack(tcp)) {
        pthread_mutex_lock(&send_lock);

        printf("show I be here?\n");
        sub = alloc_sub(14 + 20 + 20);
        sub_reserve(sub , 54);
        sub_push(sub , 20);
        struct tcp *new_tcp = sub->data;
        // sock->peer_initial_seq = ntohl(tcp->ack);

        sub->protocol = IPPROTO_TCP;
        new_tcp->dest_port = tcp->src_port; //network order
        new_tcp->src_port = tcp->dest_port; //decided by code
        new_tcp->seq = htonl(sock->initial_seq) + htonl(1);
        sock->current_seq = ntohl(new_tcp->seq);
        new_tcp->ack = tcp->seq + htonl(1);
        sock->current_ack = ntohl(new_tcp->ack);
        new_tcp->flags = htons(20496);
        new_tcp->urgent = 0;
        new_tcp->window_size = htons(64240);
        new_tcp->checksum = 0;
        new_tcp->checksum = (do_tcp_csum(new_tcp , 20 , IPPROTO_TCP ,  htonl(167772164) , htonl(167772165)));
        sock->last_seq = ntohl(new_tcp->seq);

        

        int temp = 0;
        // while(!temp > 0) {
            temp = ip_output((167772165) , sub);
            // if(temp > 0) break;
        // }
        // sub_dequeue(send_queue); this is breaking the program
        sock->state = ESTABLISHED;
        pthread_mutex_unlock(&send_lock);
        

        sleep(1);

        // free(sub);

            // sleep(1);
            printf("safe\n");
    }



    drop_pkt:
    // free(sub); //don't
    return -1;
}