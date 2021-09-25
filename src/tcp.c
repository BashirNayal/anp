#include "ip.h"
#include "utilities.h"
#include "tcp.h"
#include "sock.h"



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
int ack(struct tcp *tcp) {

}
int syn_ack(struct tcp *tcp) {
    uint16_t flags = ntohs(tcp->flags);
    if((flags & (1 << 1)) && (flags & (1 << 4))) {
        printf("syn-ack\n");
    }
}


int tcp_rx(struct subuff * sub) {
    printf("tcp_rx\n");
    struct iphdr *iphdr = IP_HDR_FROM_SUB(sub);
    struct tcp *tcp = iphdr->data;
    struct sock *sock = get_sock_with_port(tcp->dest_port);
    // printf("%\n" , (tcp->dest_port));
    uint16_t csum = do_tcp_csum(tcp , 20 , 6 , (iphdr->saddr) , (iphdr->daddr));
    if(csum != 0) { //not working
        printf("Error: invalid ICMP checksum, dropping packet\n");
        // goto drop_pkt;
    }

    if(rst_ack(tcp)) {
        // printf("%d\n" , ntohl(tcp->ack));
            return -10;

        
    }
    if(syn_ack(tcp)) {
        sock->state = SYNSENT;

        // return;
    //TODO This needs to be re-written! 
        // return -1;
        // sleep(1);
            sub = alloc_sub(14 + 20 + 20);
            sub_reserve(sub , 54);
            sub_push(sub , 20);
            struct tcp *new_tcp = sub->data;
            sub->protocol = IPPROTO_TCP;
            new_tcp->dest_port = tcp->src_port; //network order
            new_tcp->src_port = tcp->dest_port; //decided by code
            new_tcp->ack = tcp->seq + htonl(1);
            new_tcp->seq = tcp->ack + htonl(1);;
            new_tcp->flags = htons(20496);
            new_tcp->urgent = 0;
            new_tcp->window_size = htons(64240);
            new_tcp->checksum = 0;
            new_tcp->checksum = (do_tcp_csum(new_tcp , 20 , IPPROTO_TCP ,  htonl(167772164) , htonl(167772165)));
            while(true) {
                int temp = ip_output((167772165) , sub); //destination's bytes are somehow flipped on wireshark
                if(temp > 0) break;
            }
            sock->state = ESTABLISHED;
            free(sub);
            // sleep(1);
    }



    drop_pkt:
    // free(sub); //don't
    return -1;
}