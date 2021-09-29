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

#include "icmp.h"
#include "ip.h"
#include "utilities.h"

void icmp_rx(struct subuff *sub)
{   
    struct iphdr *iphdr = IP_HDR_FROM_SUB(sub);
    struct icmp* icmp = (struct icmp*)iphdr->data;

    uint16_t csum = do_csum(icmp  , iphdr->len - iphdr->ihl , 0); 
    if(csum != 0) {
        printf("Error: invalid ICMP checksum, dropping packet\n");
        goto drop_pkt;
    }
    switch(icmp->type) {
        case ICMP_V4_REPLY:
            break;
        case ICMP_V4_ECHO:
            icmp_reply(sub);
            break;
    }
    //FIXME: implement your ICMP packet processing implementation here
    //figure out various type of ICMP packets, and implement the ECHO response type (icmp_reply)
    drop_pkt:
    free_sub(sub);
}

void icmp_reply(struct subuff *sub)
{
    //            re-using the same buffer

    // struct iphdr *iphdr = IP_HDR_FROM_SUB(sub);
    // sub_reserve(sub , ETH_HLEN + IP_HDR_LEN + IP_PAYLOAD_LEN(iphdr));
    // sub_push(sub , IP_PAYLOAD_LEN(iphdr));
    // struct icmp* icmp = sub->data;
    // sub->protocol = 1;
    // icmp->checksum = 0;
    // icmp->code = 0;
    // icmp->type = 0;
    // icmp->checksum = do_csum(icmp , iphdr->len - iphdr->ihl , 0);
    // ip_output(iphdr->saddr  , sub);
    // ip_output(iphdr->saddr , sub);


    struct iphdr *old_iphdr = IP_HDR_FROM_SUB(sub);
    uint32_t destination_address = old_iphdr->saddr;
    struct subuff *buffer = alloc_sub(ETH_HLEN + IP_HDR_LEN + IP_PAYLOAD_LEN(old_iphdr)); 
    buffer->len = 0;
    buffer->seq = sub->seq;
    buffer->protocol = IPPROTO_ICMP;
    sub_reserve(buffer , ETH_HLEN + IP_HDR_LEN + IP_PAYLOAD_LEN(old_iphdr));
    sub_push(buffer , IP_PAYLOAD_LEN(old_iphdr));
    
    struct iphdr* iphdr = IP_HDR_FROM_SUB(buffer);
    iphdr->id = old_iphdr->id;
    iphdr->len = old_iphdr->len;

    struct icmp* old_icmp = (struct icmp*)old_iphdr->data;
    struct icmp* icmp = (struct icmp*)buffer->data;
    icmp->type = 0;
    icmp->code = 0;
    memcpy(icmp->data , old_icmp->data , IP_PAYLOAD_LEN(old_iphdr));
    
    icmp->checksum = 0;
    icmp->checksum = do_csum(icmp , IP_PAYLOAD_LEN(iphdr) , 0);
    ip_output(destination_address , buffer);
    free_sub(buffer);
    //FIXME: implement your ICMP reply implementation here
    // preapre an ICMP response buffer
    // send it out on ip_ouput(...)
}
