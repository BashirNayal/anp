/*
 Copyright 2021 Lin Wang

 This code is part of the Advanced Network Programming (2021) course at 
 Vrije Universiteit Amsterdam.

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

struct metadata {
    /* empty */
}

register <bit<32>>(1)count;


typedef bit<48>  EthernetAddress;
typedef bit<32>  IPv4Address;
typedef bit<9>   EgressPort;

header Ethernet_h {
    EthernetAddress dstAddr;
    EthernetAddress srcAddr;
    bit<16>         etherType;
}

header IPv4_h {
    bit<4>       ihl;
    bit<4>       version;
    bit<8>       diffserv;
    bit<16>      totalLen;
    bit<16>      identification;
    bit<3>       flags;
    bit<13>      fragOffset;
    bit<8>       ttl;
    bit<8>       protocol;
    bit<16>      hdrChecksum;
    IPv4Address  srcAddr;
    IPv4Address  dstAddr;
}
header TCP_h {
    bit<16>       src_port;
    bit<16>       dst_port;
    bit<32>       sequence_number;
    bit<32>       acknowledgement_number;
    bit<4>        hlen;
    bit<3>        reserved;
    bit<1>        NS;
    bit<1>        CWR;
    bit<1>        ECE;
    bit<1>        URG;
    bit<1>        ACK;
    bit<1>        PSH;
    bit<1>        RST;
    bit<1>        SYN;
    bit<1>        FIN;
    bit<16>       window_size;
    bit<16>       checksum;
    bit<16>       urgent_pointer;

    //...
}

struct headers {
    Ethernet_h ethernet;
    IPv4_h ipv4;
    TCP_h tcp;
}
// #define range_t 9:0
// typedef bit<32> w_t;
// extern Register<T , S> {
//     Register(bit<32> size , T init_val);
//     T read(in S index);
//     void write (in S index , in T value);

// }

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    
    state start {
        transition parse_ethernet;
    }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x0800  : parse_ipv4; //ipv4 type
            default : accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            0x6 : parse_tcp;
            default : accept;
        }
    }
    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
                     
    // count.write(0);
    action drop() {
        
    }
    // action increment_counter() {
    //     count.write(0 , 0 + 1);
    // }
    action ipv4_forward(EthernetAddress dstAddr , EgressPort port) {
        // count.write(0);
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        // bit<32> temp;
        // count.read(temp , 0);
        // count.write(0 , temp + 1);
    }
    action multicast( ) {
        standard_metadata.mcast_grp = 1;

    }
    table ipv4_lpm {
        key = { hdr.ipv4.dstAddr : lpm;
                hdr.tcp.ACK : exact;}
        actions = {
            ipv4_forward;
            drop;
            multicast;
        }
        size = 1024;
        default_action = multicast;
    }
    // table multicast_t {
    //     key = {hdr.tcp.SYN : exact;}
    //     actions = {
    //         multicast;
    //     }
    // }
    apply {
        ipv4_lpm.apply();
        // bit<32> temp;
        // count.read(temp , 0);
        // if(temp > (bit<32>)150) {
        //     drop();
        // }
        // else {
        //     ipv4_lpm.apply();
        // }
            // multicast_t.apply();
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    
        action drop() {
        mark_to_drop(standard_metadata);
    }
    apply { 
        if (standard_metadata.egress_port == standard_metadata.ingress_port)
            drop();
        // /*if (hdr.ipv4.isValid() && standard_metadata.instance_type == 0) */{
        //     clone(CloneType.E2E, (bit<32>)32w100);
        //     standard_metadata.egress_spec = 4;
        // }
        // if (standard_metadata.instance_type == PKT_INSTANCE_TYPE_INGRESS_CLONE) {
        //     // Process cloned packet
        //     standard_metadata.egress_spec = 1;
            
        // } else {
            
        // }
     }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
