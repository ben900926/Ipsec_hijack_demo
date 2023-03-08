#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "net.h"
#include "transport.h"
#include "utils.h"

uint16_t cal_tcp_cksm(struct iphdr iphdr, struct tcphdr tcphdr, uint8_t *pl, int plen)
{
    // [TODO]: Finish TCP checksum calculation
    uint16_t ip_payload[1024];
    memset(ip_payload, 0, sizeof(ip_payload));
    // header
    memcpy(ip_payload, &tcphdr, tcphdr.doff*4);
    // payload
    memcpy(ip_payload+(tcphdr.doff*2), pl, plen);
    //printf("plen: %d\n", plen);
    return compute_tcp_checksum(&iphdr, ip_payload, plen);
}

// if previous pkt is client -> server, we should not add seq by plen
uint8_t *dissect_tcp(Net *net, Txp *self, uint8_t *segm, size_t segm_len)
{
    // [TODO]: Collect information from segm
    // txp->dissect(net, txp, esp_data, esp->plen);

    // print whole tcp
    /*for(int i=0; i<segm_len; i++){
        printf("%x ", *(segm+i));
    }*/

    // set tcp header
    bzero(&(self->thdr), sizeof(self->thdr));
    memcpy(&(self->thdr), segm, sizeof(struct tcphdr));
    self->hdrlen = sizeof(struct tcphdr);

    //printf("src: %s; dst: %s; x_src: %s; x_dst: %s\n", net->src_ip, net->dst_ip, net->x_src_ip, net->x_dst_ip);

    // (Check IP addr & port to determine the next seq and ack value)
    /*if(strcmp(net->src_ip, net->x_src_ip) == 0){
        self->x_tx_seq = ntohl(self->thdr.seq) + self->plen;
        self->x_tx_ack = ntohl(self->thdr.ack_seq);
    }else{
        self->x_tx_seq = ntohl(self->thdr.seq);
        self->x_tx_ack = ntohl(self->thdr.ack_seq) + self->plen;
    }*/

    //printf("seq: %x; ack: %x\n", self->thdr.seq, self->thdr.ack_seq);
    // payload
    segm += sizeof(struct tcphdr);
    memcpy(self->pl, segm, segm_len-sizeof(struct tcphdr));
    self->plen = segm_len-sizeof(struct tcphdr);

    // print checksum
    //printf("\nchecksum: %x\n", self->thdr.check);
    //printf("revised: %x\n", cal_tcp_cksm(net->ip4hdr, self->thdr, segm, segm_len-sizeof(struct tcphdr))); //compute_tcp_checksum(&net->ip4hdr, ip_payload));
    

    // Return payload of TCP
    return self->pl;
}


// txp.fmt_rep(&txp, net.ip4hdr, data, nb); data is payload
Txp *fmt_tcp_rep(Txp *self, struct iphdr iphdr, uint8_t *data, size_t dlen)
{
    // [TODO]: Fill up self->tcphdr (prepare to send)
    //printf("src p: %x; dst p: %x psh: %x\n", self->x_src_port, self->x_dst_port, self->thdr.psh); 
    //printf("net seg: %x , net ack: %x \n", self->thdr.seq,  self->thdr.ack_seq);
    //printf("[expected] seg: %x; ack: %x\n", self->x_tx_seq,self->x_tx_ack);
    
    // source, dst port
    self->thdr.source = htons(self->x_src_port);
    self->thdr.dest = htons(self->x_dst_port);
    // sequence, ack set as expected ones
    self->thdr.seq = htonl(self->x_tx_seq);
    self->thdr.ack_seq = htonl(self->x_tx_ack);
    // pl
    memcpy(self->pl, data, dlen);
    // psh
    self->thdr.psh = 1;
    // checksum
    self->thdr.check = ntohs(cal_tcp_cksm(iphdr, self->thdr, data, dlen));
    return self;
}

inline void init_txp(Txp *self)
{
    self->pl = (uint8_t *)malloc(IP_MAXPACKET * sizeof(uint8_t));
    self->hdrlen = sizeof(struct tcphdr);

    self->dissect = dissect_tcp;
    self->fmt_rep = fmt_tcp_rep;
}

