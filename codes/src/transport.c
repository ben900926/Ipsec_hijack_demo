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

uint16_t cal_tcp_cksm(struct iphdr iphdr, struct tcphdr tcphdr, uint8_t *pl, int plen)
{
    // [TODO]: Finish TCP checksum calculation
    long sum = 0;

    // Ip header 
    // source ip
    sum += (uint16_t)(iphdr.saddr >> 8);
    sum += (uint16_t)(iphdr.saddr & 0x00ff);
    // destination ip
    sum += (uint16_t)(iphdr.saddr >> 8);
    sum += (uint16_t)(iphdr.saddr & 0x00ff);
    // protocol
    sum += (uint16_t)(iphdr.protocol);
    // header length
    sum += (uint16_t)(iphdr.ihl);

    // tcp header
    // source port
    sum += (uint16_t)(tcphdr.th_sport >> 8);
    sum += (uint16_t)(tcphdr.th_sport & 0x00ff);
    // destin. port
    sum += (uint16_t)(tcphdr.th_dport >> 8);
    sum += (uint16_t)(tcphdr.th_dport & 0x00ff);
    // sequence number
}

uint8_t *dissect_tcp(Net *net, Txp *self, uint8_t *segm, size_t segm_len)
{
    // [TODO]: Collect information from segm
    // (Check IP addr & port to determine the next seq and ack value)
    // Return payload of TCP
}

Txp *fmt_tcp_rep(Txp *self, struct iphdr iphdr, uint8_t *data, size_t dlen)
{
    // [TODO]: Fill up self->tcphdr (prepare to send)

    return self;
}

inline void init_txp(Txp *self)
{
    self->pl = (uint8_t *)malloc(IP_MAXPACKET * sizeof(uint8_t));
    self->hdrlen = sizeof(struct tcphdr);

    self->dissect = dissect_tcp;
    self->fmt_rep = fmt_tcp_rep;
}

int main(){
    struct tcphdr t;
    bzero(&t, sizeof(struct tcphdr));
    t.th_sport = 0xf3dd;
    t.th_dport = 0x0cd3;
}