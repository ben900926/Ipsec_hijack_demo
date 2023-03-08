#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ifaddrs.h>
#include <unistd.h>

#include "net.h"
#include "transport.h"
#include "esp.h"
#include "utils.h"

uint16_t cal_ipv4_cksm(struct iphdr iphdr)
{
    // [TODO]: Finish IP checksum calculation
    unsigned long sum = 0;
    // compute checksum every 16-bit
    unsigned int ip_len = iphdr.ihl << 2;
    iphdr.check = 0;
    uint16_t *ip_16 = (uint16_t*)malloc(100);
    memcpy(ip_16, &iphdr, ip_len);

    while (ip_len > 1)
    {
        //printf("%x\n",(*ip_16));
        sum += ntohs(*(ip_16));
        ip_16++;
        ip_len -= 2;
    }
    // pad byte if a length left
    if(ip_len > 0){
        sum += (*ip_16)&0x00ff;
    }
    // fold sum to 16-bit
    while(sum >> 16){
        sum = (sum & 0xffff) + (sum >> 16);
    }
    // one's complement
    sum = ~sum;
    iphdr.check = (uint16_t)sum;
    return (uint16_t)sum;
}

uint8_t *dissect_ip(Net *self, uint8_t *pkt, size_t pkt_len)
{
    // [TODO]: Collect information from pkt.
    // Return payload of network layer
    
    // (net, dev->frame + LINKHDRLEN, dev->framelen - LINKHDRLEN); in replay.c
    // 20 bytes: ip4hdr
    memcpy(&(self->ip4hdr), pkt, sizeof(self->ip4hdr));
    
    // protocol
    self->pro = self->ip4hdr.protocol;
    // ip (network byte order char)
    bzero(self->src_ip, strlen(self->src_ip));
    bzero(self->dst_ip, strlen(self->dst_ip));
    
    uint16_to_char_ip(self->ip4hdr.saddr, self->src_ip);
    uint16_to_char_ip(self->ip4hdr.daddr, self->dst_ip);
    //printf("src ip: %s dst ip: %s\n", self->src_ip, self->dst_ip);
    // header length
    self->hdrlen = self->ip4hdr.ihl * 4;
    // total length
    self->plen = pkt_len - self->hdrlen;

    return pkt + self->hdrlen;
}

Net *fmt_net_rep(Net *self)
{
    // [TODO]: Fill up self->ip4hdr (prepare to send)
    self->ip4hdr.tot_len = ntohs(self->plen + self->hdrlen);
    //printf("plen: %u, hdrlen: %lu\n", self->plen, self->hdrlen);
    self->ip4hdr.check = ntohs(cal_ipv4_cksm(self->ip4hdr));
    // ip
    if (strcmp(self->x_dst_ip, self->src_ip) == 0) {
        uint32_t tmp = self->ip4hdr.saddr;
        self->ip4hdr.saddr = self->ip4hdr.daddr;
        self->ip4hdr.daddr = tmp;
    }
    return self;
}

void init_net(Net *self)
{
    if (!self) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        exit(EXIT_FAILURE);
    }

    self->src_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->dst_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->x_src_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->x_dst_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->hdrlen = sizeof(struct iphdr);

    self->dissect = dissect_ip;
    self->fmt_rep = fmt_net_rep;
}


