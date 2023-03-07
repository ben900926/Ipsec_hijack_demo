#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ifaddrs.h>
#include <unistd.h>


void recur(char* ip_char, uint32_t num){
    if(num <= 0) return;
    uint32_t n = num % 16;
    recur(ip_char, num/16);
    // to char
    char c = 100;
    if(0<=n && n <= 9) c = '0'+n;
    else if(10<=n && n<=15) c = 'a'+(n-10);

    // cat
    ip_char[strlen(ip_char)] = c;
}


uint16_t little_endian16(uint16_t num){
    uint16_t ans = 0;
    ans += (num & 0xff00) >> 8;
    ans += (num & 0x00ff) << 8;
    return ans;
}


uint32_t little_endian(uint32_t num){
    uint32_t ans = 0;
    ans += (num & 0xff000000) >> 24;
    ans += (num & 0x00ff0000) >> 8;
    ans += (num & 0x0000ff00) << 8;
    ans += (num & 0x000000ff) << 24;

    return ans;
}

void uint16_to_char_ip(uint32_t ip, char* ip_char){
    //printf("orig ip: %x\n", ip);
    //printf("orig ip: %x\n", little_endian(ip));
    ip = little_endian(ip);
    recur(ip_char, ip);
    //printf("ip: %s\n", ip_char);
}

uint16_t compute_tcp_checksum(struct iphdr *pIph, unsigned short *ipPayload, int plen) {
    unsigned long sum = 0;
    struct tcphdr *tcphdrp = (struct tcphdr*)(ipPayload);
    unsigned short tcpLen = tcphdrp->doff*4 + plen;// ntohs(pIph->tot_len) - (pIph->ihl<<2);
    
    /*tcphdrp->source = ntohs(tcphdrp->source);
    tcphdrp->dest = ntohs(tcphdrp->dest);
    tcphdrp->seq = ntohl(tcphdrp->seq);
    tcphdrp->ack_seq = ntohl(tcphdrp->ack_seq);

    tcphdrp->window = ntohs(tcphdrp->window);
    tcphdrp->urg_ptr = ntohl(tcphdrp->urg_ptr);*/
    //add the pseudo header 
    //the source ip
    pIph->saddr = ntohl(pIph->saddr);
    sum += (pIph->saddr>>16)&0xFFFF;
    sum += (pIph->saddr)&0xFFFF;
    //printf("(%x), %lx\n",pIph->saddr, sum);
    //the dest ip
    pIph->daddr = ntohl(pIph->daddr);
    sum += (pIph->daddr>>16)&0xFFFF;
    sum += (pIph->daddr)&0xFFFF;
    //printf("(%x), %lx\n",pIph->daddr, sum);
    //protocol and reserved: 6
    sum += IPPROTO_TCP;
    //printf("%lx\n", sum);
    //the length
    sum += (tcpLen);
    //printf("tcplen: %x\n", tcpLen);
    //printf("ip sum: %lx\n", sum);

    //add the IP payload
    //initialize checksum to 0
    tcphdrp->check = 0;
    while (tcpLen > 1) {
        //printf("tcp p: %x\n", ntohs(*(ipPayload)));
        sum += ntohs(*(ipPayload));
        ipPayload++;
        tcpLen -= 2;
    }
    //if any bytes left, pad the bytes and add
    if(tcpLen > 0) {
        //printf("+++++++++++padding, %dn", tcpLen);
        //printf("extra: %x\n", (*ipPayload));
        sum += ((*ipPayload)&htons(0xFF00));
    }
    //printf("tcp header sum: %lx\n", sum);
      //Fold 32-bit sum to 16 bits: add carrier to result
      while (sum>>16) {
          sum = (sum & 0xffff) + (sum >> 16);
      }
      sum = ~sum;
    //set computation result
    tcphdrp->check = (unsigned short)sum;

    return (uint16_t)sum;
}
