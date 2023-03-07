#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ifaddrs.h>
#include <unistd.h>


void recur(char* ip_char, uint32_t num);


uint16_t little_endian16(uint16_t num);


uint32_t little_endian(uint32_t num);

void uint16_to_char_ip(uint32_t ip, char* ip_char);

uint16_t compute_tcp_checksum(struct iphdr *pIph, unsigned short *ipPayload, int plen);