#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/ioctl.h>
#include <net/if.h> // interface card data structure (wlan0), ifreq struct
#include <linux/if_ether.h> // define ethernet protocol's ID
#include <arpa/inet.h>

#include "dev.h"
#include "net.h"
#include "esp.h"
#include "replay.h"
#include "transport.h"

inline static int get_ifr_mtu(struct ifreq *ifr)
{
    int fd;

    if ((fd = socket(PF_PACKET, SOCK_RAW, 0)) < 0) {
        perror("socket()");
        exit(EXIT_FAILURE);
    }

    if (ioctl(fd, SIOCGIFMTU, ifr) < 0) {
        perror("ioctl()");
        close(fd);
        exit(EXIT_FAILURE);
    }

    return ifr->ifr_mtu;
}

inline static struct sockaddr_ll init_addr(char *name)
{
    struct sockaddr_ll addr;
    bzero(&addr, sizeof(addr));

    // [TODO]: Fill up struct sockaddr_ll addr which will be used to bind in func set_sock_fd
    struct ifreq ifr;
    strncpy((char*)ifr.ifr_name, name, IFNAMSIZ);
    
    // NOT SURE !! --> using ioctl get index
    int fd;
    if ((fd = socket(PF_PACKET, SOCK_RAW, 0)) < 0) {
        perror("socket() in init_addr");
        exit(EXIT_FAILURE);
    }

    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl() in init_addr");
        close(fd);
        exit(EXIT_FAILURE);
    }
    addr.sll_ifindex = ifr.ifr_ifindex;
    // printf("index: %d\n", addr.sll_ifindex);
    // others
    addr.sll_family = PF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL); //internet protocol packet


    if (addr.sll_ifindex == 0) {
        perror("if_nameindex()");
        exit(EXIT_FAILURE);
    }

    return addr;
}

inline static int set_sock_fd(struct sockaddr_ll dev)
{
    int fd;

    if ((fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        perror("socket()");
        exit(EXIT_FAILURE);
    }

    bind(fd, (struct sockaddr *)&dev, sizeof(dev));

    return fd;
}

void fmt_frame(Dev *self, Net net, Esp esp, Txp txp)
{
    // [TODO]: store the whole frame into self->frame
    // and store the length of the frame into self->framelen

    // link header
    memcpy(self->frame,
    self->linkhdr, LINKHDRLEN);
    // Net: iphdr
    memcpy(self->frame + LINKHDRLEN, 
    &(net.ip4hdr), net.hdrlen);
    
    // Esp: ESP headers, payload, 
    memcpy(self->frame + LINKHDRLEN + net.hdrlen, 
    &(esp.hdr), 8);
    
    // tcp
    memcpy(self->frame + LINKHDRLEN + net.hdrlen + 8, 
    &(txp.thdr), txp.hdrlen);
    memcpy(self->frame + LINKHDRLEN + net.hdrlen + 8 + txp.hdrlen, 
    txp.pl, txp.plen);
    
    // esp trailer
    memcpy(self->frame + LINKHDRLEN + net.hdrlen + 8 + txp.hdrlen + txp.plen, 
    esp.pad, esp.tlr.pad_len);
    memcpy(self->frame + LINKHDRLEN + net.hdrlen + 8 + txp.hdrlen + txp.plen + esp.tlr.pad_len, 
    &(esp.tlr), 2);
    
    // esp auth data
    memcpy(self->frame + LINKHDRLEN + net.hdrlen + 10 + txp.hdrlen + txp.plen + esp.tlr.pad_len, 
    esp.auth, esp.authlen);

    self->framelen = net.hdrlen + LINKHDRLEN + 10 + txp.hdrlen + txp.plen + esp.tlr.pad_len + esp.authlen;

    // print out
    for(int i=0 ;i<self->framelen; i++){
        printf("%x ", *(self->frame+i));
    }
    printf("\n ============ \n");

}

ssize_t tx_frame(Dev *self)
{
    if (!self) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        return -1;
    }

    ssize_t nb;
    socklen_t addrlen = sizeof(self->addr);

    nb = sendto(self->fd, self->frame, self->framelen,
                0, (struct sockaddr *)&self->addr, addrlen);

    if (nb <= 0) perror("sendto()");

    return nb;
}

// receive and store in dev->frame
ssize_t rx_frame(Dev *self)
{
    if (!self) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        return -1;
    }

    ssize_t nb;
    socklen_t addrlen = sizeof(self->addr);

    nb = recvfrom(self->fd, self->frame, self->mtu,
                  0, (struct sockaddr *)&self->addr, &addrlen);
    if (nb <= 0)
        perror("recvfrom()");

    return nb;
}

// dev_name: wlan0
void init_dev(Dev *self, char *dev_name)
{
    if (!self || !dev_name || strlen(dev_name) + 1 > IFNAMSIZ) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        exit(EXIT_FAILURE);
    }

    struct ifreq ifr;
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", dev_name);

    self->mtu = get_ifr_mtu(&ifr);

    self->addr = init_addr(dev_name);
    self->fd = set_sock_fd(self->addr);
    //printf("FD(modified): %d\n", self->fd);
    //return;

    self->frame = (uint8_t *)malloc(BUFSIZE * sizeof(uint8_t));
    self->framelen = 0;

    self->fmt_frame = fmt_frame;
    self->tx_frame = tx_frame;
    self->rx_frame = rx_frame;

    self->linkhdr = (uint8_t *)malloc(LINKHDRLEN);
}


 