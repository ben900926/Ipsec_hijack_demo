#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <linux/pfkeyv2.h> // sadb_dump? sadb_key struct(2.3.4), pf_key message(2.4)
#include <netinet/tcp.h> // for tcp header (esp payload)

#include "esp.h"
#include "transport.h"
#include "hmac.h"

EspHeader esp_hdr_rec;

/*
Getting the key from the extension with sadb_ext_type “SADB_EXT_KEY_AUTH” (8)
*/

void print_sadb_msg(struct sadb_msg* msg){
    printf("sadb key:\n");
    printf("msg_type: %x\n", msg->sadb_msg_type);
    printf("msg_satype: %x\n", msg->sadb_msg_satype);
    printf("len: %x\n", msg->sadb_msg_len);
    printf("pid: %x\n", msg->sadb_msg_pid);
    printf("\n ------- \n");

        
    /*printf("key: \n");
    for(int i=0; i<key_len*8-8; i++){
        printf("%x ", *(key+i));
    }
    // print msg
    printf("\nsadb_msg: \n");
    for(int i=0; i<msg_len; i++){
        printf("%x ", *(buf+i));
    }
    printf("\n ------- \n");*/
}


// type: security association type
void get_ik(int type, uint8_t *key)
{
    // [TODO]: Dump authentication key from security association database (SADB)
    // (Ref. RFC2367 Section 2.3.4 & 2.4 & 3.1.10)

    // sadb_dump 
    // sending socket to kernel
    int s = socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
    if(s<0){
        perror("socket: ");
        return;
    }

    char buf[4096];
    struct sadb_msg msg;

    // build and write SADB_DUMP request
    bzero(&msg, sizeof(msg)); 
    msg.sadb_msg_version = PF_KEY_V2;
    msg.sadb_msg_type = SADB_DUMP;
    msg.sadb_msg_satype = type;
    msg.sadb_msg_len = sizeof(msg) / 8;
    msg.sadb_msg_pid = getpid();
    //print_sadb_msg(&msg);
    //printf("[sadb_dump]: sending dump message\n");
    if(write(s, &msg, sizeof(msg))<0){
        perror("write: ");
        return;
    }

    // read and print SADB_DUMP replies until done
    int goteof = 0;
    while(goteof == 0){
        int msg_len = 0;
        struct sadb_msg* msg_p;

        msg_len = read(s, &buf, sizeof(buf));
        if(msg_len<0){
            perror("read:");
            return;
        }
        //printf("msg_len: %d; sadb_msg_size: %ld\n", msg_len, sizeof(struct sadb_msg));
        // base header
        msg_p = (struct sadb_msg*)&buf;
        //print_sadb_msg(msg_p);
        if(msg_p->sadb_msg_seq == 0){
            goteof = 1;
        }

        // ext_len; ext_type (2 byte)
        int i = 0;
        uint16_t ext_len, ext_type;
        while(true){
            ext_len = *(buf+16+i) + *(buf+16+i+1)*16;
            ext_type = *(buf+16+i+2) + *(buf+16+i+3)*16;

            if(ext_type == SADB_EXT_KEY_AUTH){
                struct sadb_key key_f;
                memcpy(&key_f, buf+16+i, sizeof(struct sadb_key));
                
                // get key data
                memcpy(key, buf+16+i+8, key_f.sadb_key_bits / 8 );
                break;
            }else{
                i += (ext_len * 8);
            }
        }
    
        // associate header(16), lifetime(32), address(8)
        /*struct sadb_sa sa;
        memcpy(&sa, buf+16, 16);
        printf("sa ext: %x\n", sa.sadb_sa_exttype);
        //printf("sa len: %d\n", sa.sadb_sa_len);
        
        struct sadb_lifetime lf;
        memcpy(&lf, buf+32, 32);
        printf("lf ext: %x\n", lf.sadb_lifetime_exttype);
        
        
        // address involved in Ipsec ----- ?
        struct sadb_address addr;
        memcpy(&addr, buf+64, 8); // 64-bit as unit: 32 byte
        printf("addr ext: %x\n", addr.sadb_address_exttype);
        //printf("addr len: %d %d\n", addr_len, addr.sadb_address_len);
        
        // key ext
        struct sadb_key key_s;
        memcpy(&key_s, buf+64+addr.sadb_address_len*8, 8);
        printf("key ext: %x\n", key_s.sadb_key_exttype);
        // allocate key data
        //memcpy(key, buf+64+addr_len*8+8, key_len*8-8);

        printf("key: \n");
        for(int i=0; i<key_len*8-8; i++){
            printf("%x ", *(key+i));
        }
        // print msg
        printf("\nsadb_msg: \n");
        for(int i=0; i<msg_len; i++){
            printf("%x ", *(buf+i));
        }
        printf("\n ------- \n");*/

    }
    close(s);
}

// esp->get_key(esp);
void get_esp_key(Esp *self)
{
    get_ik(SADB_SATYPE_ESP, self->esp_key);
}

// esp.set_padpl(&esp);
uint8_t *set_esp_pad(Esp *self)
{
    // [TODO]: Fill up self->pad and self->pad_len (Ref. RFC4303 Section 2.4)

    // make sure esp header + payload + trailer is multiple of 4-byte
    int temp = 8 + self->plen + 2;
    temp = temp % 4;
    if(temp>0) self->tlr.pad_len = 4 - temp;
    else self->tlr.pad_len = 0;

    *(self->pad) = 0;
    for(uint8_t i=0; i<self->tlr.pad_len; i++){
        *(self->pad+i) = i+1;
    }

    return self->pad;
}

uint8_t *set_esp_auth(Esp *self,
                      ssize_t (*hmac)(uint8_t const *, size_t,
                                      uint8_t const *, size_t,
                                      uint8_t *))
{
    if (!self || !hmac) {
        fprintf(stderr, "Invalid arguments of %s().\n", __func__);
        return NULL;
    }

    uint8_t buff[BUFSIZE];
    size_t esp_keylen = 16;
    size_t nb = 0;  // Number of bytes to be hashed
    ssize_t ret;

    // [TODO]: Put everything needed to be authenticated into buff and add up nb
    // compute over esp header, payload,(and padding) trailer (2.8 section)
    uint32_t hd1 = self->hdr.spi;
    uint32_t hd2 = self->hdr.seq;
    memcpy(buff, &hd1, 4);
    memcpy(buff + 4, &hd2, 4);
    memcpy(buff + 8, self->pl, self->plen);
    memcpy(buff + 8 + self->plen, self->pad, self->tlr.pad_len);
    memcpy(buff + 8 + self->plen + self->tlr.pad_len, &self->tlr, 2);

    nb = 10 + self->plen + self->tlr.pad_len;
    
    ret = hmac(self->esp_key, esp_keylen, buff, nb, self->auth);

    if (ret == -1) {
        fprintf(stderr, "Error occurs when try to compute authentication data");
        return NULL;
    }

    self->authlen = ret;
    return self->auth;
}

uint8_t *dissect_esp(Esp *self, uint8_t *esp_pkt, size_t esp_len)
{
    // [TODO]: Collect information from esp_pkt.
    // Return payload of ESP
    // esp header
    memcpy(&(self->hdr), esp_pkt, sizeof(self->hdr));
    
    /*printf("\n ------  esp packet: \n");
    for(int i=0; i<esp_len; i++){
        printf("%x ", *(esp_pkt+i));
    }
    printf(" ------ ------\n");*/

    // payload is TCP packet
    esp_pkt += 8;
    uint8_t *payload = (uint8_t*)malloc(200);
    // tcp hdr len
    int len = *(esp_pkt+12)/16 * 4;
    //printf("tcp hdr len: %d\n", len);
    // tcp header
    memcpy(payload, esp_pkt, len);
    esp_pkt += len;
    // tcp payload length
    int tcp_len = esp_len - 8;
    uint8_t pad_len = *(esp_pkt+esp_len-8-len - 12 - 1 - 1); // padlen, nxthdr, auth data, 
    //printf("pad len: %u\n", pad_len);
    tcp_len = tcp_len - 12 -1 -1 - pad_len; // esp auth data
    // tcp payload
    for(int i=0; i<tcp_len-len; i++){
        payload[len + i] = *(esp_pkt+i);
    }
    memcpy(self->pl, payload, len+tcp_len);
    self->plen = tcp_len; // tcp header + payload
    //printf("esp plen: %lu\n", self->plen);

    esp_pkt += tcp_len-len; // tcp_len: tcp header + payload length

    // padding, padding length is the same as last padding
    memcpy(self->pad, esp_pkt, pad_len);
    esp_pkt += pad_len;
    // plen, next
    memcpy(&(self->tlr), esp_pkt, sizeof(self->tlr));
    esp_pkt += sizeof(self->tlr);

    // 12 byte authe data
    memcpy((self->auth), esp_pkt, 12);
    self->authlen = 12;

    return payload;
}

// esp.fmt_rep(&esp, TCP);
Esp *fmt_esp_rep(Esp *self, Proto p)
{
    // [TODO]: Fill up ESP header and trailer (prepare to send)
    self->hdr.seq = (esp_hdr_rec.seq) + 1;
    self->hdr.spi = (esp_hdr_rec.spi);
    //printf("spi:%x; seq:%x\n", self->hdr.spi, self->hdr.seq);
    self->hdr.seq = htonl(self->hdr.seq);

    self->tlr.nxt = p;
    //printf("pad_len:%x; next:%x\n", self->tlr.pad_len, self->tlr.nxt);
    
    return self;
}

void init_esp(Esp *self)
{
    self->pl = (uint8_t *)malloc(MAXESPPLEN * sizeof(uint8_t));
    self->pad = (uint8_t *)malloc(MAXESPPADLEN * sizeof(uint8_t));
    self->auth = (uint8_t *)malloc(HMAC96AUTHLEN * sizeof(uint8_t));
    self->authlen = HMAC96AUTHLEN;
    self->esp_key = (uint8_t *)malloc(BUFSIZE * sizeof(uint8_t));

    self->set_padpl = set_esp_pad;
    self->set_auth = set_esp_auth;
    self->get_key = get_esp_key;
    self->dissect = dissect_esp;
    self->fmt_rep = fmt_esp_rep;
}
