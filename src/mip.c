#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>

#include "mip.h"

uint32_t mip_pack(const struct mip_hdr *h) {
    
    uint8_t ttl = (uint8_t)(h->ttl & 0x0F);
    uint16_t len = (uint16_t)(h->len_words & 0x01FF);
    uint8_t type3 = (uint8_t)(h->SDU_type & 0x07);

    uint32_t packed = 0;

    packed |= ((uint32_t)h->dst_addr) << 24;
    packed |= ((uint32_t)h->src_addr) << 16;
    packed |= ((uint32_t)ttl) << 12;
    packed |= ((uint32_t)len) << 3;
    packed |= ((uint32_t)type3);

    return htonl(packed); // Convert struct to network byte order
}

void mip_unpack(uint32_t raw, struct mip_hdr *h) {
    uint32_t unpacked = ntohl(raw);

    h->dst_addr = (unpacked >> 24);
    h->src_addr = (unpacked >> 16);
    h->ttl = (unpacked >> 12) & 0x0F;
    h->len_words = (unpacked >> 3) & 0x1FF;
    h->SDU_type = unpacked & 0x07;
}