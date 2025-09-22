#ifndef MIP_H
#define MIP_H

#include <stdint.h>
#include <stdio.h>		/* printf */
#include <stdlib.h>

#define MIP_SDU_TYPE_PING 0x02
#define MIP_SDU_TYPE_ARP 0x01

#define MIP_BROADCAST_ADDR 0xFF

typedef uint8_t mip_addr_t;

struct mip_hdr { //This implementation is not system independent using << to pack would be better
    uint8_t dst_addr; // 8 bits
    uint8_t src_addr; // 8 bits
    uint8_t ttl; // 4 bits
    uint16_t len_words; //SDU length in words 9 bits
    uint8_t SDU_type; // 3 bits
};


uint32_t mip_pack(const struct mip_hdr *h);
void mip_unpack(uint32_t net_word, struct mip_hdr *h);
//add pack and unpack to ensure cross platform
#endif
