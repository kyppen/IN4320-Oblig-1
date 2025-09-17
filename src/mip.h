#ifndef MIP_H
#define MIP_H

#include <stdint.h>
#include <stdio.h>		/* printf */
#include <stdlib.h>
#define ETH_P_MIP 0x88B5

#define MIP_SDU_PING 0x01
#define MIP_SDU_ARP 0x02

#define MIP_BROADCAST_ADDR 0xFF

typedef uint8_t mip_addr_t;

struct mip_hdr { //This implementation is not system independent using << to pack would be better
    uint32_t dst_addr;
    uint32_t src_addr;
    uint32_t ttl;
    uint32_t len;
    uint32_t SDU_type;
};

//add pack and unpack to ensure cross platform
#endif
