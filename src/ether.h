#ifndef ETHER_H
#define ETHER_H

#include <stdint.h>
#include <arpa/inet.h>

#define ETH_ADDR_LEN 6
#define ETH_HDR_LEN 14

#define ETH_P_MIP 0x88B5


struct eth_hdr {
    uint8_t dst_mac[ETH_ADDR_LEN];
    uint8_t src_mac[ETH_ADDR_LEN];
    uint16_t ether_type;
} __attribute__((__packed__));

#endif
