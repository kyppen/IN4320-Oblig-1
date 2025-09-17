#ifndef _COMMON_H
#define _COMMON_H

#include <stdint.h>		/* uint8_t */
#include <unistd.h>		/* size_t */
#include <linux/if_packet.h>	/* struct sockaddr_ll */
#include "mip.h"

#define MAX_EVENTS	10
#define MAX_IF		3
#define ETH_BROADCAST	{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}


struct ether_frame {
    uint8_t dst_addr[6];
    uint8_t src_addr[6];
    uint8_t eth_proto[2];
} __attribute__((packed));

struct mip_header { //This implementation is not system independent using << to pack would be better
    uint32_t dst_addr;
    uint32_t src_addr;
    uint32_t ttl;
    uint32_t len;
    uint32_t SDU;
};

struct ifs_data {
    struct sockaddr_ll addr[MAX_IF];
    int rsock;
    int ifn;
};

typedef struct {
    uint8_t type1bit : 1;
    uint8_t mip_addr : 8;
} MIP_ARP;



void get_mac_from_interfaces(struct ifs_data *);
void print_mac_addr(uint8_t *, size_t);
void init_ifs(struct ifs_data *, int);
int create_raw_socket(void);
int send_arp_request(struct ifs_data *);

int send_arp_response(struct ifs_data *, struct sockaddr_ll *,
              struct ether_frame);
uint32_t mip_pack(struct mip_hdr *hdr);
void mip_unpack(uint32_t raw, struct mip_hdr *hdr);

int handle_arp_packet(struct ifs_data *);

#endif /* _COMMON_H */