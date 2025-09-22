#ifndef _COMMON_H
#define _COMMON_H

#include <stdint.h>		/* uint8_t */
#include <unistd.h>		/* size_t */
#include <linux/if_packet.h>	/* struct sockaddr_ll */
#include "mip.h"
#include "pdu.h"

#define MAX_EVENTS	10
#define MAX_IF		3
#define ETH_BROADCAST	{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}


struct ether_frame {
    uint8_t dst_addr[6];
    uint8_t src_addr[6];
    uint8_t eth_proto[2];
} __attribute__((packed));

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
int send_mip_packet(struct ifs_data *,
    uint8_t *src_mac_addr,
    uint8_t *dst_mac_addr,
    uint8_t src_mip_addr,
    uint8_t dst_mip_addr,
    uint8_t ttl_4bit,
    uint8_t sdu_type,
    const char *sdu_ascii);
int handle_mip_packet(struct ifs_data *ifs, const char *app_mode);
int handle_arp_packet(struct ifs_data *);
void print_pdu_content(const struct pdu *pdu);

#endif /* _COMMON_H */