#ifndef PDU_H
#define PDU_H

#include <stdint.h>
#include <stddef.h>
#include "ether.h"
#include "mip.h"

struct pdu {
    struct eth_hdr *ethhdr;
    struct mip_hdr *miphdr;
    uint8_t *sdu;
};

struct pdu * pdu_alloc(void);

void fill_pdu(struct pdu *pdu,
    uint8_t *src_mac_addr,
    uint8_t *dst_mac_addr,
    uint8_t src_ip_addr,
    uint8_t dst_ip_addr,
    uint8_t ttl_4bit,
    uint8_t sdu_type,
    const char *sdu_ascii
    );

size_t mip_serialize_pdu(const struct pdu *pdu, uint8_t *send_buffer);
size_t mip_deserialize_pdu(struct pdu *pdu, uint8_t *recv_buffer);

void destroy_pdu(struct pdu *pdu);
void print_pdu(struct pdu *pdu);
//destroy

#endif
