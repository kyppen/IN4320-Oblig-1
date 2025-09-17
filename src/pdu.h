#ifndef PDU_H
#define PDU_H

#include <stdint.h>
#include <stddef.h>
#include "ether.h"
#include "mip.h"

struct pdu {
    struct eth_hdr *eth_header;
    struct mip_header *mip_header;
};