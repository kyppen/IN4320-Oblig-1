

#include <assert.h>
#include <stdint.h>

#include "ether.h"
#include "pdu.h"

#include <string.h>

#include "common.h"

size_t align4(size_t n) {
	size_t rem = n % 4;
	if (rem == 0) return n;
	return n + (4 - rem);
}

void fill_pdu(struct pdu *pdu,
              uint8_t *src_mac_addr,
              uint8_t *dst_mac_addr,
              uint8_t src_mip_addr,
              uint8_t dst_mip_addr,
              uint8_t ttl_4bit,
              uint8_t sdu_type,
              const char *sdu_ascii)
{
    assert(pdu && pdu->ethhdr);
    assert(src_mac_addr && dst_mac_addr);

    assert(ETH_ADDR_LEN == 6);
    if (ETH_ADDR_LEN == 6) {
        printf("ETH_ADDR_LEN == 6\n");
    }

    printf("sizeof %lu\n", sizeof(pdu->ethhdr->src_mac));
    printf("sizeof %lu\n", sizeof(pdu->ethhdr->dst_mac));
    _Static_assert(ETH_ADDR_LEN == 6, "ETH_ADDR_LEN MUST BE 6");
    _Static_assert(sizeof(pdu->ethhdr->src_mac) == 6, "src_mac must be 6 bytes");
    _Static_assert(sizeof(pdu->ethhdr->dst_mac) == 6, "dst_mac must be 6 bytes");

    memcpy(pdu->ethhdr->src_mac, src_mac_addr, ETH_ADDR_LEN);
    memcpy(pdu->ethhdr->dst_mac, dst_mac_addr, ETH_ADDR_LEN);
    pdu->ethhdr->ethertype = htons(ETH_P_MIP);

    pdu->miphdr->dst_addr = dst_mip_addr;
    pdu->miphdr->src_addr = src_mip_addr;
    pdu->miphdr->ttl = ttl_4bit & 0x0F;// 4 bits
    pdu->miphdr->SDU_type = sdu_type & 0x07; // 3 bits

    size_t slen = sdu_ascii ? (strlen(sdu_ascii) + 1) : 0;
    size_t padded = align4(slen);

    free(pdu->sdu);


    if (padded) { // if padded is more then 0 we need to allocate
        pdu->sdu = calloc(1, padded);
        if (pdu->sdu && sdu_ascii && slen) {
            memcpy(pdu->sdu, sdu_ascii, slen);
        }
    } else {
        pdu->sdu = NULL;
    }
    pdu->miphdr->len_words = (uint16_t)(padded / 4);
}

void print_pdu_content(const struct pdu *pdu)
{
    printf("====================================================\n");
    printf("\tSource MAC:      "); print_mac_addr(pdu->ethhdr->src_mac, ETH_ADDR_LEN);
    printf("\tDestination MAC: "); print_mac_addr(pdu->ethhdr->dst_mac, ETH_ADDR_LEN);
    printf("\tEthertype:       0x%04x\n", ntohs(pdu->ethhdr->ethertype));
    printf("\tMIP src:         %u\n", pdu->miphdr->src_addr);
    printf("\tMIP dst:         %u\n", pdu->miphdr->dst_addr);
    printf("\tTTL:		    %u\n", pdu->miphdr->ttl & 0x0F);
    //printf("\tSDU type:        0x%02x\n", pdu->miphdr->SDU_type & 0x07);
    printf("\tSDU type:        0x%02x\n", pdu->miphdr->SDU_type);
    printf("\tSDU length:      %u bytes\n", (unsigned)(pdu->miphdr->len_words * 4));

    if (pdu->sdu) {
        printf("\tSDU (ascii):     %s\n", (const char*)pdu->sdu);
    }
    printf("====================================================\n");
}

struct pdu * pdu_alloc(void) {
	printf("Gay\n");
	struct pdu *pdu = calloc(1,sizeof(*pdu));
	if (!pdu) return NULL;
	pdu->ethhdr = (struct eth_hdr*)calloc(1, sizeof (*pdu->ethhdr));
	pdu->miphdr = (struct mip_hdr*)calloc(1, sizeof (*pdu->miphdr));
	printf("pdu_alloc_2\n");

	if (!pdu->miphdr || !pdu->ethhdr) {
		fprintf(stderr, "Memory allocation failed\n");
		destroy_pdu(pdu);
		return NULL;
	}
	printf("pdu_alloc_2\n");
	//Setting some default values incase
	pdu->ethhdr->ethertype = htons(ETH_P_MIP);
	pdu->miphdr->dst_addr = 0;
	pdu->miphdr->src_addr = 0;
	pdu->miphdr->ttl = 1; // default to once to avoid Broadcast storm. Will be overwritten anyway
	pdu->miphdr->len_words = 0;
	pdu->miphdr->SDU_type = MIP_SDU_TYPE_PING;
	printf("gay2\n");
	return pdu;
}

void destroy_pdu(struct pdu *pdu) {
	if (!pdu) {
		return;
	}
	free(pdu->ethhdr);
	free(pdu->miphdr);
	free(pdu->sdu);
	free(pdu);
}


size_t mip_serialize_pdu(const struct pdu *pdu, uint8_t *send_buffer) {
	size_t send_len = 0;

	memcpy(send_buffer + send_len, pdu->ethhdr, ETH_HDR_LEN);
	send_len += ETH_HDR_LEN;

	uint32_t net_mip = mip_pack(pdu->miphdr);
	memcpy(send_buffer + send_len, &net_mip, 4);
	send_len += 4;

	size_t sdu_bytes = pdu->miphdr->len_words * 4;
	if (sdu_bytes && pdu->sdu) {
		memcpy(send_buffer + send_len, pdu->sdu, sdu_bytes);
		send_len += sdu_bytes;
	}
	return send_len;
}

size_t mip_deserialize_pdu(struct pdu *pdu, uint8_t *recv_buffer) {

	size_t offset = 0;

	pdu->ethhdr = malloc(sizeof(struct eth_hdr));
	memcpy(pdu->ethhdr, recv_buffer + offset, ETH_HDR_LEN);
	offset += ETH_HDR_LEN;
	pdu->miphdr = malloc(sizeof(struct mip_hdr));

	uint32_t net_mip = 0;
	memcpy(&net_mip, recv_buffer + offset, 4);
	offset += 4;
	mip_unpack(net_mip, pdu->miphdr);


	size_t sdu_bytes = pdu->miphdr->len_words * 4;
	if (sdu_bytes > 0) {
		pdu->sdu = calloc(1, sdu_bytes);
		memcpy(pdu->sdu, recv_buffer + offset, sdu_bytes);
		offset += sdu_bytes;
	} else {
		pdu->sdu = NULL;
	}
	return offset;
}

