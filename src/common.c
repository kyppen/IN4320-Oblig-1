#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ifaddrs.h>		/* getifaddrs */
#include <arpa/inet.h>		/* htons */
#include <stdint.h>
#include <sys/socket.h>	/* socket */

#include "common.h"
#include "mip.h"
#include "pdu.h"
/*
 * Print MAC address in hex format
 */

void print_mac_addr(uint8_t *addr, size_t len)
{
	size_t i;

	for (i = 0; i < len - 1; i++) {
		printf("%02x:", addr[i]);
	}
	printf("%02x\n", addr[i]);
}

/*
 * This function stores struct sockaddr_ll addresses for all interfaces of the
 * node (except loopback interface)
 */
void get_mac_from_interfaces(struct ifs_data *ifs)
{
	struct ifaddrs *ifaces, *ifp;
	int i = 0;

	/* Enumerate interfaces: */
	/* Note in man getifaddrs that this function dynamically allocates
	   memory. It becomes our responsability to free it! */
	if (getifaddrs(&ifaces)) {
		perror("getifaddrs");
		exit(-1);
	}

	/* Walk the list looking for ifaces interesting to us */
	for (ifp = ifaces; ifp != NULL; ifp = ifp->ifa_next) {
		/* We make sure that the ifa_addr member is actually set: */
		if (ifp->ifa_addr != NULL &&
		    ifp->ifa_addr->sa_family == AF_PACKET &&
		    strcmp("lo", ifp->ifa_name))
		/* Copy the address info into the array of our struct */
		memcpy(&(ifs->addr[i++]),
		       (struct sockaddr_ll*)ifp->ifa_addr,
		       sizeof(struct sockaddr_ll));
	}
	/* After the for loop, the address info of all interfaces are stored */
	/* Update the counter of the interfaces */
	ifs->ifn = i;

	/* Free the interface list */
	freeifaddrs(ifaces);
}

void init_ifs(struct ifs_data *ifs, int rsock)
{
	/* Walk through the interface list */
	get_mac_from_interfaces(ifs);

	/* We use one RAW socket per node */
	ifs->rsock = rsock;
}

int create_raw_socket(void)
{
	int sd;
	short unsigned int protocol = 0xFFFF;

	/* Set up a raw AF_PACKET socket without ethertype filtering */
	sd = socket(AF_PACKET, SOCK_RAW, htons(protocol));
	if (sd == -1) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	return sd;
}

int send_arp_request(struct ifs_data *ifs)
{
	struct ether_frame frame_hdr;
	struct msghdr	*msg;
	struct iovec	msgvec[1];
	int    rc;

	/* Fill in Ethernet header. ARP request is a BROADCAST packet. */
	uint8_t dst_addr[] = ETH_BROADCAST;

	memcpy(frame_hdr.dst_addr, dst_addr, 6);
	memcpy(frame_hdr.src_addr, ifs->addr[0].sll_addr, 6);
	/* Match the ethertype in packet_socket.c: */
	frame_hdr.eth_proto[0] = frame_hdr.eth_proto[1] = 0xFF;

	/* Point to frame header */
	msgvec[0].iov_base = &frame_hdr;
	msgvec[0].iov_len  = sizeof(struct ether_frame);

	/* Allocate a zeroed-out message info struct */
	msg = (struct msghdr *)calloc(1, sizeof(struct msghdr));

	/* Fill out message metadata struct */
	/* host A and C (senders) have only one interface, which is stored in
	 * the first element of the array when we walked through the interface
	 * list.
	 */
	msg->msg_name	 = &(ifs->addr[0]);
	msg->msg_namelen = sizeof(struct sockaddr_ll);
	msg->msg_iovlen	 = 1;
	msg->msg_iov	 = msgvec;

	/* Send message via RAW socket */
	rc = sendmsg(ifs->rsock, msg, 0);
	if (rc == -1) {
		perror("sendmsg");
		free(msg);
		return -1;
	}

	/* Remember that we allocated this on the heap; free it */
	free(msg);

	return rc;
}

int handle_arp_packet(struct ifs_data *ifs)
{
	struct sockaddr_ll so_name;
	struct ether_frame frame_hdr;
	struct msghdr	msg = {0};
	struct iovec	msgvec[1];
	int    rc;

	/* Point to frame header */
	msgvec[0].iov_base = &frame_hdr;
	msgvec[0].iov_len  = sizeof(struct ether_frame);

	/* Fill out message metadata struct */
	msg.msg_name	= &so_name;
	msg.msg_namelen = sizeof(struct sockaddr_ll);
	msg.msg_iovlen	= 1;
	msg.msg_iov	= msgvec;

	rc = recvmsg(ifs->rsock, &msg, 0);
	if (rc <= 0) {
		perror("sendmsg");
		return -1;
	}

	/* Send back the ARP response via the same receiving interface */
	/* Send ARP response only if the request was a broadcast ARP request
	 * This is so dummy!
	 */
	int check = 0;
	uint8_t brdcst[] = ETH_BROADCAST;
	for (int i = 0; i < 6; i++) {
		if (frame_hdr.dst_addr[i] != brdcst[i])
		check = -1;
	}
	if (!check) {
		/* Handling an ARP request */
		printf("\nWe received a handshake offer from the neighbor: ");
		print_mac_addr(frame_hdr.src_addr, 6);

		/* print the if_index of the receiving interface */
		printf("We received an incoming packet from iface with index %d\n",
		       so_name.sll_ifindex);

		rc = send_arp_response(ifs, &so_name, frame_hdr);
		if (rc < 0)
		perror("send_arp_response");
	}

	/* Node received an ARP Reply */
	printf("\nHello from neighbor ");
	print_mac_addr(frame_hdr.src_addr, 6);

	return rc;
}



int send_arp_response(struct ifs_data *ifs, struct sockaddr_ll *so_name,
		      struct ether_frame frame)
{
	struct msghdr *msg;
	struct iovec msgvec[1];
	int rc;

	/* Swap MAC addresses of the ether_frame to send back (unicast) the ARP
	 * response */
	memcpy(frame.dst_addr, frame.src_addr, 6);

	/* Find the MAC address of the interface where the broadcast packet came
	 * from. We use sll_ifindex recorded in the so_name. */
	for (int i = 0; i < ifs->ifn; i++) {
		if (ifs->addr[i].sll_ifindex == so_name->sll_ifindex)
		memcpy(frame.src_addr, ifs->addr[i].sll_addr, 6);
	}
	/* Match the ethertype in packet_socket.c: */
	frame.eth_proto[0] = frame.eth_proto[1] = 0xFF;

	/* Point to frame header */
	msgvec[0].iov_base = &frame;
	msgvec[0].iov_len  = sizeof(struct ether_frame);

	/* Allocate a zeroed-out message info struct */
	msg = (struct msghdr *)calloc(1, sizeof(struct msghdr));

	/* Fill out message metadata struct */
	msg->msg_name	 = so_name;
	msg->msg_namelen = sizeof(struct sockaddr_ll);
	msg->msg_iovlen	 = 1;
	msg->msg_iov	 = msgvec;

	/* Construct and send message */
	rc = sendmsg(ifs->rsock, msg, 0);
	if (rc == -1) {
		perror("sendmsg");
		free(msg);
		return -1;
	}

	printf("Nice to meet you ");
	print_mac_addr(frame.dst_addr, 6);

	printf("I am ");
	print_mac_addr(frame.src_addr, 6);

	/* Remember that we allocated this on the heap; free it */
	free(msg);

	return rc;
}

uint32_t mip_pack(struct mip_hdr *header) {
	uint32_t packed = 0;
	packed |= ((uint32_t)(header->dst_addr & 0xFF)) << 24;
	packed |= ((uint32_t)(header->src_addr & 0xFF)) << 16;
	packed |= ((uint32_t)(header->ttl & 0x0F)) << 12;
	packed |= ((uint32_t)(header->len & 0x1FF)) << 3;
	packed |= (uint32_t)(header->SDU_type & 0x01);

	return htonl(packed); // Convert struct to network byte order
}

void mip_unpack(uint32_t raw, struct mip_hdr *header) {
	uint32_t unpacked = ntohl(raw);

	header->dst_addr = (unpacked >> 24) & 0xFF;
	header->src_addr = (unpacked >> 16) & 0xFF;
	header->ttl = (unpacked >> 12) & 0x0F;
	header->len = (unpacked >> 3) & 0x1FF;
	header->SDU_type = unpacked & 0x01;
}

struct pdu * pdu_alloc(void) {
	struct pdu *pdu = (struct pdu *)calloc(1, sizeof(struct pdu));
	if (!pdu) return NULL;
	pdu->ethhdr = (struct eth_hdr*)calloc(1, sizeof(struct eth_hdr));
	pdu->miphdr = (struct mip_hdr*)calloc(1, sizeof(struct mip_hdr));

	if (!pdu->miphdr || !pdu->ethhdr) {
		destroy_pdu(pdu);
		return NULL;
	}

	//Setting some default values incase
	pdu->ethhdr->ether_type = htons(ETH_P_MIP);
	pdu->miphdr->dst_addr = 0;
	pdu->miphdr->src_addr = 0;
	pdu->miphdr->ttl = 1; // default to once to avoid Broadcast storm. Will be overwritten anyways
	pdu->miphdr->len = 0;
	pdu->miphdr->SDU_type = MIP_SDU_PING;
}

void destroy_pdu(struct pdu *pdu) {
	free(pdu->ethhdr);
	free(pdu->miphdr);
	free(pdu->sdu);
	//free(pdu);
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
	memcpy(pdu->ethhdr->src_mac, src_mac_addr, 6);
	memcpy(pdu->ethhdr->dst_mac, dst_mac_addr, 6);
	pdu->ethhdr->ether_type = htons(ETH_P_MIP);

	pdu->miphdr->dst_addr = dst_mip_addr;
	pdu->miphdr->src_addr = src_mip_addr;
	pdu->miphdr->ttl = ttl_4bit & 0x0F; // 4 bits
	pdu->miphdr->SDU_type = sdu_type & 0x07; // 9 bits

	size_t slen = (sdu_ascii ? (strlen(sdu_ascii) - 1) : 0);
	size_t padded = slen * 4;

	if (padded > 0) { // if padded is more then 0 we need to allocate
		pdu->sdu = calloc(1, padded);
		if (sdu_ascii && slen) {
			memcpy(pdu->sdu, sdu_ascii, slen);
		}

	} else {
		pdu->sdu = NULL;
	}
	pdu->miphdr->len = padded / 4;
}

size_t mip_serialize_pdu(const struct pdu *pdu, uint8_t *send_buffer) {
	size_t send_len = 0;

	memcpy(send_buffer + send_len, pdu->ethhdr, 6);
	send_len += ETH_HDR_LEN;

	uint32_t net_mip = mip_pack(pdu->miphdr);
	memcpy(send_buffer + send_len, &net_mip, 4);
	send_len += 4;

	size_t sdu_bytes = pdu->miphdr->len * 4;
	if (sdu_bytes && pdu->sdu) {
		memcpy(send_buffer + send_len, pdu->sdu, sdu_bytes);
		send_len += sdu_bytes;
	}
	return send_len;
}

size_t mip_deserialize_pdu(struct pdu *pdu, uint8_t *recv_buffer) {
	size_t recv_len = 0;

	pdu->ethhdr = malloc(sizeof(struct eth_hdr));
	memcpy(pdu->ethhdr, recv_buffer + recv_len, ETH_HDR_LEN);
	recv_len += ETH_HDR_LEN;

	pdu->miphdr = malloc(sizeof(struct mip_hdr));
	uint32_t net_mip = 0;
	memcpy(pdu->miphdr, recv_buffer + recv_len, ETH_HDR_LEN);
	mip_unpack(net_mip, pdu->miphdr);
	recv_len += ETH_HDR_LEN;

	size_t sdu_bytes = pdu->miphdr->len * 4;
	if (sdu_bytes > 0) {
		pdu->sdu = calloc(1, sdu_bytes);
		memcpy(pdu->sdu, recv_buffer + recv_len, sdu_bytes);
		recv_len += sdu_bytes;
	} else {
		pdu->sdu = NULL;
	}
	return recv_len;
}
void print_pdu_content(const struct pdu *pdu)
{
	printf("====================================================\n");
	printf("\tSource MAC:      "); print_mac_addr(pdu->ethhdr->src_mac, ETH_ADDR_LEN);
	printf("\tDestination MAC: "); print_mac_addr(pdu->ethhdr->dst_mac, ETH_ADDR_LEN);

	printf("\tEthertype:       0x%04x\n", ntohs(pdu->ethhdr->ether_type));
	printf("\tMIP src:         %u\n", pdu->miphdr->src_addr);
	printf("\tMIP dst:         %u\n", pdu->miphdr->dst_addr);
	printf("\tTTL:   struct pdu * alloc_pdu(void);          %u\n", pdu->miphdr->ttl & 0x0F);
	printf("\tSDU type:        0x%02x\n", pdu->miphdr->SDU_type & 0x07);
	printf("\tSDU length:      %u bytes\n", (unsigned)(pdu->miphdr->len * 4));

	if (pdu->sdu) {
		printf("\tSDU (ascii):     %s\n", (const char*)pdu->sdu);
	}
	printf("====================================================\n");
}



