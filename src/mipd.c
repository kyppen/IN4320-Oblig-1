#include <stdlib.h>		/* free */
#include <stdio.h>		/* printf */
#include <unistd.h>		/* fgets */
#include <string.h>		/* memset */
#include <sys/socket.h>	/* socket */
#include <fcntl.h>
#include <sys/epoll.h>	/* epoll */
#include <linux/if_packet.h>	/* AF_PACKET */
#include <net/ethernet.h>	/* ETH_* */
#include <arpa/inet.h>		/* htons */

#include "common.h"
#include "pdu.h"

int main(int argc, char *argv[]) {
    printf("Arguments passed %d\n", argc);
    // Hold our raw socket

    int raw_sock, rc;
    struct ifs_data local_ifs;

    struct epoll_event ev, events[MAX_EVENTS];
    int epollfd;

    struct mip_header head;

    head.len = ETH_HLEN;

    if (argc == 5) {
        printf("right amount of arguments passed");
        printf("%s\n", argv[1]);
        printf("%s\n", argv[2]);
        printf("%s\n", argv[3]);
        printf("%s\n", argv[4]);
    }
    raw_sock = create_raw_socket();
    init_ifs(&local_ifs, raw_sock);

    /* Create epoll table */
    epollfd = epoll_create1(0);
    if (epollfd == -1) {
        perror("epoll_create1");
        close(raw_sock);
        exit(EXIT_FAILURE);
    }

    /* Add RAW socket to epoll table */
    ev.events = EPOLLIN;
    ev.data.fd = raw_sock;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, raw_sock, &ev) == -1) {
        perror("epoll_ctl: raw_sock");
        close(raw_sock);
        exit(EXIT_FAILURE);
    }


    struct mip_hdr h1 = { 5, 42, 7, 255, 1};
    uint32_t raw = mip_pack(&h1);

    printf("Packed 0x%08X\n", ntohl(raw));

    struct mip_hdr h2;
    mip_unpack(raw, &h2);
    printf("Unpacked: dest=%u, src=%u, ttl=%u, len=%u, sdu=%u\n",
        h2.dst_addr, h2.src_addr, h2.ttl, h2.len, h2.SDU_type);

    uint8_t src_mac[6] = {0x02,0x00,0x00,0x00,0x00,0x01};
    uint8_t dst_mac[6] = {0x02,0x00,0x00,0x00,0x00,0x02};

    //trouble starts here
    struct pdu *p = pdu_alloc();
    fill_pdu(p, src_mac, dst_mac,
             /*src*/0x01, /*dst*/0x05,
             /*ttl*/1,
             /*type*/MIP_SDU_PING,
             "PING:hello");





    for (int i = 0; i < local_ifs.ifn; i++) {
        print_mac_addr(local_ifs.addr[i].sll_addr, 6);
    }

    printf("\n<%s> Hi! I am %s with MAC ", argv[0], argv[0]);
    print_mac_addr(local_ifs.addr[0].sll_addr, 6);

    send_arp_request(&local_ifs);
    /* epoll_wait forever for incoming packets */
    while(1) {
        rc = epoll_wait(epollfd, events, MAX_EVENTS, -1); //wait for data to appear on the socket
        if (rc == -1) {
            perror("epoll_wait");
            break;
        } else if (events->data.fd == raw_sock) {
            printf("\n<info> The neighbor is initiating a handshake\n");
            rc = handle_arp_packet(&local_ifs);
            if (rc < 1) {
                perror("recv");
                break;
            }
        }
    }

    close(raw_sock);
    return -1;
}
