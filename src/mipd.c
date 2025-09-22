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


    //struct mip_hdr h1 = { 0x10, 0x20, 7, 255, 1};
    //uint32_t raw = mip_pack(&h1);

    //printf("Packed 0x%08X\n", ntohl(raw));


    uint8_t src_mac[6] = {0x02,0x00,0x00,0x00,0x00,0x01};
    uint8_t dst_mac[6] = {0x02,0x00,0x00,0x00,0x00,0x02};

    //TESTING SERIALIZATION AND DESERIALIZATION
    struct pdu *p = pdu_alloc();
    fill_pdu(p, src_mac, dst_mac,
             0x10, 0x20,
             1,
             MIP_SDU_TYPE_PING,
             "PING:hello");


    uint8_t buf[1500];
    size_t len = mip_serialize_pdu(p, buf);

    struct pdu q = {0};
    mip_deserialize_pdu(&q, buf);
    print_pdu_content(&q);
    // TESTING END

    for (int i = 0; i < local_ifs.ifn; i++) {
        print_mac_addr(local_ifs.addr[i].sll_addr, 6);
    }

    printf("\n<%s> Hi! I am %s with MAC ", argv[0], argv[0]);
    print_mac_addr(local_ifs.addr[0].sll_addr, 6);

    send_mip_packet(&local_ifs,src_mac, dst_mac,
             0x10, 0x20,
             1,
             MIP_SDU_TYPE_PING,
             "PING:hello");

    printf("Send mip packet atleast didnt fail?");
    //send_arp_request(&local_ifs);
    /* epoll_wait forever for incoming packets */
    while(1) {
        rc = epoll_wait(epollfd, events, MAX_EVENTS, -1); //wait for data to appear on the socket
        if (rc == -1) {
            perror("epoll_wait");
            break;
        } else if (events->data.fd == raw_sock) {
            printf("\n<info> The neighbor is initiating a handshake\n");
            //rc = handle_arp_packet(&local_ifs);
            rc = handle_mip_packet(&local_ifs, "Hello there");
            if (rc < 1) {
                perror("recv");
                break;
            }
        }
    }

    close(raw_sock);
    return -1;
}
