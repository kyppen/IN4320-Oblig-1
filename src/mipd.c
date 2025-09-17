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

    for (int i = 0; i < local_ifs.ifn; i++) {
        print_mac_addr(local_ifs.addr[i].sll_addr, 6);
    }

    printf("\n<%s> Hi! I am %s with MAC ", argv[0], argv[0]);
    print_mac_addr(local_ifs.addr[0].sll_addr, 6);

    send_arp_request(&local_ifs);
    /* epoll_wait forever for incoming packets */
    while(1) {
        rc = epoll_wait(epollfd, events, MAX_EVENTS, -1);
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