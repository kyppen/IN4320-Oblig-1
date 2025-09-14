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
    int raw_soc;
    struct	ifs_data local_ifs;
    if (argc == 5) {
        printf("right amount of arguments passed");
        printf("%s\n", argv[1]);
        printf("%s\n", argv[2]);
        printf("%s\n", argv[3]);
        printf("%s\n", argv[4]);
    }
    raw_soc = create_raw_socket();
    //init_ifs(&local_ifs, raw_soc);

    for (int i = 0; i < local_ifs.ifn; i++) {
        print_mac_addr(local_ifs.addr[i].sll_addr, 6);
    }

    return -1;
}