#ifndef _COMMON_H
#define _COMMON_H

#define Request 0
#define Response 1
#include <stdint.h>

struct cache_entry {
    uint8_t mip_addr;
    uint8_t mac[6];
    int ifindex;
};


int arp_cache_init(int size);
int arp_cache_add(struct cache_entry *entry);
int arp_cache_remove(struct cache_entry *entry);
int arp_cache_lookup(struct cache_entry *entry);

#endif /* _MIP_ARP_H */

