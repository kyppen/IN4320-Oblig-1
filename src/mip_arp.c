#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


struct cache_entry *arp_cache_init(void) {
    return NULL;
}

struct cache_entry *arp_cache_add(struct cache_entry *entry, uint8_t mip, uint8_t mac[6], int ifindex) {
    //struct cache_entry *new_entry = malloc(sizeof(*new_entry));

}