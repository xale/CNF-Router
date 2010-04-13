#ifndef _SR_ARP_CACHE_H_
#define _SR_ARP_CACHE_H_

#include <stdint.h>

struct arp_entry
{
	uint32_t ip;
	uint8_t mac[6];
	unsigned int expiration_time;
	struct arp_entry *next;
};

struct arp_table
{
	struct arp_entry *entry;
};

#endif // _SR_ARP_CACHE_H
