#ifndef _SR_ARP
#define _SR_ARP

#ifdef _LINUX_
#include <stdint.h>
#endif

#ifdef _DARWIN_
#include <inttypes.h>
#endif

#include <time.h>
#include "dlinklist.h"

typedef struct arp_entry
{
	uint32_t ip;
	uint8_t mac[6];
	time_t expiration_time;
} arp_entry;

arp_entry* look_up_in_cache(dlinklist* arp_cache, uint32_t ip);
void add_cache_entry(dlinklist* arp_cache, const uint32_t ip, const uint8_t *const mac);
void add_to_cache(dlinklist* arp_cache, const uint8_t *const packet);
void send_arp_request(struct sr_instance *const sr, const uint32_t ip, const struct sr_if* const iface);
int arp_reply(const struct sr_instance *const sr, uint8_t *const packet);

// mac should be a pointer to a six-byte buffer, which, upon succesful lookup will contain the mac address associated with ip
int arp_lookup(const struct sr_instance* const sr, uint32_t ip, uint8_t *mac);

#endif // _SR_ARP
