#ifndef _SR_ARP
#define _SR_ARP

#ifdef _LINUX_
#include <stdint.h>
#endif

#ifdef _DARWIN_
#include <inttypes.h>
#endif

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

struct arp_entry* look_up_in_cache(const struct arp_table *arp_cache, uint32_t ip);
void add_cache_entry(struct arp_table* arp_cache, const uint32_t ip, const uint8_t *const mac);
void add_to_cache(struct arp_table* arp_cache, const uint8_t *const packet);
void send_arp_request(struct sr_instance *const sr, const uint32_t ip, const struct sr_if *const iface);
int arp_reply(const struct sr_instance *const sr, uint8_t *const packet);

// mac should be a pointer to a six-byte buffer, which, upon succesful lookup will contain the mac address associated with ip
int arp_lookup(const struct sr_instance *const sr, uint32_t ip, uint8_t *mac);

#endif // _SR_ARP
