#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "sr_rt.h"
#include "sr_if.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arp.h"

#define ARP_CACHE_ENTRY_TIMEOUT	600 // 10 Minutes

bool arp_compare_ip(void* entry, void* ipPtr)
{
	return (((arp_entry*)entry)->ip == *((uint32_t*)ipPtr));
}

arp_entry* look_up_in_cache(dlinklist* arp_cache, uint32_t ip)
{
	assert(arp_cache != NULL);
	
	// Attempt to find an entry in the cache with the specified IP address
	dlinklist_node* cache_entry = dlinklist_find(arp_cache, &ip, arp_compare_ip);
	
	// If no entry exists with this IP, return "not found" (NULL)
	if (cache_entry == NULL)
		return NULL;
	
	// If the entry exists, but has expired, remove it from the cache and return "not found"
	arp_entry* entry = cache_entry->contents;
#ifndef _DISABLE_ARP_EXPIRATION_
	if (entry->expiration_time <= time(NULL))
	{
		// Remove the entry from the cache
		dlinklist_removenode(arp_cache, cache_entry);
		return NULL;
	}
#endif
	
	return entry;
}

void add_cache_entry(dlinklist* arp_cache, const uint32_t ip, const uint8_t *const mac)
{
	assert(arp_cache != NULL);
	
	// Search for an existing entry in the cache with this IP address
	arp_entry* entry = look_up_in_cache(arp_cache, ip);
	
	// If the entry does not exist, create it
	if (entry == NULL)
	{
		// Create a new cache entry
		entry = malloc(sizeof(arp_entry));
		assert(entry != NULL);
		entry->ip = ip;
		
		// Add the entry to the cache
		dlinklist_node* node = dlinklist_add(arp_cache, entry);
		assert(node != NULL);
	}
	
	// Insert/update the entry's MAC address and expiration time
	memcpy(entry->mac, mac, ETHER_ADDR_LEN);
	entry->expiration_time = time(NULL) + ARP_CACHE_ENTRY_TIMEOUT;
}

void add_to_cache(dlinklist* arp_cache, const uint8_t *const packet)
{
	struct sr_arphdr *arp = (struct sr_arphdr *) (packet + sizeof(struct sr_ethernet_hdr));
	add_cache_entry(arp_cache, arp->ar_sip, arp->ar_sha);
}

int arp_lookup(const struct sr_instance *const sr, uint32_t ip, uint8_t *mac)
{
	arp_entry *entry = look_up_in_cache(sr->arp_cache, ip);
	if (entry == NULL) // need to send arp request
	{
		return -1;
	}
	else
	{
		memcpy(mac, entry->mac, ETHER_ADDR_LEN);
		return 0;
	}
}

void send_arp_request(struct sr_instance * sr, const uint32_t ip, const struct sr_if *const iface)
{
	uint8_t packet[sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr)];
	const unsigned int len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr);
	struct sr_ethernet_hdr *eth_header = (struct sr_ethernet_hdr *) packet;
	struct sr_arphdr *arp = (struct sr_arphdr *) (packet + sizeof(struct sr_ethernet_hdr));

	memcpy(eth_header->ether_shost, iface->addr, ETHER_ADDR_LEN);
	memset(eth_header->ether_dhost, 0xFF, ETHER_ADDR_LEN);
	eth_header->ether_type = htons(ETHERTYPE_ARP);

	arp->ar_hrd = htons(ARPHDR_ETHER);
	arp->ar_pro = htons(ETHERTYPE_IP);
	arp->ar_hln = 6;
	arp->ar_pln = 4;
	arp->ar_op = htons(ARP_REQUEST);
	memcpy(arp->ar_sha, iface->addr, ETHER_ADDR_LEN);
	arp->ar_sip = iface->ip;
	memset(arp->ar_tha, 0xFF, ETHER_ADDR_LEN);
	arp->ar_tip = ip;

	sr_send_packet(sr, packet, len, iface->name);
}

int arp_reply(const struct sr_instance *const sr, uint8_t *const packet)
{
	struct sr_ethernet_hdr *eth_header = (struct sr_ethernet_hdr *) packet;
	struct sr_arphdr *arp = (struct sr_arphdr *) (packet + sizeof(struct sr_ethernet_hdr));
	uint8_t to[ETHER_ADDR_LEN];
	const struct sr_if *iface;
	iface = get_interface_from_ip(sr, arp->ar_tip);
	if (iface == NULL)
	{
		return -1;
	}
	const uint8_t *const from = iface->addr;
	memcpy(to, eth_header->ether_shost, ETHER_ADDR_LEN);
	memcpy(eth_header->ether_shost, from, ETHER_ADDR_LEN);
	memcpy(eth_header->ether_dhost, to, ETHER_ADDR_LEN);
	memcpy(arp->ar_sha, from, ETHER_ADDR_LEN);
	memcpy(arp->ar_tha, to, ETHER_ADDR_LEN);
	uint32_t tmp = arp->ar_sip;
	arp->ar_sip = arp->ar_tip;
	arp->ar_tip = tmp;
	arp->ar_op = htons(ARP_REPLY);
	return 0;
}
