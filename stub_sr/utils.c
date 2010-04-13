#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_arp_cache.h"
#include "assert.h"

void print_mac(const uint8_t *mac)
{
	for (int i=0; i<6; ++i)
	{
		printf("%x", *mac);
		++mac;
	}
	printf("\n");
}

void print_ip(const uint32_t ip)
{
	const uint8_t *byte = (uint8_t *) &ip;
	for (int i=0; i<4; ++i)
	{
		printf("%u", *byte);
		if (i < 3)
		{
			printf(".");
		}
		++byte;
	}
	printf("\n");
}

struct sr_if* get_interface_from_ip(const struct sr_instance *const sr, const uint32_t ip)
{
	const struct sr_if *iface;
	printf("Trying to match against: ");
	print_ip(ip);
	for(
			iface = sr->if_list;
			iface != NULL && iface->ip != ip;
			iface = iface->next
	   )
	{
		printf("Failed match against: ");
		print_ip(iface->ip);
	}
	return iface;
}

uint32_t get_ip_from_mac(const struct sr_instance *const sr, const uint8_t *const mac)
{
	print_mac(mac);
	const struct sr_if* iface;
	for(
			iface = sr->if_list;
			iface != NULL && memcmp(iface->addr, mac, ETHER_ADDR_LEN) != 0;
			iface = iface->next
	   )
	{
		printf("Failed match with ");
		print_mac(iface->addr);
	}
	if (iface == NULL) // we don't know
	{
		return 0;
	}
	else
	{
		return iface->ip;
	}
}

uint16_t checksum(const struct ip *const ip)
{
	// header checksum adapted from
	// http://www.netrino.com/Embedded-Systems/How-To/Additive-Checksums

	const uint16_t *bytes = (const uint16_t *) ip;
	uint32_t sum = 0;
	short nWords = 2 * ip->ip_hl;
	/*
	 * IP headers always contain an even number of bytes.
	 */
	while (nWords-- > 0)
	{
		sum += *(bytes++);
	}

	/*
	 * Use carries to compute 1's complement sum.
	 */
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += sum >> 16;

	/*
	 * Return the inverted 16-bit result.
	 */
	return ((uint16_t) ~sum);
}

const struct sr_if* find_iface_by_name(const struct sr_instance *const sr, char *name)
{
	const struct sr_if* iface = NULL;
	for (
			iface = sr->if_list;
			iface != NULL &&
				strncmp(iface->name, name, sr_IFACE_NAMELEN) != 0;
			iface = iface->next
		);
	return iface;
}

const struct sr_rt* find_route_by_ip(const struct sr_instance *const sr, uint32_t dest_ip)
{
	uint32_t mask = 0;
	const struct sr_rt *rt_node = sr->routing_table;
	const struct sr_rt *ret = NULL;
	for (; rt_node != NULL; rt_node = rt_node->next)
	{
		if  (
				((rt_node->dest.s_addr & rt_node->mask.s_addr) ==
				 (dest_ip & rt_node->mask.s_addr)) && // prefix matches
				((rt_node->mask.s_addr & mask) == mask) // longer prefix
			) 
		{
			mask = rt_node->mask.s_addr;
			ret = rt_node;
		}
	}
	return ret;
}

struct arp_entry* look_up_in_cache(struct arp_table *arp_cache, uint32_t ip)
{
	struct arp_entry *arp_entry;
	for (
			arp_entry = arp_cache->entry;
			arp_entry != NULL && arp_entry->ip != ip;
			arp_entry = arp_entry->next
		);
	return arp_entry;
}

void add_cache_entry(struct arp_table* arp_cache, const uint32_t ip, const uint8_t *const mac)
{
	assert(arp_cache != NULL);
	struct arp_entry* arp;
	struct arp_entry* new_arp;
	arp = look_up_in_cache(arp_cache, ip);
	if (arp == NULL)
	{
		new_arp = malloc(sizeof(struct arp_entry));
		if (new_arp == NULL)
		{
			return;
		}
		new_arp->ip = ip;
		memcpy(new_arp->mac, mac, ETHER_ADDR_LEN);
		new_arp->next = NULL;
		// FIXME: set expiry time
		if (arp_cache->entry == NULL)
		{
			arp_cache->entry = new_arp;
			return;
		}
		arp = arp_cache->entry;
		while (arp->next != NULL)
		{
			arp = arp->next;
		}
		arp->next = new_arp;
		return;
	}
	memcpy(arp->mac, mac, ETHER_ADDR_LEN);
	// FIXME: update expiry time
}

void add_to_cache(struct arp_table* arp_cache, const uint8_t *const packet)
{
	struct sr_arphdr *arp = (struct sr_arphdr *) (packet + sizeof(struct sr_ethernet_hdr));
	add_cache_entry(arp_cache, arp->ar_sip, arp->ar_sha);
}

int arp_lookup(const struct sr_instance *const sr, uint32_t ip, uint8_t *mac)
{
	struct arp_entry *entry = look_up_in_cache(sr->arp_cache, ip);
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

void send_arp_request(const struct sr_instance *const sr, const uint32_t ip, const struct sr_if *const iface)
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


	printf("Debug... ");
	print_ip(ip);

	printf("Debug... %s\n", iface->name);

	sr_send_packet(sr, packet, len, iface->name);
}

int send_packet_via_interface(const struct sr_instance *const sr, uint8_t *const packet, const struct sr_if *const iface)
{
	struct sr_ethernet_hdr *eth_header = (struct sr_ethernet_hdr *) packet;
	struct ip *ip = (struct ip *) (packet + sizeof(struct sr_ethernet_hdr));

	int status = arp_lookup(sr, ip->ip_dst.s_addr, eth_header->ether_dhost);

	// could do retransmit queue if unknown, but this is simpler
	if (status != 0)
	{
		send_arp_request(sr, ip->ip_dst.s_addr, iface);
		return -1;
	}
	memcpy(eth_header->ether_shost, iface->addr, ETHER_ADDR_LEN);
	eth_header->ether_type = htons(ETHERTYPE_IP);

	sr_send_packet(sr, packet, ip->ip_len, iface->name);
}

int route_packet(const struct sr_instance *const sr, uint8_t *const packet)
{
	struct sr_ethernet_hdr *eth_header = (struct sr_ethernet_hdr *) packet;
	struct ip *ip = (struct ip *) (packet + sizeof(struct sr_ethernet_hdr));

	if (ip->ip_ttl == 0) // do not forward; send icmp packet back
	{
	}

	--ip->ip_ttl;

	uint16_t checksum_old = ip->ip_sum;
	ip->ip_sum = 0;
	uint16_t checksum_new = checksum(ip);
	if (checksum_old != checksum_new) // checksums don't match
	{
	}
	ip->ip_sum = checksum_new; // FIXME maybe should be hton or something

	struct sr_rt *route = find_route_by_ip(sr, ip->ip_dst.s_addr);
	struct sr_if *iface = find_iface_by_name(sr, route->interface);

	send_packet_via_interface(sr, packet, iface);
	return 0;
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
