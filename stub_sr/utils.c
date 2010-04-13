#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "sr_if.h"
#include "sr_router.h"

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

int get_mac_from_ip(const struct sr_instance *const sr, const uint32_t ip, uint8_t *const mac)
{
	printf("Trying to match against: ");
	print_ip(ip);
	const struct sr_if* iface;
	for(
			iface = sr->if_list;
			iface != NULL && iface->ip != ip;
			iface = iface->next
	   )
	{
		printf("Failed match against: ");
		print_ip(iface->ip);
	}
	if (iface == NULL) // we don't know
	{
		return -1;
	}
	else
	{
		memcpy(mac, iface->addr, ETHER_ADDR_LEN);
		return 0;
	}
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

uint16_t checksum(const struct sr_ip *const ip)
{
	// header checksum adapted from
	// http://www.netrino.com/Embedded-Systems/How-To/Additive-Checksums

	const uint16_t *bytes = (const uint16_t *) ip
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

int find_route(const struct sr_instance *const sr, uint32_t dest_ip, uint32_t *const gw_ip, char **iface)
{
	uint32_t mask = 0;
	const struct sr_rt *rt_node = sr->routing_table;
	for (; rt_node != NULL; rt_node = rt_node->next)
	{
		if  (
				rt_node->dest->s_addr & rt_node->mask->s_addr ==
				dest_ip & rt_node->mask->s_addr && // prefix matches
				rt_node->mask->s_addr & mask == mask // longer prefix
			) 
		{
			mask = rt_node->mask->s_addr;
			*gw_ip = rt_node->gw->s_addr;
			*iface = rt_node->interface;
		}
	}
	return 0;
}

int route_packet(const struct sr_instance *const sr, uint8_t *const packet)
{
	struct sr_ethernet_hdr *eth_header = (struct sr_ethernet_hdr *) packet;
	struct sr_ip *ip = (struct sr_ip *) (packet + sizeof(struct sr_ethernet_hdr));

	if (ip->ip_ttl == 0) // do not forward; send icmp packet back
	{
	}

	--ip->ip_ttl;

	uint16_t checksum_old = ip->ip_sum;
	ip->ip_sum = 0;
	uint16_t checksum = checksum(ip);
	if (checksum_old != checksum) // checksums don't match
	{
	}
	ip->ip_sum = checksum; // FIXME maybe should be hton or something

	char iface[sr_IFACE_NAMELEN];
	uint32_t gw_ip;
	find_route(sr, ip->dst_addr->s_addr, &gw_ip, &iface);
	// FIXME: send packet along

	return 0;

}


int arp_reply(const struct sr_instance *const sr, uint8_t *const packet)
{
	struct sr_ethernet_hdr *eth_header = (struct sr_ethernet_hdr *) packet;
	struct sr_arphdr *arp = (struct sr_arphdr *) (packet + sizeof(struct sr_ethernet_hdr));
	uint8_t from[ETHER_ADDR_LEN];
	uint8_t to[ETHER_ADDR_LEN];
	int status = get_mac_from_ip(sr, arp->ar_tip, from);
	if (status != 0)
	{
		return status;
	}
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
