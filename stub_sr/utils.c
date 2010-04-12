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
	memcpy(arp->ar_sha, to, ETHER_ADDR_LEN);
	memcpy(arp->ar_tha, from, ETHER_ADDR_LEN);
	uint32_t tmp = arp->ar_sip;
	arp->ar_sip = arp->ar_tip;
	arp->ar_tip = tmp;
	arp->ar_op = htons(ARP_REPLY);
	return 0;
}
