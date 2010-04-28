#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "sr_rt.h"
#include "sr_if.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arp.h"

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

int send_ip_packet_via_interface_to_route(struct sr_instance * sr, uint8_t *const packet, const struct sr_if *const iface, const struct sr_rt *const route)
{
	struct sr_ethernet_hdr *eth_header = (struct sr_ethernet_hdr *) packet;
	struct ip *ip = (struct ip *) (packet + sizeof(struct sr_ethernet_hdr));

	int status = arp_lookup(sr, route->gw.s_addr, eth_header->ether_dhost);

	// could do retransmit queue if unknown, but this is simpler
	if (status != 0)
	{
		send_arp_request(sr, ip->ip_dst.s_addr, iface);
		return -1;
	}
	memcpy(eth_header->ether_shost, iface->addr, ETHER_ADDR_LEN);
	eth_header->ether_type = htons(ETHERTYPE_IP);

	printf("Actually sending packet of length %d via sr_send_packet.\n", htons(ip->ip_len) + sizeof(struct sr_ethernet_hdr));
	sr_send_packet(sr, packet, htons(ip->ip_len) + sizeof(struct sr_ethernet_hdr), iface->name);
	
	return 0;
}

int forward_ip_packet(struct sr_instance * sr, uint8_t *const packet)
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
	struct sr_if *iface = sr_get_interface(sr, route->interface);

	printf("Going to send_ip_packet_via_interface_to_route %s.\n", iface->name);
	send_ip_packet_via_interface_to_route(sr, packet, iface, route);
	return 0;
}
