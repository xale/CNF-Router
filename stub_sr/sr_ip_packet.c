#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <time.h>

#include "sr_rt.h"
#include "sr_if.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arp.h"
#include "sr_icmp_packet.h"
#include "sr_ip_packet.h"
#include "sr_firewall.h"

uint16_t ip_checksum(const struct ip *const ip)
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
	while ((sum >> 16) > 0)
		sum = (sum >> 16) + (sum & 0xFFFF);

	/*
	 * Return the inverted 16-bit result.
	 */
	return ((uint16_t) ~sum);
}

int send_ip_packet(struct sr_instance* sr, uint8_t *const packet)
{
	// Locate the IP header
	struct ip *ip = (struct ip *) (packet + sizeof(struct sr_ethernet_hdr));
	
	// Clear and recompute the IP checksum
	ip->ip_sum = 0;
	ip->ip_sum = ip_checksum(ip);
	
	// Determine routing information for outgoing packet
	struct sr_rt *route = find_route_by_ip(sr, ip->ip_dst.s_addr);
	struct sr_if *iface = sr_get_interface(sr, route->interface);
	
	// Route and send the packet
	printf("Going to send_ip_packet_via_interface_to_route %s.\n", iface->name);
	return send_ip_packet_via_interface_to_route(sr, packet, iface, route);
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

	printf("Actually sending packet of length %lu via sr_send_packet.\n", ntohs(ip->ip_len) + sizeof(struct sr_ethernet_hdr));
	return sr_send_packet(sr, packet, ntohs(ip->ip_len) + sizeof(struct sr_ethernet_hdr), iface->name);
}
bool try_add_flow_entry(struct sr_instance *sr, uint8_t *packet, uint8_t icmp_code_on_failure)
{
	struct firewall_entry *entry  = firewall_entry_from_packet(packet);
	entry->expiration = time(NULL) + FLOW_ENTRY_EXPIRATION_TIME;
	bool status = add_or_replace_flow_table_entries(sr->flow_table, entry);
	if (!status)
	{
		send_icmp_destination_unreachable_packet(sr, packet, icmp_code_on_failure);
		return false;
	}
	return true;
}

int forward_ip_packet(struct sr_instance* sr, uint8_t *const packet)
{
	struct ip *ip = (struct ip *) (packet + sizeof(struct sr_ethernet_hdr));
	
	// Verify the checksum of the incoming packet
	if (ip_checksum(ip) != 0x0)
	{
		// Verification failed: do not forward corrupted packet
		printf("Packet's checksum is invalid; dropping.");
		return -1;
	}

	if (arrived_on_external_interface(sr, packet))
	{ // do firewally filtery stuff
		bool status;
		struct firewall_entry *entry = firewall_entry_from_packet(packet);
		if (flow_table_allows_entry(sr->flow_table, entry))
		{
			goto allowed;
		}
		if (exceptions_list_allows_entry(entry))
		{
			status = try_add_flow_entry(sr, packet, 1);
		}
		if (status)
		{
			goto allowed;
		}
		return -1; // or something
	}

	// try to add flow rule; possibly fail to forward with icmp unreachable;
	int status = try_add_flow_entry(sr, packet, 0);
	if (!status)
	{
		return -1;
	}
	
allowed:
	// Check if the packet's TTL has expired
	if (ip->ip_ttl <= 1)
	{
		// TTL exprired: do not forward packet, send ICMP "Time Exceeded" reply to origin host
		printf("Packet's TTL has expired; replying with ICMP 'time exceeded'");
		send_icmp_ttl_expired_packet(sr, packet);
		return -1;
	}
	
	// Decrement the TTL
	--ip->ip_ttl;
	
	return send_ip_packet(sr, packet);
}

int packet_sent_to_me(struct sr_instance *const sr, const uint8_t *const packet)
{
	struct sr_ethernet_hdr *eth_header = (struct sr_ethernet_hdr *) packet;
	struct ip *ip = (struct ip *) (packet + sizeof(struct sr_ethernet_hdr));

	const struct sr_if *const iface = get_iface_from_mac(sr, eth_header->ether_dhost);
	return (ip->ip_dst.s_addr == iface->ip);
}
