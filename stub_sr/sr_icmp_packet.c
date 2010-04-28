/*
 *  sr_icmp_packet.c
 *  Router
 *
 *  Created by Alex Heinz on 4/28/10.
 *
 */

#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "sr_router.h"
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_protocol.h"
#include "sr_ip_packet.h"

#include "sr_icmp_packet.h"

uint16_t icmp_checksum(const uint8_t* const icmp_packet, uint32_t length)
{
	// Split the message into 16-bit chunks
	const uint16_t* bytes = (const uint16_t*)icmp_packet;
	
	// Calculate the 32-bit sum of all the chunks
	uint32_t sum = 0;
	for (uint32_t bytes_index = 0; bytes_index < (length / 2); bytes_index++)
	{
		sum += bytes[bytes_index];
	}
	
	// Compute one's-complement sum using overflow from 16-bit addition
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	
	// Invert the result, and return the lower 16 bits
	return ((uint16_t)~sum);
}

int send_icmp_ttl_expired_packet(const struct sr_instance* sr, const uint8_t* const expired_packet)
{
	const struct sr_ethernet_hdr* expired_eth_hdr = (const struct sr_ethernet_hdr*)(expired_packet);
	const struct ip* expired_ip_hdr = (const struct ip*)(expired_packet + sizeof(struct sr_ethernet_hdr));
	
	// Calculate ICMP packet length
	uint32_t packet_length = (sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct icmphdr) + expired_ip_hdr->ip_len);
	
	// Create the packet
	uint8_t* packet = malloc(packet_length);
	assert(packet != NULL);
	
	// Fill in the IP header information
	struct ip* outgoing_ip_hdr = (struct ip*)(packet + sizeof(struct sr_ethernet_hdr));
	outgoing_ip_hdr->ip_hl = (sizeof(struct ip) / 4);
	outgoing_ip_hdr->ip_v = 4;
	outgoing_ip_hdr->ip_tos = 0;
	outgoing_ip_hdr->ip_len = htons(packet_length - sizeof(struct sr_ethernet_hdr));
	outgoing_ip_hdr->ip_id = htons(0);
	outgoing_ip_hdr->ip_off = htons(0);
	outgoing_ip_hdr->ip_ttl = 255;
	outgoing_ip_hdr->ip_p =	IPPROTO_ICMP;
	
	// Fill in the source and destination IP addresses
	const struct sr_if* interface = get_iface_from_mac(sr, expired_eth_hdr->ether_dhost);
	outgoing_ip_hdr->ip_src.s_addr = interface->ip;
	outgoing_ip_hdr->ip_dst.s_addr = expired_ip_hdr->ip_src.s_addr;
	
	// Clear and compute the IP header checksum
	outgoing_ip_hdr->ip_sum = 0;
	outgoing_ip_hdr->ip_sum = ip_checksum(outgoing_ip_hdr);
	
	// Fill the ICMP header information
	struct icmphdr* outgoing_icmp_hdr = (struct icmphdr*)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
	outgoing_icmp_hdr->type = ICMP_TIME_EXCEEDED;
	outgoing_icmp_hdr->code = ICMP_EXC_TTL;
	memset(&(outgoing_icmp_hdr->un), 0, sizeof(outgoing_icmp_hdr->un));
	
	// Fill the remainder of the packet
	memcpy((packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct icmphdr)), expired_ip_hdr, expired_ip_hdr->ip_len);
	
	// Compute the ICMP checksum
	outgoing_icmp_hdr->checksum = 0;
	outgoing_icmp_hdr->checksum = icmp_checksum((uint8_t*)outgoing_icmp_hdr, (sizeof(struct icmphdr) + expired_ip_hdr->ip_hl + 8));
	
	// Determine routing information for the outgoing packet
	struct sr_rt *route = find_route_by_ip(sr, outgoing_ip_hdr->ip_dst.s_addr);
	struct sr_if *iface = sr_get_interface(sr, route->interface);
	
	// Send the packet
	send_ip_packet_via_interface_to_route(sr, packet, iface, route);
	
	// Free the space allocated for the packet
	free(packet);
	
	return 0;
}
