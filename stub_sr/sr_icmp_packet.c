/*
 *  sr_icmp_packet.c
 *  Router
 *
 *  Created by Alex Heinz on 4/28/10.
 *
 */

#include <stdlib.h>

#include "sr_router.h"
#include "sr_protocol.h"

#include "sr_icmp_packet.h"

uint16_t icmp_checksum(uint8_t* icmp_packet, uint32_t length)
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

#define ICMP_TTL_EXPIRED_MESSAGE_HEADER_BYTES	16
#define ICMP_TTL_EXPIRED_MESSAGE_DATA_BYTES		8

int send_icmp_ttl_expired_packet(const struct sr_instance* sr, const uint8_t* const expired_packet)
{
	// Calculate ICMP packet length
	
	// FIXME: WRITEME
	
	//struct sr_rt *route = find_route_by_ip(sr, ip->ip_dst.s_addr);
	//struct sr_if *iface = sr_get_interface(sr, route->interface);
	
	//send_ip_packet_via_interface_to_route(sr, packet, iface, route);
	
	return 0;
}
