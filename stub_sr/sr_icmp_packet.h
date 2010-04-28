/*
 *  sr_icmp_packet.h
 *  Router
 *
 *  Created by Alex Heinz on 4/28/10.
 *
 */

#ifndef _SR_ICMP_PACKET
#define _SR_ICMP_PACKET

#ifdef _LINUX_
#include <stdint.h>
#endif

#ifdef _DARWIN_
#include <inttypes.h>
#endif

uint16_t icmp_checksum(uint8_t* icmp_packet, uint32_t length);

int send_icmp_ttl_expired_packet(const struct sr_instance* const sr, const uint8_t* const expired_packet);

#endif // _SR_ICMP_PACKET
