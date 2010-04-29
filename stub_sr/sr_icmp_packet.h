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

struct icmphdr
{
	uint8_t type;        /* message type */
	uint8_t code;        /* type sub-code */
	uint16_t checksum;
	union
	{
		struct
		{
			uint16_t id;
			uint16_t sequence;
		} __attribute__ ((packed)) echo;         /* echo datagram */
		uint32_t   gateway;    /* gateway address */
		struct
		{
			uint16_t __unused;
			uint16_t mtu;
		} __attribute__ ((packed)) frag;         /* path mtu discovery */
	} un;
} __attribute__ ((packed));

#define ICMP_ECHOREPLY      0   /* Echo Reply           */
#define ICMP_DEST_UNREACH   3   /* Destination Unreachable  */
#define ICMP_SOURCE_QUENCH  4   /* Source Quench        */
#define ICMP_REDIRECT       5   /* Redirect (change route)  */
#define ICMP_ECHO       8   /* Echo Request         */
#define ICMP_TIME_EXCEEDED  11  /* Time Exceeded        */
#define ICMP_PARAMETERPROB  12  /* Parameter Problem        */
#define ICMP_TIMESTAMP      13  /* Timestamp Request        */
#define ICMP_TIMESTAMPREPLY 14  /* Timestamp Reply      */
#define ICMP_INFO_REQUEST   15  /* Information Request      */
#define ICMP_INFO_REPLY     16  /* Information Reply        */
#define ICMP_ADDRESS        17  /* Address Mask Request     */
#define ICMP_ADDRESSREPLY   18  /* Address Mask Reply       */
#define NR_ICMP_TYPES       18


/* Codes for UNREACH. */
#define ICMP_NET_UNREACH    0   /* Network Unreachable      */
#define ICMP_HOST_UNREACH   1   /* Host Unreachable     */
#define ICMP_PROT_UNREACH   2   /* Protocol Unreachable     */
#define ICMP_PORT_UNREACH   3   /* Port Unreachable     */
#define ICMP_FRAG_NEEDED    4   /* Fragmentation Needed/DF set  */
#define ICMP_SR_FAILED      5   /* Source Route failed      */
#define ICMP_NET_UNKNOWN    6
#define ICMP_HOST_UNKNOWN   7
#define ICMP_HOST_ISOLATED  8
#define ICMP_NET_ANO        9
#define ICMP_HOST_ANO       10
#define ICMP_NET_UNR_TOS    11
#define ICMP_HOST_UNR_TOS   12
#define ICMP_PKT_FILTERED   13  /* Packet filtered */
#define ICMP_PREC_VIOLATION 14  /* Precedence violation */
#define ICMP_PREC_CUTOFF    15  /* Precedence cut off */
#define NR_ICMP_UNREACH     15  /* instead of hardcoding immediate value */

/* Codes for REDIRECT. */
#define ICMP_REDIR_NET      0   /* Redirect Net         */
#define ICMP_REDIR_HOST     1   /* Redirect Host        */
#define ICMP_REDIR_NETTOS   2   /* Redirect Net for TOS     */
#define ICMP_REDIR_HOSTTOS  3   /* Redirect Host for TOS    */

/* Codes for TIME_EXCEEDED. */
#define ICMP_EXC_TTL        0   /* TTL count exceeded       */
#define ICMP_EXC_FRAGTIME   1   /* Fragment Reass time exceeded */

uint16_t icmp_checksum(const uint8_t* const icmp_packet, uint32_t length);

int send_icmp_ttl_expired_packet(struct sr_instance* const sr, const uint8_t* const expired_packet);

int send_icmp_echo_reply_packet(struct sr_instance* const sr, uint8_t* const echo_request_packet);

#endif // _SR_ICMP_PACKET
