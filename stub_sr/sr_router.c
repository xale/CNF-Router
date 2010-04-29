/**********************************************************************
 * file:  sr_router.c 
 * date:  Mon Feb 18 12:50:42 PST 2002  
 * Contact: casado@stanford.edu 
 *
 * Description:
 * 
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arp.h"
#include "sr_ip_packet.h"
#include "dlinklist.h"
#include "utils.h"
#include "sr_icmp_packet.h"

/*--------------------------------------------------------------------- 
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 * 
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr) 
{
    /* REQUIRES */
    assert(sr);

    /* Add initialization code here! */

} /* -- sr_init -- */



/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr, 
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d on interface %s.\n", len, interface);
	struct sr_ethernet_hdr *header = (struct sr_ethernet_hdr *) packet;
	struct sr_arphdr *arp = (struct sr_arphdr *) (packet + sizeof(struct sr_ethernet_hdr));
	struct ip *ip = (struct ip *) (packet + sizeof(struct sr_ethernet_hdr));

	int status;
//	printf("%u == %u\n", header.ether_type, ETHERTYPE_ARP);
	if (ntohs(header->ether_type) == ETHERTYPE_ARP)
	{
		printf("*** -> Received ARP packet.\n");
		printf("*** -> Adding to cache.\n");
		add_to_cache(sr->arp_cache, packet);
		if (ntohs(arp->ar_op) == ARP_REQUEST)
		{
			printf("*** -> Received ARP request.\n");
			status = arp_reply(sr, packet);
			if (status != 0)
			{
				printf("*** -> Arp not directed at us.\n");
			}
			else
			{
				sr_send_packet(sr, packet, 42, interface);
				printf("*** -> Sent ARP reply.\n");
			}
		}
	}
	else if (packet_sent_to_me(sr, packet))
	{
		struct icmphdr *icmp_hdr = (struct icmphdr*)(packet + sizeof(struct ip) + sizeof(struct sr_ethernet_hdr));
		if (icmp_hdr->type == ICMP_ECHO)
		{
			icmp_hdr->type = ICMP_ECHOREPLY;
			uint32_t addr = ip->ip_dst.s_addr;
			ip->ip_dst.s_addr = ip->ip_src.s_addr;
			ip->ip_src.s_addr = addr;
			ip->ip_ttl = 64;
			icmp_hdr->checksum = htons(0);
			// compute the checksum including the data
			icmp_hdr->checksum = icmp_checksum(icmp_hdr, ntohs(ip->ip_len) - sizeof(struct ip));
			printf("Pong.\n");
			printf("Sending icmp echo reply to ");
			print_ip(ntohl(addr));
			send_ip_packet(sr, packet);
		}
	}
	else
	{
		printf("Attempting to forward packet to ");
		print_ip(ip->ip_dst.s_addr);
		forward_ip_packet(sr, packet);
	}
}/* end sr_ForwardPacket */


/*--------------------------------------------------------------------- 
 * Method:
 *
 *---------------------------------------------------------------------*/
