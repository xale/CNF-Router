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

    printf("*** -> Received packet of length %d \n",len);
	struct sr_ethernet_hdr header;
	struct sr_arphdr arp;
	uint8_t mac[6];
	memcpy(&header, packet, sizeof(struct sr_ethernet_hdr));
//	printf("%u == %u\n", header.ether_type, ETHERTYPE_ARP);
	if (ntohs(header.ether_type) == ETHERTYPE_ARP)
	{
		printf("*** -> Received ARP packet.\n");
		memcpy(&arp, packet + 14, sizeof(struct sr_arphdr));
		if (ntohs(arp.ar_op) == ARP_REQUEST)
		{
			printf("*** -> Received ARP request.\n");
			get_mac_from_ip(sr, arp.ar_tip, mac);
			print_mac(mac);
			get_mac_from_ip(sr, ntohl(arp.ar_tip), mac);
			print_mac(mac);
		}
	}

}/* end sr_ForwardPacket */


/*--------------------------------------------------------------------- 
 * Method:
 *
 *---------------------------------------------------------------------*/
