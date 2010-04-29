#include <stdio.h>
#include <stdint.h>

#include "sr_firewall.h"

const unsigned int MAX_FLOW_ENTRIES = 10;  // change to increase number of flows
const unsigned int TIME_TO_INCREMENT = 60;
const struct firewall_entry INBOUND_EXCEPTIONS[] = // add exceptions in host byte order; 0 is wildcard
{
	{0,0,0,0,0}
}; 

unsigned int number_of_exceptions(void)
{
	return sizeof(INBOUND_EXCEPTIONS)/sizeof(struct firewall_entry);
}

void reverse_entry(struct firewall_entry *src, struct firewall_entry *dst)
{
	dst->srcIP = src->dstIP;
	dst->dstIP = src->srcIP;
	dst->protocol = src->protocol;
	dst->srcPort = src->dstPort;
	dst->dstPort = src->srcPort;
}
