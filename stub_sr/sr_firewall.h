#ifndef _SR_FIREWALL_H
#define _SR_FIREWALL_H

struct firewall_entry
{
	uint32_t srcIP;
	uint32_t dstIP;
	uint8_t  protocol;
	uint16_t srcPort;
	uint16_t dstPort;
};

#endif
