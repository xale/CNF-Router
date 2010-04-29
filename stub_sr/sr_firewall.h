#ifndef _SR_FIREWALL_H
#define _SR_FIREWALL_H

struct firewall_entry
{
	uint32_t srcIP;
	uint32_t dstIP;
	uint8_t  protocol;
	uint16_t srcPort;
	uint16_t dstPort;
	uint32_t expiration;
};

void reverse_entry(struct firewall_entry *src, struct firewall_entry *dst);

void clean_expired_flow_entries(dlinklist* flow_table);

#endif
