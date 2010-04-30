#ifndef _SR_FIREWALL_H
#define _SR_FIREWALL_H

#include <time.h>

struct firewall_entry
{
	uint32_t srcIP;
	uint32_t dstIP;
	uint8_t  protocol;
	uint16_t srcPort;
	uint16_t dstPort;
	time_t expiration;
};

void reverse_entry(struct firewall_entry *src, struct firewall_entry *dst);

bool flow_table_allows_entry(dlinklist* flow_table, const struct firewall_entry* const entry);
bool exceptions_list_allows_entry(const struct firewall_entry* const entry);

bool firewall_entry_from_packet(const uint8_t* const packet, struct firewall_entry* const entry);
bool add_flow_table_entry(dlinklist* flow_table, struct firewall_entry* const entry);

void clean_expired_flow_entries(dlinklist* flow_table);

#endif
