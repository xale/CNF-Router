#ifndef _SR_FIREWALL_H
#define _SR_FIREWALL_H

#include <time.h>
#include "sr_router.h"

extern const unsigned int FLOW_ENTRY_EXPIRATION_TIME;

struct firewall_entry
{
	uint32_t srcIP;
	uint32_t dstIP;
	uint8_t  protocol;
	uint16_t srcPort;
	uint16_t dstPort;
	time_t expiration;
};

void reverse_entry(const struct firewall_entry* const src, struct firewall_entry* const dst);

bool flow_table_allows_entry(dlinklist* flow_table, const struct firewall_entry* const entry);
bool exceptions_list_allows_entry(const struct firewall_entry* const entry);

struct firewall_entry* firewall_entry_from_packet(const uint8_t* const packet);
bool add_or_replace_flow_table_entries(dlinklist* flow_table, struct firewall_entry* const entry);

void clean_expired_flow_entries(dlinklist* flow_table);

bool arrived_on_external_interface(struct sr_instance *sr, uint8_t *packet);
unsigned int number_of_exceptions(void);

#endif
