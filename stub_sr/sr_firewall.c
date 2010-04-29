#include <stdio.h>
#include <stdint.h>
#include <time.h>

#include "dlinklist.h"
#include "sr_firewall.h"

#define WILDCARD_VALUE	0
const unsigned int MAX_FLOW_ENTRIES = 10;  // change to increase number of flows
const unsigned int FLOW_ENTRY_EXPIRATION_TIME = 60;
const struct firewall_entry INBOUND_EXCEPTIONS[] = // add exceptions in host byte order; 0 is wildcard
{
	{0,0,0,0,0,0}
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
	dst->expiration = src->expiration;
}

bool compare_firewall_entries(const void* const t_entry, const void* const s_entry)
{
	const struct firewall_entry* const table_entry = (struct firewall_entry*)t_entry;
	const struct firewall_entry* const search_entry = (struct firewall_entry*)s_entry;
	
	// For each field in the entry we are searching for, check if the table entry's corresponding field is equal, or a wildcard
	return (((table_entry->srcIP == WILDCARD_VALUE) || (table_entry->srcIP == search_entry->srcIP)) &&
			((table_entry->dstIP == WILDCARD_VALUE) || (table_entry->dstIP == search_entry->dstIP)) &&
			((table_entry->protocol == WILDCARD_VALUE) || (table_entry->protocol == search_entry->protocol)) &&
			((table_entry->srcPort == WILDCARD_VALUE) || (table_entry->srcPort == search_entry->srcPort)) &&
			((table_entry->dstPort == WILDCARD_VALUE) || (table_entry->dstPort == search_entry->dstPort)));
}

bool expired_flow_entry(const void* const t_entry, const void* const timePtr)
{
	const struct firewall_entry* const flow_table_entry = (struct firewall_entry*)t_entry;
	time_t time_now = *((time_t*)timePtr);
	
	return (flow_table_entry->expiration <= time_now);
}

void clean_expired_flow_entries(dlinklist* flow_table)
{
	time_t time_now = time(NULL);
	
	// Search the flow table for entries whose expiration time is past
	dlinklist_node* expired_node = dlinklist_find(flow_table, &time_now, expired_flow_entry);
	while (expired_node != NULL)
	{
		// Remove the node from the list
		dlinklist_removenode(flow_table, expired_node);
		
		// Look for additional expired nodes
		expired_node = dlinklist_find(flow_table, &time_now, expired_flow_entry);
	}
}
