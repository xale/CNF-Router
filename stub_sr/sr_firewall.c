#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <assert.h>

#include "dlinklist.h"
#include "sr_protocol.h"
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

void reverse_entry(const struct firewall_entry* const src, struct firewall_entry* const dst)
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
	
	// For each field in the entry we are searching for, check if the table entry's corresponding field is equal, or a wildcard (port-less protocols are assumed to store a wildcard value for source and destination port)
	return (((table_entry->srcIP == WILDCARD_VALUE) || (table_entry->srcIP == search_entry->srcIP)) &&
			((table_entry->dstIP == WILDCARD_VALUE) || (table_entry->dstIP == search_entry->dstIP)) &&
			((table_entry->protocol == WILDCARD_VALUE) || (table_entry->protocol == search_entry->protocol)) &&
			((table_entry->srcPort == WILDCARD_VALUE) || (table_entry->srcPort == search_entry->srcPort)) &&
			((table_entry->dstPort == WILDCARD_VALUE) || (table_entry->dstPort == search_entry->dstPort)));
}

bool flow_table_allows_entry(dlinklist* flow_table, const struct firewall_entry* const entry)
{
	// Search for entries in the flow table that match (via compare_firewall_entries()) the specified entry
	dlinklist_node* match_node = dlinklist_find(flow_table, entry, compare_firewall_entries);
	struct firewall_entry* match_entry;
	time_t time_now = time(NULL);
	while (match_node != NULL)
	{
		match_entry = (struct firewall_entry*)(match_node->contents);
		
		// Make sure the entry is not expired
		if (match_entry->expiration <= time_now)
		{
			// Remove the entry from the table
			dlinklist_removenode(flow_table, match_node);
			
			// Search for other matching entries
			match_node = dlinklist_find(flow_table, entry, compare_firewall_entries);
		}
		else
		{
			// Valid entry found; allow packet
			return true;
		}
	}
	
	// No un-expired entries found
	return false;
}

bool exceptions_list_allows_entry(const struct firewall_entry* const entry)
{
	unsigned int num_exceptions = number_of_exceptions();
	for (unsigned int index = 0; index < num_exceptions; index++)
	{
		if (compare_firewall_entries(&INBOUND_EXCEPTIONS[index], entry))
			return true;
	}
	
	return false;
}

struct firewall_entry* firewall_entry_from_packet(const uint8_t* const packet)
{
	struct ip* ip_header = (struct ip*)(packet + sizeof(struct sr_ethernet_hdr));
	
	// Create a firewall entry
	struct firewall_entry* entry = malloc(sizeof(struct firewall_entry));
	assert(entry != NULL);
	
	// Fill the source and destination IP addresses
	entry->srcIP = ntohl(ip_header->ip_src.s_addr);
	entry->dstIP = ntohl(ip_header->ip_dst.s_addr);
	
	// Determine the packet protocol
	entry->protocol = ip_header->ip_p;
	
	// Determine ports on a per-protocol basis
	switch (entry->protocol)
	{
		case IPPROTO_TCP:
		{
			// TCP: get port values from the TCP header
			struct tcphdr* tcp_header = (struct tcphdr*)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
			entry->srcPort = ntohs(tcp_header->th_sport);
			entry->dstPort = ntohs(tcp_header->th_dport);
			break;
		}
		case IPPROTO_UDP:
		{
			// UDP: get port values from UDP header
			struct udphdr* udp_header = (struct udphdr*)(packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
			entry->srcPort = ntohs(udp_header->uh_sport);
			entry->dstPort = ntohs(udp_header->uh_dport);
			break;
		}
		default:
			// Portless protocols: use wildcards
			entry->srcPort = WILDCARD_VALUE;
			entry->dstPort = WILDCARD_VALUE;
			break;
	}
	
	return entry;
}

bool add_or_replace_flow_table_entries(dlinklist* flow_table, struct firewall_entry* const outgoing_entry)
{
	// Create the incoming-flow entry from the outgoing entry
	struct firewall_entry* incoming_entry = malloc(sizeof(struct firewall_entry));
	assert(incoming_entry != NULL);
	reverse_entry(outgoing_entry, incoming_entry);
	
	// Check if the entries are already present in the table
	dlinklist_node* existing_node = dlinklist_find(flow_table, outgoing_entry, compare_firewall_entries);
	if (existing_node != NULL)
	{
		// Remove the old node
		dlinklist_removenode(flow_table, existing_node);
		
		// Make sure there is a matching incoming-flow entry
		existing_node = dlinklist_find(flow_table, incoming_entry, compare_firewall_entries);
		assert(existing_node != NULL);
		dlinklist_removenode(flow_table, existing_node);
		
		// Replace the old entries with the new
		return ((dlinklist_add(flow_table, outgoing_entry) != NULL) &&
				(dlinklist_add(flow_table, incoming_entry) != NULL));
	}
	
	// If the entries do not already exist in the table, check that there is space to add two nodes
	if ((flow_table->count + 2) > MAX_FLOW_ENTRIES)
	{
		// Attempt to clean expired entries
		clean_expired_flow_entries(flow_table);
		
		// Check if there is sufficient space to add the new entries
		if ((flow_table->count + 2) > MAX_FLOW_ENTRIES)
			return false;
	}
	
	// Add the entries to the table
	return ((dlinklist_add(flow_table, outgoing_entry) != NULL) &&
			(dlinklist_add(flow_table, incoming_entry) != NULL));
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
