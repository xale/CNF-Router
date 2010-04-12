#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "sr_if.h"
#include "sr_router.h"

void print_mac(const uint8_t *mac)
{
	for (int i=0; i<6; ++i)
	{
		printf("%x", *mac);
		++mac;
	}
	printf("\n");
}

void get_mac_from_ip(const struct sr_instance *const sr, const uint32_t ip, uint8_t *const mac)
{
	const struct sr_if* iface;
	for(
			iface = sr->if_list;
			iface != NULL && iface->ip != ip;
			iface = iface->next
	   );
	if (iface == NULL) // we don't know
	{
		memset(mac, 0, 6);
	}
	else
	{
		memcpy(mac, iface->addr, 6);
	}
}

uint32_t get_ip_from_mac(const struct sr_instance *const sr, const uint8_t *const mac)
{
	print_mac(mac);
	const struct sr_if* iface;
	for(
			iface = sr->if_list;
			iface != NULL && memcmp(iface->addr, mac, 6) != 0;
			iface = iface->next
	   )
	{
		printf("Failed match with ");
		print_mac(iface->addr);
	}
	if (iface == NULL) // we don't know
	{
		return 0;
	}
	else
	{
		return iface->ip;
	}
}
