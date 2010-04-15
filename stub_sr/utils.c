#include <stdint.h>
#include <stdio.h>

void print_mac(const uint8_t *mac)
{
	for (int i=0; i<6; ++i)
	{
		printf("%x", *mac);
		++mac;
		if (i != 5)
		{
			printf(":");
		}
	}
	printf("\n");
}

void print_ip(const uint32_t ip)
{
	const uint8_t *byte = (uint8_t *) &ip;
	for (int i=0; i<4; ++i)
	{
		printf("%u", *byte);
		if (i < 3)
		{
			printf(".");
		}
		++byte;
	}
	printf("\n");
}
