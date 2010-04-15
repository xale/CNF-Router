#ifndef _SR_IP_PACKET_H
#define _SR_IP_PACKET_H

uint16_t checksum(const struct ip *const ip);

int send_ip_packet_via_interface(const struct sr_instance * sr, uint8_t *const packet, const struct sr_if *const iface);

int forward_ip_packet(const struct sr_instance *const sr, uint8_t *const packet);

#endif // _SR_IP_PACKET_H
