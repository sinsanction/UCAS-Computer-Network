#include "ip.h"
#include "types.h"
#include "rtable.h"
#include "icmp.h"
#include "arp.h"

#include "log.h"

#include <stdio.h>
#include <stdlib.h>

// handle ip packet
//
// If the packet is ICMP echo request and the destination IP address is equal to
// the IP address of the iface, send ICMP echo reply; otherwise, forward the
// packet.
void handle_ip_packet(iface_info_t *iface, char *packet, int len)
{
	struct iphdr *iphdr = packet_to_ip_hdr(packet);
	log(DEBUG, "handle ip packet\n");

	if (iphdr->protocol == IPPROTO_ICMP) {
		unsigned char *icmp_type = (unsigned char *)iphdr + IP_HDR_SIZE(iphdr);
		if (*icmp_type == ICMP_ECHOREQUEST && ntohl(iphdr->daddr) == iface->ip) {
			log(DEBUG, "handle icmp request packet\n");
			icmp_send_packet(packet, len, ICMP_ECHOREPLY, 0);
			return;
		}
		log(DEBUG, "forward icmp packet\n");
	}
	
	u32 dest_ip = ntohl(iphdr->daddr);
	rt_entry_t *rt_dest = longest_prefix_match(dest_ip);
	if (rt_dest) { // forward the packet
		iphdr->ttl = iphdr->ttl - 1;
		if (iphdr->ttl <= 0) { //ICMP TTL equals 0 during transit
			log(DEBUG, "handle icmp ttl 0 packet\n");
			icmp_send_packet(packet, len, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL);
		}
		else {
			iphdr->checksum = ip_checksum(iphdr);
			if (rt_dest->gw == 0) {
				iface_send_packet_by_arp(rt_dest->iface, dest_ip, packet, len);
			}
			else {
				iface_send_packet_by_arp(rt_dest->iface, rt_dest->gw, packet, len);
			}
		}
	}
	else { //ICMP Dest Network Unreachable
		log(DEBUG, "handle icmp net unreach packet\n");
		icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_NET_UNREACH);
	}
}
