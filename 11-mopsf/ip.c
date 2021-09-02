#include "ip.h"
#include "icmp.h"
#include "arpcache.h"
#include "rtable.h"
#include "arp.h"

#include "mospf_proto.h"
#include "mospf_daemon.h"

#include "log.h"

#include <stdlib.h>
#include <assert.h>

// handle ip packet
//
// If the packet is ICMP echo request and the destination IP address is equal to
// the IP address of the iface, send ICMP echo reply; otherwise, forward the
// packet.
/*
void handle_ip_packet(iface_info_t *iface, char *packet, int len)
{
	struct iphdr *ip = packet_to_ip_hdr(packet);
	u32 daddr = ntohl(ip->daddr);
	if (daddr == iface->ip) {
		if (ip->protocol == IPPROTO_ICMP) {
			struct icmphdr *icmp = (struct icmphdr *)IP_DATA(ip);
			if (icmp->type == ICMP_ECHOREQUEST) {
				icmp_send_packet(packet, len, ICMP_ECHOREPLY, 0);
			}
		}
		else if (ip->protocol == IPPROTO_MOSPF) {
			handle_mospf_packet(iface, packet, len);
		}

		free(packet);
	}
	else if (ip->daddr == htonl(MOSPF_ALLSPFRouters)) {
		assert(ip->protocol == IPPROTO_MOSPF);
		handle_mospf_packet(iface, packet, len);

		free(packet);
	}
	else {
		ip_forward_packet(daddr, packet, len);
	}
}*/

void handle_ip_packet(iface_info_t *iface, char *packet, int len)
{
	struct iphdr *iphdr = packet_to_ip_hdr(packet);
	u32 dest_ip = ntohl(iphdr->daddr);
	//log(DEBUG, "handle ip packet\n");

	if (dest_ip == iface->ip) {
		if (iphdr->protocol == IPPROTO_ICMP) {
			unsigned char *icmp_type = (unsigned char *)iphdr + IP_HDR_SIZE(iphdr);
			if (*icmp_type == ICMP_ECHOREQUEST) {
				log(DEBUG, "handle icmp request packet\n");
				icmp_send_packet(packet, len, ICMP_ECHOREPLY, 0);
			}
		}
		else if (iphdr->protocol == IPPROTO_MOSPF) {
			handle_mospf_packet(iface, packet, len);
		}
		free(packet);
	}
	else if (dest_ip == MOSPF_ALLSPFRouters) {
		if (iphdr->protocol == IPPROTO_MOSPF) {
			handle_mospf_packet(iface, packet, len);
		}
		else {
			log(ERROR, "handle mospf packet, but protocol != IPPROTO_MOSPF\n");
		}
		free(packet);
	}
	else { // forward the packet
		if (iphdr->ttl <= 1) { //ICMP TTL equals 0 during transit
			log(DEBUG, "handle icmp ttl 0 packet\n");
			icmp_send_packet(packet, len, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL);
			free(packet);
			return;
		}

		rt_entry_t *rt_dest = longest_prefix_match(dest_ip);
		if (!rt_dest) { //ICMP Dest Network Unreachable
			log(DEBUG, "handle icmp net unreach packet\n");
			icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_NET_UNREACH);
			free(packet);
			return;
		}

		iphdr->ttl = iphdr->ttl - 1;
		iphdr->checksum = ip_checksum(iphdr);
		if (rt_dest->gw == 0) {
			iface_send_packet_by_arp(rt_dest->iface, dest_ip, packet, len);
		}
		else {
			iface_send_packet_by_arp(rt_dest->iface, rt_dest->gw, packet, len);
		}
	}
}
