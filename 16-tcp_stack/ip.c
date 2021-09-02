#include "ip.h"
#include "icmp.h"
#include "arpcache.h"
#include "rtable.h"
#include "arp.h"
#include "tcp.h"

#include "log.h"

#include <stdlib.h>


void handle_ip_packet(iface_info_t *iface, char *packet, int len)
{
	struct iphdr *ip = packet_to_ip_hdr(packet);
	u32 daddr = ntohl(ip->daddr);
	if (daddr == iface->ip) {
		if (ip->protocol == IPPROTO_ICMP) {
			struct icmphdr *icmp = (struct icmphdr *)IP_DATA(ip);
			if (icmp->type == ICMP_ECHOREQUEST) {
				log(DEBUG, "handle icmp request packet\n");
				icmp_send_packet(packet, len, ICMP_ECHOREPLY, 0);
			}
			else {
				log(DEBUG, "receive icmp packet, type: %d\n", icmp->type);
			}
		}
		else if (ip->protocol == IPPROTO_TCP) {
			handle_tcp_packet(packet, ip, (struct tcphdr *)(IP_DATA(ip)));
		}
		else {
			log(ERROR, "unsupported IP protocol (0x%x) packet.", ip->protocol);
		}

		free(packet);
	}
	else {
		// ip_forward_packet(daddr, packet, len);
		log(ERROR, "received packet with incorrect destination IP address.");
	}
}
