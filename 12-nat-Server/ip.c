#include "ip.h"
#include "icmp.h"
#include "arpcache.h"
#include "rtable.h"
#include "arp.h"
#include "nat.h"
#include "log.h"

#include <stdlib.h>

void handle_ip_packet(iface_info_t *iface, char *packet, int len)
{
	struct iphdr *ip = packet_to_ip_hdr(packet);
	u32 daddr = ntohl(ip->daddr);

	if (daddr == iface->ip && ip->protocol == IPPROTO_ICMP) {
		struct icmphdr *icmp = (struct icmphdr *)IP_DATA(ip);
		if (icmp->type == ICMP_ECHOREQUEST) {
			log(DEBUG, "handle icmp request packet\n");
			icmp_send_packet(packet, len, ICMP_ECHOREPLY, 0);
		}
		else {
			log(DEBUG, "receive icmp packet, type: %d\n", icmp->type);
		}

		free(packet);
	}
	else {
		nat_translate_packet(iface, packet, len);
	}
}
