#include "icmp.h"
#include "ip.h"
#include "rtable.h"
#include "arp.h"
#include "base.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// send icmp packet
void icmp_send_packet(const char *in_pkt, int len, u8 type, u8 code)
{
	struct ether_header *in_eh = (struct ether_header *)in_pkt;
	struct iphdr *in_iphdr = packet_to_ip_hdr(in_pkt);
	int len_icmp = len - ETHER_HDR_SIZE - IP_HDR_SIZE(in_iphdr);
	int packet_len;

	if(type == ICMP_ECHOREPLY)
		packet_len = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + len_icmp;
	else
		packet_len = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + ICMP_HDR_SIZE + IP_HDR_SIZE(in_iphdr) + ICMP_COPIED_DATA_LEN;
	
	char *packet = (char *)malloc(packet_len);

	struct ether_header *eh = (struct ether_header *)packet;
	memcpy(eh->ether_dhost, in_eh->ether_shost, ETH_ALEN);
	memcpy(eh->ether_shost, in_eh->ether_dhost, ETH_ALEN);
	eh->ether_type = htons(ETH_P_IP);

	struct iphdr *iphdr = packet_to_ip_hdr(packet);
	rt_entry_t *src_entry = longest_prefix_match(ntohl(in_iphdr->saddr));
	ip_init_hdr(iphdr, src_entry->iface->ip, ntohl(in_iphdr->saddr), packet_len - ETHER_HDR_SIZE, IPPROTO_ICMP);

	struct icmphdr *icmp = (struct icmphdr *)(packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE);
	if (type == ICMP_ECHOREPLY) {
		memcpy((char*)icmp, (in_pkt + ETHER_HDR_SIZE + IP_HDR_SIZE(in_iphdr)), len_icmp);
		icmp->type = type;
		icmp->code = code;
	}
	else {
		icmp->type = type;
		icmp->code = code;
		memset((char*)icmp + 4, 0, 4);
		memcpy((char*)icmp + 8, (char*)in_iphdr, IP_HDR_SIZE(in_iphdr) + ICMP_COPIED_DATA_LEN);
	}
	icmp->checksum = icmp_checksum(icmp, packet_len - ETHER_HDR_SIZE - IP_BASE_HDR_SIZE);

	icmp_ip_send_packet(packet, packet_len);
	free(packet);
}
