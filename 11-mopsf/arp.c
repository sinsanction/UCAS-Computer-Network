#include "arp.h"
#include "base.h"
#include "types.h"
#include "ether.h"
#include "arpcache.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"

const u8 eth_broadcast_addr[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
const u8 arp_request_addr[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

// send an arp request: encapsulate an arp request packet, send it out through
// iface_send_packet
void arp_send_request(iface_info_t *iface, u32 dst_ip)
{
	char *packet = (char *)malloc(ETHER_HDR_SIZE + sizeof(struct ether_arp));
	memset(packet, 0, ETHER_HDR_SIZE + sizeof(struct ether_arp));
	
	struct ether_header *eh = (struct ether_header *)packet;
	memcpy(eh->ether_dhost, eth_broadcast_addr, ETH_ALEN);
	memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
	eh->ether_type = htons(ETH_P_ARP);

	struct ether_arp *arp = (struct ether_arp *)(packet + ETHER_HDR_SIZE);
	arp->arp_hrd = htons(ARPHRD_ETHER);
	arp->arp_pro = htons(ETH_P_IP);
	arp->arp_hln = ETH_ALEN;
	arp->arp_pln = 4;
	arp->arp_op = htons(ARPOP_REQUEST);
	memcpy(arp->arp_sha, iface->mac, ETH_ALEN);
	arp->arp_spa = htonl(iface->ip);
	memcpy(arp->arp_tha, arp_request_addr, ETH_ALEN);
	arp->arp_tpa = htonl(dst_ip);

	iface_send_packet(iface, packet, ETHER_HDR_SIZE + sizeof(struct ether_arp));
	free(packet);
	log(DEBUG, "handle arp send request packet\n");
}

// send an arp reply packet: encapsulate an arp reply packet, send it out
// through iface_send_packet
void arp_send_reply(iface_info_t *iface, struct ether_arp *req_hdr)
{
	char *packet = (char *)req_hdr - ETHER_HDR_SIZE;
	struct ether_header *eh = (struct ether_header *)packet;

	//log(DEBUG, "arp_shost:" ETHER_STRING " eh_shost:" ETHER_STRING, ETHER_FMT(req_hdr->arp_sha), ETHER_FMT(eh->ether_shost));

	memcpy(eh->ether_dhost, eh->ether_shost, ETH_ALEN);
	memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
	eh->ether_type = htons(ETH_P_ARP);

	req_hdr->arp_op = htons(ARPOP_REPLY);
	memcpy(req_hdr->arp_tha, req_hdr->arp_sha, ETH_ALEN);
	req_hdr->arp_tpa = req_hdr->arp_spa;
	memcpy(req_hdr->arp_sha, iface->mac, ETH_ALEN);
	req_hdr->arp_spa = htonl(iface->ip);

	iface_send_packet(iface, packet, ETHER_HDR_SIZE + sizeof(struct ether_arp));
}

void handle_arp_packet(iface_info_t *iface, char *packet, int len)
{
	struct ether_arp *arp = (struct ether_arp *)(packet + ETHER_HDR_SIZE);
	log(DEBUG, "handle arp packet\n");

	if (ntohs(arp->arp_op) == ARPOP_REQUEST) {
		if (ntohl(arp->arp_tpa) == iface->ip) {
			//log(DEBUG, "got packet from %s, %d bytes, proto_id: %d\n", iface->name, len, ntohs(arp->arp_op));
			arpcache_insert(ntohl(arp->arp_spa), arp->arp_sha);
			arp_send_reply(iface, arp);
		}
	}
	else if (ntohs(arp->arp_op) == ARPOP_REPLY) {
		if (ntohl(arp->arp_tpa) == iface->ip) {
			arpcache_insert(ntohl(arp->arp_spa), arp->arp_sha);
		}
	}
	else {
		log(ERROR, "Unknown arp packet type 0x%04hx, ingore it.", ntohs(arp->arp_op));
	}

	free(packet);
}

// send (IP) packet through arpcache lookup 
//
// Lookup the mac address of dst_ip in arpcache. If it is found, fill the
// ethernet header and emit the packet by iface_send_packet, otherwise, pending 
// this packet into arpcache, and send arp request.
void iface_send_packet_by_arp(iface_info_t *iface, u32 dst_ip, char *packet, int len)
{
	struct ether_header *eh = (struct ether_header *)packet;

	u8 dst_mac[ETH_ALEN];
	int found = arpcache_lookup(dst_ip, dst_mac);
	if (found) {
		// log(DEBUG, "found the mac of %x, send this packet", dst_ip);
		memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
		eh->ether_type = htons(ETH_P_IP);
		memcpy(eh->ether_dhost, dst_mac, ETH_ALEN);
		iface_send_packet(iface, packet, len);
		free(packet);
	}
	else {
		// log(DEBUG, "lookup %x failed, pend this packet", dst_ip);
		arpcache_append_packet(iface, dst_ip, packet, len);
	}
}
