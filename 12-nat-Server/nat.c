#include "nat.h"
#include "ip.h"
#include "icmp.h"
#include "tcp.h"
#include "rtable.h"
#include "hash.h"
#include "arp.h"

#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#define MAX_LINE_LEN 100

static struct nat_table nat;

// get the interface from iface name
static iface_info_t *if_name_to_iface(char *if_name)
{
	char *name_end = if_name;
	while (*name_end != ' ' && *name_end != '\n' && *name_end != '\0') name_end++;
	*name_end = '\0';

	iface_info_t *iface = NULL;
	list_for_each_entry(iface, &instance->iface_list, list) {
		if (strcmp(iface->name, if_name) == 0) {
			return iface;
		}
	}

	log(ERROR, "Could not find the desired interface according to if_name '%s'", if_name);
	return NULL;
}

// get int from string ipv4
static u32 ipv4_to_int(char *ipv4){
    u32 sum = 0;
    for (int i=1; i<=4; i++) {
        sum = sum * 256 + atoi(ipv4);
        while (*ipv4 >= '0' && *ipv4 <= '9') ipv4++;
        ipv4++;
    }
    return sum;
}

u8 hash_nat(u32 nat_ip, u16 nat_port)
{
	char tmp[6];
	memcpy(&tmp[0], (char *)&nat_ip, 4);
	memcpy(&tmp[4], (char *)&nat_port, 2);
	return hash8(tmp, 6);
}

u16 assign_external_port(void)
{
	for (u16 i = NAT_PORT_MIN; i < NAT_PORT_MAX; i++) {
		if (nat.assigned_ports[i] == 0) {
			nat.assigned_ports[i] = 1;
			return i;
		}
	}
	
	log(ERROR, "there is no more external port\n");
	return 0;
}

struct nat_mapping *new_map_entry(u32 int_src_ip, u16 int_src_port, u16 ext_src_port, u32 ext_dst_ip, u16 ext_dst_port, u32 int_dst_ip, u16 int_dst_port)
{
	struct nat_mapping *map_entry = (struct nat_mapping *)malloc(sizeof(struct nat_mapping));
	map_entry->internal_src_ip = int_src_ip;
	map_entry->internal_src_port = int_src_port;
	map_entry->external_src_ip = nat.public_ip;
	map_entry->external_src_port = ext_src_port;

	map_entry->external_dst_ip = ext_dst_ip;
	map_entry->external_dst_port = ext_dst_port;
	map_entry->internal_dst_ip = int_dst_ip;
	map_entry->internal_dst_port = int_dst_port;
	map_entry->update_time = time(NULL);

	map_entry->conn.internal_fin = 0;
	map_entry->conn.external_fin = 0;
	map_entry->conn.internal_seq_end = 0;
	map_entry->conn.external_seq_end = 0;
	map_entry->conn.internal_ack = 0;
	map_entry->conn.external_ack = 0;
	init_list_head(&map_entry->list);
	list_add_tail(&map_entry->list, &(nat.nat_mapping_list[hash_nat(ext_dst_ip, ext_dst_port)]));
	return map_entry;
}

// do translation for the packet: replace the ip/port, recalculate ip & tcp
// checksum, update the statistics of the tcp connection
void do_translation(iface_info_t *iface, char *packet, int len)
{
	struct iphdr *ip = packet_to_ip_hdr(packet);
	struct tcphdr *tcp = packet_to_tcp_hdr(packet);

	pthread_mutex_lock(&nat.lock);
	struct nat_mapping *map_entry = NULL;
	u32 src_ip, dst_ip;
	u16 src_port, dst_port;
	int dir, find = 0;

	src_ip = ntohl(ip->saddr);
	src_port = ntohs(tcp->sport);
	dst_ip = ntohl(ip->daddr);
	dst_port = ntohs(tcp->dport);

	u8 index = hash_nat(dst_ip, dst_port);

	list_for_each_entry(map_entry, &(nat.nat_mapping_list[index]), list) {
		if (map_entry->external_dst_ip == dst_ip && map_entry->external_dst_port == dst_port && 
		map_entry->internal_src_ip == src_ip && map_entry->internal_src_port == src_port) {
			dir = DIR_IN;
			find = 1;
			break;
		}
	}

	if (find == 0) {
		for (int i=0; i<HASH_8BITS; i++) {
			list_for_each_entry(map_entry, &(nat.nat_mapping_list[i]), list) {
				if (map_entry->external_src_ip == dst_ip && map_entry->external_src_port == dst_port && 
				map_entry->internal_dst_ip == src_ip && map_entry->internal_dst_port == src_port) {
					dir = DIR_OUT;
					find = 1;
					break;
				}
			}
			if (find) break;
		}
	}

	if (find == 0) {
		if (tcp->flags == TCP_SYN) {
			struct dnat_rule *rule_entry = NULL;
			list_for_each_entry(rule_entry, &nat.rules, list) {
				if (rule_entry->external_ip == dst_ip && rule_entry->external_port == dst_port) {
					u16 ext_port = assign_external_port();
					map_entry = new_map_entry(src_ip, src_port, ext_port, rule_entry->external_ip, 
					rule_entry->external_port, rule_entry->internal_ip, rule_entry->internal_port);

					log(DEBUG, "dnat new mapping: "IP_FMT" %d -> "IP_FMT" %d\n", HOST_IP_FMT_STR(rule_entry->internal_ip), 
					rule_entry->internal_port, HOST_IP_FMT_STR(rule_entry->external_ip), rule_entry->external_port);
					log(DEBUG, "snat new mapping: "IP_FMT" %d -> "IP_FMT" %d\n", HOST_IP_FMT_STR(src_ip), src_port, HOST_IP_FMT_STR(nat.public_ip), ext_port);

					dir = DIR_IN;
					find = 1;
					break;
				}
			}
		}
	}

	if (find == 0) {
		log(ERROR, "can not find or build mapping\n");
		icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);
		free(packet);
		pthread_mutex_unlock(&nat.lock);
		return;
	}

	if (dir == DIR_IN) {
		log(DEBUG, "handle in tcp packet\n");
		int clear = (tcp->flags & TCP_RST) ? 1 : 0;
		map_entry->conn.external_fin = (tcp->flags & TCP_FIN) ? 1 : 0;
		map_entry->conn.external_seq_end = tcp_seq_end(ip, tcp);
		map_entry->conn.external_ack = ntohl(tcp->ack);
		map_entry->update_time = time(NULL);

		tcp->dport = htons(map_entry->internal_dst_port);
		tcp->sport = htons(map_entry->external_src_port);
		ip->daddr = htonl(map_entry->internal_dst_ip);
		ip->saddr = htonl(map_entry->external_src_ip);

		tcp->checksum = tcp_checksum(ip, tcp);
		ip->checksum = ip_checksum(ip);

		rt_entry_t *rt_dest = longest_prefix_match(map_entry->internal_dst_ip);
		if (!rt_dest) {
			log(ERROR, "can not find the route to dest ip\n");
			icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);
			free(packet);
			pthread_mutex_unlock(&nat.lock);
			return;
		}

		if (rt_dest->gw == 0) {
			iface_send_packet_by_arp(rt_dest->iface, map_entry->internal_dst_ip, packet, len);
		}
		else {
			iface_send_packet_by_arp(rt_dest->iface, rt_dest->gw, packet, len);
		}

		if (clear) {
			nat.assigned_ports[map_entry->external_src_port] = 0;
			list_delete_entry(&(map_entry->list));
			free(map_entry);
		}
	}
	else if (dir == DIR_OUT) {
		log(DEBUG, "handle out tcp packet\n");
		int clear = (tcp->flags & TCP_RST) ? 1 : 0;
		map_entry->conn.internal_fin = (tcp->flags & TCP_FIN) ? 1 : 0;
		map_entry->conn.internal_seq_end = tcp_seq_end(ip, tcp);
		map_entry->conn.internal_ack = ntohl(tcp->ack);
		map_entry->update_time = time(NULL);

		tcp->dport = htons(map_entry->internal_src_port);
		tcp->sport = htons(map_entry->external_dst_port);
		ip->daddr = htonl(map_entry->internal_src_ip);
		ip->saddr = htonl(map_entry->external_dst_ip);

		tcp->checksum = tcp_checksum(ip, tcp);
		ip->checksum = ip_checksum(ip);

		rt_entry_t *rt_dest = longest_prefix_match(map_entry->internal_src_ip);
		if (!rt_dest) {
			log(ERROR, "can not find the route to dest ip\n");
			free(packet);
			pthread_mutex_unlock(&nat.lock);
			return;
		}

		if (rt_dest->gw == 0) {
			iface_send_packet_by_arp(rt_dest->iface, map_entry->internal_src_ip, packet, len);
		}
		else {
			iface_send_packet_by_arp(rt_dest->iface, rt_dest->gw, packet, len);
		}

		if (clear) {
			nat.assigned_ports[map_entry->external_src_port] = 0;
			list_delete_entry(&(map_entry->list));
			free(map_entry);
		}
	}

	pthread_mutex_unlock(&nat.lock);
}

void nat_translate_packet(iface_info_t *iface, char *packet, int len)
{
	struct iphdr *ip = packet_to_ip_hdr(packet);
	if (ip->protocol != IPPROTO_TCP) {
		log(ERROR, "received non-TCP packet (0x%0hhx), drop it", ip->protocol);
		free(packet);
		return;
	}

	do_translation(iface, packet, len);
}

// check whether the flow is finished according to FIN bit and sequence number
// XXX: seq_end is calculated by `tcp_seq_end` in tcp.h
static int is_flow_finished(struct nat_connection *conn)
{
    return (conn->internal_fin && conn->external_fin) && \
            (conn->internal_ack >= conn->external_seq_end) && \
            (conn->external_ack >= conn->internal_seq_end);
}

// nat timeout thread: find the finished flows, remove them and free port
// resource
void *nat_timeout(void *arg)
{
	while (1) {
		sleep(1);
		pthread_mutex_lock(&nat.lock);

		for (int i=0; i<HASH_8BITS; i++) {
			struct nat_mapping *map_entry = NULL, *map_q = NULL;
			list_for_each_entry_safe(map_entry, map_q, &(nat.nat_mapping_list[i]), list) {
				if ((time(NULL) - map_entry->update_time > TCP_ESTABLISHED_TIMEOUT) || is_flow_finished(&(map_entry->conn))) {
					log(DEBUG, "remove map entry, port: %d\n", map_entry->external_src_port);
					nat.assigned_ports[map_entry->external_src_port] = 0;
					list_delete_entry(&(map_entry->list));
					free(map_entry);
				}
			}
		}

		pthread_mutex_unlock(&nat.lock);
	}

	return NULL;
}

int parse_config(const char *filename)
{
	char *line = (char *)malloc(MAX_LINE_LEN);
	FILE *fp = fopen(filename, "r");

	if (fp == NULL) {
		log(ERROR, "config file do not exist\n");
		free(line);
		return -1;
	}

	while (fgets(line, MAX_LINE_LEN, fp)) {
		char *drule = strstr(line, "dnat-rules:");
		if (drule) {
			struct dnat_rule *new_rule = (struct dnat_rule *)malloc(sizeof(struct dnat_rule));
			memset(new_rule, 0, sizeof(struct dnat_rule));
			drule += 12;
			new_rule->external_ip = ipv4_to_int(drule);

			drule = strstr(drule, ":");
			drule += 1;
			new_rule->external_port = atoi(drule);

			drule = strstr(line, "->");
			drule += 3;
			new_rule->internal_ip = ipv4_to_int(drule);

			drule = strstr(drule, ":");
			drule += 1;
			new_rule->internal_port = atoi(drule);

			init_list_head(&new_rule->list);
			list_add_tail(&new_rule->list, &nat.rules);

			nat.assigned_ports[new_rule->external_port] = 1;

			log(DEBUG, "dnat_rule: "IP_FMT" %d "IP_FMT" %d\n", HOST_IP_FMT_STR(new_rule->external_ip), 
			new_rule->external_port, HOST_IP_FMT_STR(new_rule->internal_ip), new_rule->internal_port);
			continue;
		}
    }

	fclose(fp);
	free(line);
	return 0;
}

// initialize
void nat_init(const char *config_file)
{
	memset(&nat, 0, sizeof(nat));

	for (int i = 0; i < HASH_8BITS; i++)
		init_list_head(&nat.nat_mapping_list[i]);

	init_list_head(&nat.rules);

	// seems unnecessary
	memset(nat.assigned_ports, 0, sizeof(nat.assigned_ports));

	parse_config(config_file);

	nat.public_ip = ipv4_to_int("159.226.39.100");

	pthread_mutex_init(&nat.lock, NULL);

	pthread_create(&nat.thread, NULL, nat_timeout, NULL);
}

void nat_exit()
{
	for (int i=0; i<HASH_8BITS; i++) {
		struct nat_mapping *map_entry = NULL, *map_q = NULL;
		list_for_each_entry_safe(map_entry, map_q, &(nat.nat_mapping_list[i]), list) {
			list_delete_entry(&(map_entry->list));
			free(map_entry);
		}
	}

	struct dnat_rule *rule = NULL, *rule_q = NULL;
	list_for_each_entry_safe(rule, rule_q, &nat.rules, list) {
		list_delete_entry(&(rule->list));
		free(rule);
	}
}
