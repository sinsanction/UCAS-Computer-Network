#include "mospf_daemon.h"
#include "mospf_proto.h"
#include "mospf_nbr.h"
#include "mospf_database.h"
#include "arp.h"

#include "ip.h"

#include "list.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

extern ustack_t *instance;

pthread_mutex_t mospf_lock;

const u8 eth_allrouter_addr[ETH_ALEN] = { 0x01, 0x00, 0x5e, 0x00, 0x00, 0x05 };

void mospf_init()
{
	pthread_mutex_init(&mospf_lock, NULL);

	instance->area_id = 0;
	// get the ip address of the first interface
	iface_info_t *iface = list_entry(instance->iface_list.next, iface_info_t, list);
	instance->router_id = iface->ip;
	instance->sequence_num = 0;
	instance->lsuint = MOSPF_DEFAULT_LSUINT;

	iface = NULL;
	list_for_each_entry(iface, &instance->iface_list, list) {
		iface->helloint = MOSPF_DEFAULT_HELLOINT;
		iface->num_nbr = 0;
		init_list_head(&iface->nbr_list);
	}

	init_mospf_db();
}

void *sending_mospf_hello_thread(void *param);
void *sending_mospf_lsu_thread(void *param);
void *checking_nbr_thread(void *param);
void *checking_database_thread(void *param);

void mospf_run()
{
	pthread_t hello, lsu, nbr, db;
	pthread_create(&hello, NULL, sending_mospf_hello_thread, NULL);
	pthread_create(&lsu, NULL, sending_mospf_lsu_thread, NULL);
	pthread_create(&nbr, NULL, checking_nbr_thread, NULL);
	pthread_create(&db, NULL, checking_database_thread, NULL);
}

void print_database(void)
{
	fprintf(stdout, "MOSPF Database:\n");
	fprintf(stdout, "RID\t\tNetwork\t\tMask\t\tNeighbor\n");
	fprintf(stdout, "--------------------------------------------------------\n");
	mospf_db_entry_t *db_entry = NULL;
	list_for_each_entry(db_entry, &mospf_db, list) {
		for (int i=0; i<db_entry->nadv; i++) {
			fprintf(stdout, IP_FMT"\t"IP_FMT"\t"IP_FMT"\t"IP_FMT"\t\n",
				HOST_IP_FMT_STR(db_entry->rid),
				HOST_IP_FMT_STR(db_entry->array[i].network),
				HOST_IP_FMT_STR(db_entry->array[i].mask),
				HOST_IP_FMT_STR(db_entry->array[i].rid));
		}
		fprintf(stdout, "\n");
	}
	fprintf(stdout, "--------------------------------------------------------\n");
}

void mospf_send_hello_packet(iface_info_t *iface)
{
	char *packet = (char *)malloc(ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE);
	struct ether_header *eh = (struct ether_header *)packet;
	struct iphdr *ip = (struct iphdr *)(packet + ETHER_HDR_SIZE);
	struct mospf_hdr *mospf = (struct mospf_hdr *)((char *)ip + IP_BASE_HDR_SIZE);
	struct mospf_hello *mospf_he = (struct mospf_hello *)((char *)mospf + MOSPF_HDR_SIZE);

	memset(packet, 0, ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE);

	mospf_init_hello(mospf_he, iface->mask);

	mospf_init_hdr(mospf, MOSPF_TYPE_HELLO, MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE, instance->router_id, instance->area_id);
	mospf->checksum = mospf_checksum(mospf);

	ip_init_hdr(ip, iface->ip, MOSPF_ALLSPFRouters, IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE, IPPROTO_MOSPF);

	memcpy(eh->ether_dhost, eth_allrouter_addr, ETH_ALEN);
	memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
	eh->ether_type = htons(ETH_P_IP);

	iface_send_packet(iface, packet, ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE);
	free(packet);
}

void mospf_send_lsu_packet(void)
{
	int mospf_lsa_count = 0;
	iface_info_t *iface = NULL;
	list_for_each_entry(iface, &instance->iface_list, list) {
		if (iface->num_nbr) {
			/*
			mospf_nbr_t *nbr = NULL;
			list_for_each_entry(nbr, &iface->nbr_list, list) {
				mospf_lsa_count++;
			}
			*/
			mospf_lsa_count += iface->num_nbr;
		}
		else {
			mospf_lsa_count++;
		}
	}
	log(DEBUG, "send_lsu_packet: neighbor num: %d\n", mospf_lsa_count);
	int mospf_packet_len = MOSPF_HDR_SIZE + MOSPF_LSU_SIZE + mospf_lsa_count * MOSPF_LSA_SIZE;
	char *mospf_packet = (char *)malloc(mospf_packet_len);
	memset(mospf_packet, 0, mospf_packet_len);
	struct mospf_hdr *mospf = (struct mospf_hdr *)mospf_packet;
	struct mospf_lsu *mospf_ls = (struct mospf_lsu *)((char *)mospf + MOSPF_HDR_SIZE);
	struct mospf_lsa *mospf_lsa_array = (struct mospf_lsa *)((char *)mospf_ls + MOSPF_LSU_SIZE);

	int i = 0;
	iface = NULL;
	list_for_each_entry(iface, &instance->iface_list, list) {
		if (iface->num_nbr) {
			mospf_nbr_t *nbr = NULL;
			list_for_each_entry(nbr, &iface->nbr_list, list) {
				mospf_lsa_array[i].network = iface->ip & iface->mask;
				mospf_lsa_array[i].mask = iface->mask;
				mospf_lsa_array[i].rid = nbr->nbr_id;
				i++;
			}
		}
		else {
			mospf_lsa_array[i].network = iface->ip & iface->mask;
			mospf_lsa_array[i].mask = iface->mask;
			mospf_lsa_array[i].rid = 0;
			i++;
		}
	}

	if (i != mospf_lsa_count) {
		log(ERROR, "i != mospf_lsa_count: i: %d, count: %d\n", i, mospf_lsa_count);
	}

	mospf_init_lsu(mospf_ls, mospf_lsa_count);
	instance->sequence_num++;

	mospf_init_hdr(mospf, MOSPF_TYPE_LSU, MOSPF_HDR_SIZE + MOSPF_LSU_SIZE + mospf_lsa_count * MOSPF_LSA_SIZE, instance->router_id, instance->area_id);
	mospf->checksum = mospf_checksum(mospf);

	iface = NULL;
	list_for_each_entry(iface, &instance->iface_list, list) {
		if (iface->num_nbr) {
			mospf_nbr_t *nbr = NULL;
			list_for_each_entry(nbr, &iface->nbr_list, list) {
				char *packet = (char *)malloc(ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + mospf_packet_len);
				struct ether_header *eh = (struct ether_header *)packet;
				struct iphdr *ip = (struct iphdr *)(packet + ETHER_HDR_SIZE);
				char *mospf_message = packet + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE;

				memset(packet, 0, ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + mospf_packet_len);
				memcpy(mospf_message, mospf_packet, mospf_packet_len);

				ip_init_hdr(ip, iface->ip, nbr->nbr_ip, IP_BASE_HDR_SIZE + mospf_packet_len, IPPROTO_MOSPF);

				memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
				eh->ether_type = htons(ETH_P_IP);

				iface_send_packet_by_arp(iface, nbr->nbr_ip, packet, ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + mospf_packet_len);
			}
		}
	}

	free(mospf_packet);
	return;
}

void *sending_mospf_hello_thread(void *param)
{
	while (1) {
		sleep(MOSPF_DEFAULT_HELLOINT);
		pthread_mutex_lock(&mospf_lock);

		iface_info_t *iface = NULL;
		list_for_each_entry(iface, &instance->iface_list, list) {
			mospf_send_hello_packet(iface);
		}

		pthread_mutex_unlock(&mospf_lock);
	}

	return NULL;
}

void *checking_nbr_thread(void *param)
{
	while (1) {
		sleep(1);
		pthread_mutex_lock(&mospf_lock);

		int update = 0;
		iface_info_t *iface = NULL;
		list_for_each_entry(iface, &instance->iface_list, list) {
			mospf_nbr_t *nbr = NULL, *nbr_q = NULL;
			list_for_each_entry_safe(nbr, nbr_q, &iface->nbr_list, list) {
				if (nbr->alive > 3 * iface->helloint) {
					update = 1;
					iface->num_nbr--;
					list_delete_entry(&nbr->list);
					free(nbr);
				}
				else{
					nbr->alive++;
				}
			}
		}

		if (update) {
			mospf_send_lsu_packet();
		}

		pthread_mutex_unlock(&mospf_lock);
	}

	return NULL;
}

void *checking_database_thread(void *param)
{
	while (1) {
		sleep(1);
		pthread_mutex_lock(&mospf_lock);

		int update = 0;
		mospf_db_entry_t *db_entry = NULL, *db_q = NULL;
		list_for_each_entry_safe(db_entry, db_q, &mospf_db, list) {
			if (db_entry->alive > MOSPF_DATABASE_TIMEOUT) {
				update = 1;
				list_delete_entry(&db_entry->list);
				free(db_entry->array);
				free(db_entry);
			}
			else {
				db_entry->alive++;
			}
		}

		if (update) {
			build_route_table();
		}

		pthread_mutex_unlock(&mospf_lock);
	}

	return NULL;
}

void handle_mospf_hello(iface_info_t *iface, const char *packet, int len)
{
	struct iphdr *ip = (struct iphdr *)(packet + ETHER_HDR_SIZE);
	struct mospf_hdr *mospf = (struct mospf_hdr *)((char *)ip + IP_HDR_SIZE(ip));
	struct mospf_hello *mospf_he = (struct mospf_hello *)((char *)mospf + MOSPF_HDR_SIZE);

	pthread_mutex_lock(&mospf_lock);
	mospf_nbr_t *nbr = NULL;
	list_for_each_entry(nbr, &iface->nbr_list, list) {
		if (nbr->nbr_id == ntohl(mospf->rid)) {
			nbr->nbr_ip = ntohl(ip->saddr);
			nbr->nbr_mask = ntohl(mospf_he->mask);
			nbr->alive = 0;

			pthread_mutex_unlock(&mospf_lock);
			return;
		}
	}

	mospf_nbr_t *new_nbr = (mospf_nbr_t *)malloc(sizeof(mospf_nbr_t));
	new_nbr->nbr_id = ntohl(mospf->rid);
	new_nbr->nbr_ip = ntohl(ip->saddr);
	new_nbr->nbr_mask = ntohl(mospf_he->mask);
	new_nbr->alive = 0;
	init_list_head(&new_nbr->list);
	list_add_tail(&new_nbr->list, &iface->nbr_list);
	//iface->helloint = ntohs(mospf_he->helloint);
	iface->num_nbr++;

	mospf_send_lsu_packet();
	pthread_mutex_unlock(&mospf_lock);
	return;
}

void *sending_mospf_lsu_thread(void *param)
{
	while (1) {
		sleep(MOSPF_DEFAULT_LSUINT);
		pthread_mutex_lock(&mospf_lock);

		mospf_send_lsu_packet();

		print_database();

		pthread_mutex_unlock(&mospf_lock);
	}

	return NULL;
}

void handle_mospf_lsu(iface_info_t *iface, char *packet, int len)
{
	struct ether_header *eh = (struct ether_header *)packet;
	struct iphdr *ip = (struct iphdr *)(packet + ETHER_HDR_SIZE);
	struct mospf_hdr *mospf = (struct mospf_hdr *)((char *)ip + IP_HDR_SIZE(ip));
	struct mospf_lsu *mospf_ls = (struct mospf_lsu *)((char *)mospf + MOSPF_HDR_SIZE);
	int update = 0, saved = 0;

	pthread_mutex_lock(&mospf_lock);
	if (instance->router_id == ntohl(mospf->rid)) {
		pthread_mutex_unlock(&mospf_lock);
		return;
	}

	mospf_db_entry_t *db_entry = NULL;
	list_for_each_entry(db_entry, &mospf_db, list) {
		if (db_entry->rid == ntohl(mospf->rid)) {
			saved = 1;
			if (db_entry->seq < ntohs(mospf_ls->seq)) {
				db_entry->seq = ntohs(mospf_ls->seq);
				db_entry->nadv = ntohl(mospf_ls->nadv);
				db_entry->alive = 0;
				free(db_entry->array);
				db_entry->array = (struct mospf_lsa *)malloc(MOSPF_LSA_SIZE * db_entry->nadv);
				memcpy(db_entry->array, (char*)mospf_ls + MOSPF_LSU_SIZE, MOSPF_LSA_SIZE * db_entry->nadv);
				update = 1;
			}
		}
	}

	if (saved == 0) {
		db_entry = (mospf_db_entry_t *)malloc(sizeof(mospf_db_entry_t));
		db_entry->rid = ntohl(mospf->rid);
		db_entry->seq = ntohs(mospf_ls->seq);
		db_entry->nadv = ntohl(mospf_ls->nadv);
		db_entry->alive = 0;
		db_entry->array = (struct mospf_lsa *)malloc(MOSPF_LSA_SIZE * db_entry->nadv);
		memcpy(db_entry->array, (char*)mospf_ls + MOSPF_LSU_SIZE, MOSPF_LSA_SIZE * db_entry->nadv);
		init_list_head(&db_entry->list);
		list_add_tail(&db_entry->list, &mospf_db);
	}

	if (saved == 0 || update == 1) {
		mospf_ls->ttl = mospf_ls->ttl - 1;
		if (mospf_ls->ttl > 0) {
			mospf->checksum = mospf_checksum(mospf);
			iface_info_t *iface_out = NULL;

			list_for_each_entry(iface_out, &instance->iface_list, list) {
				if (iface_out->num_nbr && iface_out != iface) {
					mospf_nbr_t *nbr = NULL;
					list_for_each_entry(nbr, &iface_out->nbr_list, list) {
						char *packet_out = (char *)malloc(len);
						struct ether_header *eh_out = (struct ether_header *)packet_out;
						struct iphdr *ip_out = (struct iphdr *)(packet_out + ETHER_HDR_SIZE);
						memcpy(packet_out, packet, len);

						ip_out->daddr = htonl(nbr->nbr_ip);
						ip_out->checksum = ip_checksum(ip_out);

						memcpy(eh_out->ether_shost, iface_out->mac, ETH_ALEN);
						eh_out->ether_type = htons(ETH_P_IP);

						iface_send_packet_by_arp(iface_out, nbr->nbr_ip, packet_out, len);
					}
				}
			}
		}
		build_route_table();
	}

	pthread_mutex_unlock(&mospf_lock);
	return;
}

void handle_mospf_packet(iface_info_t *iface, char *packet, int len)
{
	struct iphdr *ip = (struct iphdr *)(packet + ETHER_HDR_SIZE);
	struct mospf_hdr *mospf = (struct mospf_hdr *)((char *)ip + IP_HDR_SIZE(ip));

	if (mospf->version != MOSPF_VERSION) {
		log(ERROR, "received mospf packet with incorrect version (%d)", mospf->version);
		return;
	}
	if (mospf->checksum != mospf_checksum(mospf)) {
		log(ERROR, "received mospf packet with incorrect checksum");
		return;
	}
	if (ntohl(mospf->aid) != instance->area_id) {
		log(ERROR, "received mospf packet with incorrect area id");
		return;
	}

	switch (mospf->type) {
		case MOSPF_TYPE_HELLO: {
			//log(DEBUG, "handle mospf hello packet\n");
			handle_mospf_hello(iface, packet, len);
			break;
		}
		case MOSPF_TYPE_LSU: {
			//log(DEBUG, "handle mospf lsu packet\n");
			handle_mospf_lsu(iface, packet, len);
			break;
		}
		default:
			log(ERROR, "received mospf packet with unknown type (%d).", mospf->type);
			break;
	}
}
