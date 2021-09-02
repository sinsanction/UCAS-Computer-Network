#include "mospf_daemon.h"
#include "mospf_nbr.h"
#include "mospf_proto.h"
#include "mospf_database.h"
#include "rtable.h"
#include "ip.h"
#include "list.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

struct list_head mospf_db;

int node_num;
u32 node_map[MAX_NODE_NUM];

int graph[MAX_NODE_NUM][MAX_NODE_NUM];
int dist[MAX_NODE_NUM];
int visit[MAX_NODE_NUM];
int prev[MAX_NODE_NUM];

int stack[MAX_NODE_NUM];
int stack_top;

void init_mospf_db(void)
{
	init_list_head(&mospf_db);
}

int rid_to_index(u32 rid)
{
	for (int i=0; i<node_num; i++) {
		if (node_map[i] == rid) {
			return i;
		}
	}
	log(ERROR, "unknown rid: "IP_FMT"\n", HOST_IP_FMT_STR(rid));
	return -1;
}

int node_mapped(u32 rid)
{
	for (int i=0; i<node_num; i++) {
		if (node_map[i] == rid) {
			return 1;
		}
	}
	return 0;
}

void get_node_mapped(void)
{
	node_map[0] = instance->router_id;
	node_num = 1;

	iface_info_t *iface = NULL;
	list_for_each_entry(iface, &instance->iface_list, list) {
		if (iface->num_nbr) {
			mospf_nbr_t *nbr = NULL;
			list_for_each_entry(nbr, &iface->nbr_list, list) {
				if (!node_mapped(nbr->nbr_id)) {
					node_map[node_num++] = nbr->nbr_id;
				}
			}
		}
	}

	mospf_db_entry_t *db_entry = NULL;
	list_for_each_entry(db_entry, &mospf_db, list) {
		if (!node_mapped(db_entry->rid)) {
			node_map[node_num++] = db_entry->rid;
		}
		for (int i=0; i<db_entry->nadv; i++) {
			if (db_entry->array[i].rid && !node_mapped(db_entry->array[i].rid))
				node_map[node_num++] = db_entry->array[i].rid;
		}
	}
	/*
	for (int i=0; i<node_num; i++) {
		log(DEBUG, "index: %d, rid "IP_FMT" ", i, HOST_IP_FMT_STR(node_map[i]));
	}*/
}

void clear_route_table(void)
{
	rt_entry_t *rt_entry, *rt_q;
	list_for_each_entry_safe(rt_entry, rt_q, &rtable, list) {
		if (rt_entry->gw) {
            remove_rt_entry(rt_entry);
        } 
	}
}

void init_graph(void)
{
	for (int i=0; i<node_num; i++) {
		for (int j=0; j<node_num; j++) {
			if (i==j)
				graph[i][j] = 0;
			else
				graph[i][j] = INT_MAX;
		}
	}

	iface_info_t *iface = NULL;
	list_for_each_entry(iface, &instance->iface_list, list) {
		if (iface->num_nbr) {
			mospf_nbr_t *nbr = NULL;
			list_for_each_entry(nbr, &iface->nbr_list, list) {
				graph[0][rid_to_index(nbr->nbr_id)] = 1;
				graph[rid_to_index(nbr->nbr_id)][0] = 1;
			}
		}
	}

	mospf_db_entry_t *db_entry = NULL;
	list_for_each_entry(db_entry, &mospf_db, list) {
		int x = rid_to_index(db_entry->rid);
		for (int i=0; i<db_entry->nadv; i++) {
			if (db_entry->array[i].rid) {
				graph[x][rid_to_index(db_entry->array[i].rid)] = 1;
				graph[rid_to_index(db_entry->array[i].rid)][x] = 1;
			}
		}
	}
	/*
	for (int i=0; i<node_num; i++) {
		for (int j=0; j<node_num; j++) {
			fprintf(stdout, "%d ", graph[i][j]);
		}
		fprintf(stdout, "\n");
	}
	fprintf(stdout, "\n");*/
}

int min_dist(void)
{
	int min_d = INT_MAX;
	int min_i = -1;
	for (int i=0; i<node_num; i++) {
		if (!visit[i] && dist[i] < min_d) {
			min_d = dist[i];
			min_i = i;
		}
	}
	return min_i;
}

void Dijkstra(void)
{
	for (int i=0; i<node_num; i++) {
		dist[i] = INT_MAX;
		visit[i] = 0;
		prev[i] = -1;
	}
	dist[0] = 0;
	stack_top = 0;

	for (int i=0; i<node_num; i++) {
		int u = min_dist();
		if (u == -1) {
			log(ERROR, "all node visited, stopped at: %d\n", i);
			break;
		}
		visit[u] = 1;
		stack[stack_top++] = u;
		
		for (int v=0; v<node_num; v++) {
			if (!visit[v] && (graph[u][v] + dist[u] < dist[v])) {
				dist[v] = graph[u][v] + dist[u];
				prev[v] = u;
			}
		}
	}
	/*
	for (int i=0; i<stack_top; i++) {
		log(DEBUG, "index: %d, dist: %d, prev: %d", stack[i], dist[stack[i]], prev[stack[i]]);
	}*/

	return;
}

void gen_route_table(void)
{
	mospf_db_entry_t *db_entry;
	iface_info_t *iface_out;
	int node_now, find = 0;
	u32 gw;
	
	for (int i=1; i<stack_top; i++) {
		node_now = stack[i];
		find = 0;
		mospf_db_entry_t *db_tmp = NULL;
		list_for_each_entry(db_tmp, &mospf_db, list) {
			if (db_tmp->rid == node_map[node_now]) {
				db_entry = db_tmp;
				find = 1;
			}
		}

		if (find == 0) {
			log(WARNING, "node database not find: %d "IP_FMT"\nhello came before lsu\n", node_now, HOST_IP_FMT_STR(node_map[node_now]));
			continue;
		}

		while (prev[node_now] != 0) {
			node_now = prev[node_now];
		}
		find = 0;
		iface_info_t *iface = NULL;
		list_for_each_entry(iface, &instance->iface_list, list) {
			if (iface->num_nbr) {
				mospf_nbr_t *nbr = NULL;
				list_for_each_entry(nbr, &iface->nbr_list, list) {
					if (nbr->nbr_id == node_map[node_now]) {
						iface_out = iface;
						gw = nbr->nbr_ip;
						find = 1;
					}
				}
			}
		}

		if (find == 0) {
			log(WARNING, "nerghbor not find: %d "IP_FMT"\nlsu came before hello\n", node_now, HOST_IP_FMT_STR(node_map[node_now]));
			continue;
		}

		for (int j=0; j<db_entry->nadv; j++) {
			find = 0;
			rt_entry_t *rt_entry = NULL;
			list_for_each_entry(rt_entry, &rtable, list) {
				if (rt_entry->dest == db_entry->array[j].network) {
					find = 1;
				}
			}

			if (find == 0) {
				rt_entry = new_rt_entry(db_entry->array[j].network, db_entry->array[j].mask, gw, iface_out);
				add_rt_entry(rt_entry);
			}
		}
	}
}

void build_route_table(void)
{
	clear_route_table();
	get_node_mapped();

	init_graph();
	Dijkstra();
	
	gen_route_table();
	print_rtable();

	return;
}