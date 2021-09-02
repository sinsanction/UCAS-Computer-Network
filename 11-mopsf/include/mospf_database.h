#ifndef __MOSPF_DATABASE_H__
#define __MOSPF_DATABASE_H__

#include "base.h"
#include "list.h"

#include "mospf_proto.h"

#define MAX_NODE_NUM 30
#define MAX_NET_NUM 50
#define INT_MAX 0x1fffffff

extern struct list_head mospf_db;

typedef struct {
	struct list_head list;
	u32	rid;
	u16	seq;
	int nadv;
	int alive;
	struct mospf_lsa *array;
} mospf_db_entry_t;

void init_mospf_db(void);
void build_route_table(void);

#endif
