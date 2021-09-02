#ifndef __BASE_H__
#define __BASE_H__

#include "types.h"
#include "ether.h"
#include "list.h"

#include <unistd.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <poll.h>
#include <ifaddrs.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/route.h>
#include <net/if.h>

#include <linux/if_packet.h>
#include <linux/udp.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#define DYNAMIC_ROUTING

typedef struct {
	struct list_head iface_list;	// the list of interfaces
	int nifs;						// number of interfaces
	struct pollfd *fds;				// structure used to poll packets among 
								    // all the interfaces

#ifdef DYNAMIC_ROUTING
	// used for mospf routing
	u32 area_id;	
	u32 router_id;
	u16 sequence_num;
	int lsuint;
#endif
} ustack_t;

extern ustack_t *instance;

typedef struct {
	struct list_head list;		// list node used to link all interfaces

	int fd;						// file descriptor for receiving & sending packets
	int index;					// the index (unique ID) of this interface
	u8	mac[ETH_ALEN];			// mac address of this interface
	u32 ip;						// IPv4 address (in host byte order)
	u32 mask;					// Network Mask (in host byte order)
	char name[16];				// name of this interface
	char ip_str[16];			// readable IP address

#ifdef DYNAMIC_ROUTING
	// list of mospf neighbors
	int helloint;
	int num_nbr;
	struct list_head nbr_list;
#endif
} iface_info_t;

void init_ustack();
iface_info_t *fd_to_iface(int fd);
void iface_send_packet(iface_info_t *iface, const char *packet, int len);
#endif
