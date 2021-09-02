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

typedef struct {
	struct list_head iface_list;
	int nifs;
	struct pollfd *fds;
} ustack_t;

extern ustack_t *instance;

typedef struct stp_port stp_port_t;
typedef struct {
	struct list_head list;

	int fd;

	int index;
	u8	mac[ETH_ALEN];
	char name[16];

	stp_port_t *port;
} iface_info_t;

void init_ustack();
iface_info_t *fd_to_iface(int fd);
void iface_send_packet(iface_info_t *iface, const char *packet, int len);

void broadcast_packet(iface_info_t *iface, const char *packet, int len);

#endif
