#include "base.h"
#include "stp.h"
#include <stdio.h>

// XXX ifaces are stored in instace->iface_list
extern ustack_t *instance;

extern void iface_send_packet(iface_info_t *iface, const char *packet, int len);

void broadcast_packet(iface_info_t *iface, const char *packet, int len)
{
	iface_info_t *ifc = NULL;
	list_for_each_entry(ifc, &instance->iface_list, list) {
		if (ifc != iface && (stp_port_is_designated(ifc->port) || stp_port_is_root(ifc->port))) {
			iface_send_packet(ifc, packet, len);
		}
	}
}
