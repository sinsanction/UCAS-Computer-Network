#include "base.h"
#include <stdio.h>

// XXX ifaces are stored in instace->iface_list
extern ustack_t *instance;

extern void iface_send_packet(iface_info_t *iface, const char *packet, int len);

void broadcast_packet(iface_info_t *iface, const char *packet, int len)
{
	// TODO: broadcast packet 
	//fprintf(stdout, "TODO: broadcast packet.\n");
	iface_info_t *ifc = NULL;
	list_for_each_entry(ifc, &instance->iface_list, list) {
		if (ifc != iface) {
			iface_send_packet(ifc, packet, len);
		}
	}
}
