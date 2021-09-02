#include "base.h"
#include "ether.h"
#include "arp.h"
#include "arpcache.h"
#include "ip.h"
#include "rtable.h"
#include "tcp_sock.h"
#include "tcp_apps.h"

#include "log.h"

#include <stdlib.h>
#include <unistd.h>
#include <libgen.h>

// handle packet, hand the packet to handle_ip_packet or handle_arp_packet
// according to ether_type
void handle_packet(iface_info_t *iface, char *packet, int len)
{
	struct ether_header *eh = (struct ether_header *)packet;

	//log(DEBUG, "got packet from %s, %d bytes, proto: 0x%04hx\n", iface->name, len, ntohs(eh->ether_type));
	switch (ntohs(eh->ether_type)) {
		case ETH_P_IP:
			handle_ip_packet(iface, packet, len);
			break;
		case ETH_P_ARP:
			handle_arp_packet(iface, packet, len);
			break;
		default: {
			log(ERROR, "Unknown packet type 0x%04hx, ingore it.", ntohs(eh->ether_type));
			free(packet);
			break;
		}
	}
}

void ustack_run()
{
	struct sockaddr_ll addr;
	socklen_t addr_len = sizeof(addr);
	char buf[ETH_FRAME_LEN];
	int len;

	while (1) {
		int ready = poll(instance->fds, instance->nifs, -1);
		if (ready < 0) {
			perror("Poll failed!");
			break;
		}
		else if (ready == 0)
			continue;

		for (int i = 0; i < instance->nifs; i++) {
			if (instance->fds[i].revents & POLLIN) {
				len = recvfrom(instance->fds[i].fd, buf, ETH_FRAME_LEN, 0, \
						(struct sockaddr*)&addr, &addr_len);
				if (len <= 0) {
					log(ERROR, "receive packet error: %s", strerror(errno));
				}
				else if (addr.sll_pkttype == PACKET_OUTGOING) {
					// XXX: Linux raw socket will capture both incoming and
					// outgoing packets, we only care about the incoming ones.

					// log(DEBUG, "received packet which is sent from the "
					// 		"interface itself, drop it.");
				}
				else {
					iface_info_t *iface = fd_to_iface(instance->fds[i].fd);
					char *packet = malloc(len);
					if (!packet) {
						log(ERROR, "malloc failed when receiving packet.");
						continue;
					}
					memcpy(packet, buf, len);
					handle_packet(iface, packet, len);
				}
			}
		}
	}
}

static void usage_and_exit(const char *basename)
{
	fprintf(stderr, "Usage: \n");
	fprintf(stderr, "\t%s server local_port\n", basename);
	fprintf(stderr, "\t%s client remote_ip remote_port\n", basename);

	exit(1);
}

static void run_application(const char *basename, char **args, int n)
{
	pthread_t thread;

	if (strcmp(args[0], "server") == 0) {
		if (n != 2)
			usage_and_exit(basename);

		u16 port = htons(atoi(args[1]));
		pthread_create(&thread, NULL, tcp_server, &port);
	}
	else if (strcmp(args[0], "client") == 0) {
		if (n != 3)
			usage_and_exit(basename);

		struct sock_addr skaddr;
		skaddr.ip = inet_addr(args[1]);
		skaddr.port = htons(atoi(args[2]));
		pthread_create(&thread, NULL, tcp_client, &skaddr);
	}
	else {
		usage_and_exit(basename);
	}
}

int main(int argc, char **argv)
{
	if (getuid() && geteuid()) {
		fprintf(stderr, "Permission denied, should be superuser!\n");
		exit(1);
	}

	if (argc < 2) {
		usage_and_exit(argv[0]);
	}

	init_ustack();

	arpcache_init();

	init_rtable();
	load_rtable_from_kernel();

	init_tcp_stack();

	run_application((const char *)basename(argv[0]), argv+1, argc-1);

	ustack_run();

	return 0;
}
