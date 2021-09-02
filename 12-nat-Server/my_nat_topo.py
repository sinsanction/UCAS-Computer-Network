#!/usr/bin/python

from mininet.node import OVSBridge
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI

class NATTopo(Topo):
    def build(self):
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        n1 = self.addHost('n1')

        self.addLink(h1, n1)
        self.addLink(h2, n1)

if __name__ == '__main__':
    topo = NATTopo()
    net = Mininet(topo = topo, switch = OVSBridge, controller = None) 

    h1, h2, n1 = net.get('h1', 'h2', 'n1')

    h1.cmd('ifconfig h1-eth0 10.11.0.1/16')
    h1.cmd('route add default gw 10.11.0.254')

    h2.cmd('ifconfig h2-eth0 10.22.0.2/16')
    h2.cmd('route add default gw 10.22.0.254')

    n1.cmd('ifconfig n1-eth0 10.11.0.254/16')
    n1.cmd('ifconfig n1-eth1 10.22.0.254/16')

    for h in (h1, h2):
        h.cmd('./scripts/disable_offloading.sh')
        h.cmd('./scripts/disable_ipv6.sh')

    n1.cmd('./scripts/disable_arp.sh')
    n1.cmd('./scripts/disable_icmp.sh')
    n1.cmd('./scripts/disable_ip_forward.sh')
    n1.cmd('./scripts/disable_ipv6.sh')

    net.start()
    CLI(net)
    net.stop()
