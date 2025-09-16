#!/usr/bin/python
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import Controller

class MyTopology(Topo):
    """
    A basic topology
    """
    def __init__(self):
        Topo.__init__(self)

        # Set Up Topology Here
        switch = self.addSwitch('s1') ## Adds a Switch
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')

        self.addLink(h1, switch)
        self.addLink(h2, switch)
        self.addLink(h3, switch)
        self.addLink(h4, switch)

if __name__ == '__main__':
    """
    If this script is run as an executable (by chmod +x), this is
    what it will do
    """
    topo = MyTopology() ## Creates the topology
    net = Mininet( topo=topo, controller=Controller) ## Loads the topology
    net.start() ## Starts Mininet

    # Commands here will run on the simulated topology
    CLI(net)
    net.stop() ## Stops Mininet