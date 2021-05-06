import time
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import RemoteController, OVSSwitch, Switch

from IDSTests import TestIDS

class Topology(Topo):

    def __init__(self):
        # initialize base class
        Topo.__init__(self)

        ids = self.addSwitch("sw1", mac="00:00:00:00:00:11")
        h1 = self.addHost("h1", ip="100.0.0.10/24", mac="00:00:00:00:00:01")
        h2 = self.addHost("h2", ip="100.0.0.11/24", mac="00:00:00:00:00:02")
        h3 = self.addHost("h3", ip="100.0.0.12/24", mac="00:00:00:00:00:03")
        self.addLink(ids, h1)
        self.addLink(ids, h2)
        self.addLink(ids, h3)


def start_arp(net):
    for host in ["h1","h2","h3","h4"]:
	client = net.get(host)
	# access web server through 100.0.0.30 for loadbalance
	client.cmd("arp -s 100.0.0.30 00:00:00:00:00:14")


def restart_web_server(net, host):
    print("Restarting HTTP server %s on port 80" % host.upper()) 
    server = net.get(host)
    server.cmd("pkill -9 python2") 
    server.cmd("python2 -m SimpleHTTPServer 80 &")   


def start_web_servers(net):
    # start web servers
    for ws in ["h2"]:
        print("Starting HTTP server %s on port 80" % ws.upper()) 
        server = net.get(ws)
        server.cmd("python2 -m SimpleHTTPServer 80 &")


def start_tshark(net):
    # start web servers
    for ws in ["h3"]:
        print("Starting Wireshark on host %s on interface h3-eth0" % ws.upper()) 
        server = net.get(ws)
        server.cmd("tshark -i h3-eth0 -w /opt/IDS.pcap &")






def setup():
    # create a topology
    topology = Topology()
    # start a controller
    controller = RemoteController("pox_controller", ip="127.0.0.1", port=6633)
    # start minient 
    
    #net = Mininet(topo=topology)
    net = Mininet(topo=topology, switch=OVSSwitch, controller=controller, autoSetMacs=True, autoStaticArp=True, build=True, cleanup=True)
    net.start()

    # virtual ip
    # start_arp(net)
    start_web_servers(net)
    start_tshark(net)

    # test 
    time.sleep(3)
    ids_tests = TestIDS(net)
    ids_tests.run_tests()
    ids_tests.get_results()

    # start cli
    CLI(net)



if __name__ == "__main__":
    setup()
