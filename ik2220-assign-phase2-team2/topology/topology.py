from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import RemoteController, OVSSwitch, Switch

class Topology(Topo):

    def __init__(self):
        # initialize base class
        Topo.__init__(self)

        sw1 = self.addSwitch("sw1", mac="00:00:00:00:00:11")
        sw2 = self.addSwitch("sw2", mac="00:00:00:00:00:12")
        sw3 = self.addSwitch("sw3", mac="00:00:00:00:00:13")
        sw4 = self.addSwitch("sw4", mac="00:00:00:00:00:14")
        fw1 = self.addSwitch("sw5")
        fw2 = self.addSwitch("sw6")
        ids = self.addSwitch("sw7")

        ### PUBLIC ZONE ###
        h1 = self.addHost("h1", ip="100.0.0.10/24", mac="00:00:00:00:00:01")
        h2 = self.addHost("h2", ip="100.0.0.11/24", mac="00:00:00:00:00:02")
        self.addLink(h1, sw1)
        self.addLink(h2, sw1)

        ### PRIVATE ZONE ###
        h3 = self.addHost("h3", ip="100.0.0.50/24", mac="00:00:00:00:00:03")
        h4 = self.addHost("h4", ip="100.0.0.51/24", mac="00:00:00:00:00:04")
        self.addLink(h3, sw3)
        self.addLink(h4, sw3)

        ### DEMILITARIZED ZONE ###
        ws1 = self.addHost("ws1", ip="100.0.0.40/24", mac="00:00:00:00:00:05")
        ws2 = self.addHost("ws2", ip="100.0.0.41/24", mac="00:00:00:00:00:06")
        ws3 = self.addHost("ws3", ip="100.0.0.42/24", mac="00:00:00:00:00:07")
        insp = self.addHost("insp", ip="100.0.0.30/24", mac="00:00:00:00:00:08")
        self.addLink(ws1, sw4)
        self.addLink(ws2, sw4)
        self.addLink(ws3, sw4)
        self.addLink(sw2, ids)
        self.addLink(ids, sw4)
        self.addLink(ids, insp)

        # ### INTERZONE LINKS ###
        self.addLink(sw1, fw1)
        self.addLink(fw1, sw2)
        self.addLink(sw2, fw2)
        self.addLink(fw2, sw3)


def start_web_servers(net):
    # start web servers
    for ws in ["ws1", "ws2", "ws3"]:
        print("Starting HTTP server %s on port 80" % ws.upper()) 
        server = net.get(ws)
        server.cmd("python2 -m SimpleHTTPServer 80 &")


def start_arp(net):
    for host in ["h1","h2","h3","h4"]:
	client = net.get(host)
	# access web server through 100.0.0.30 for loadbalance
	client.cmd("arp -s 100.0.0.30 00:00:00:00:00:14")


def start_tshark(net):
    # start web servers
    for host in ["insp"]:
        print("Starting Wireshark on host %s on interface insp-eth0" % host.upper()) 
        server = net.get(host)
        server.cmd("tshark -i insp-eth0 -w /opt/IDS.pcap &")


def setup():
    # create a topology
    topology = Topology()
    # start a controller
    controller = RemoteController("pox_controller", ip="127.0.0.1", port=6633)
    # start minient 
    net = Mininet(topo=topology, switch=OVSSwitch, controller=controller, autoSetMacs=True, autoStaticArp=True, build=True, cleanup=True)
    net.start()

    # web servers
    start_web_servers(net)
    # virtual ip
    start_arp(net)
    # start tshark
    start_tshark(net)

    # start cli
    CLI(net)



if __name__ == "__main__":
    setup()
