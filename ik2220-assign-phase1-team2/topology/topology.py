from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import RemoteController, OVSSwitch, Switch


class Topology(Topo):

    def __init__(self):
        # initialize base class
        Topo.__init__(self)

        sw1 = self.addSwitch("sw1")
        sw2 = self.addSwitch("sw2")
        sw3 = self.addSwitch("sw3")
        sw4 = self.addSwitch("sw4")
        fw1 = self.addSwitch("sw5")
        fw2 = self.addSwitch("sw6")

        ### PUBLIC ZONE ###
        h1 = self.addHost("h1", ip="100.0.0.10/24")
        h2 = self.addHost("h2", ip="100.0.0.11/24")
        self.addLink(h1, sw1)
        self.addLink(h2, sw1)

        ### PRIVATE ZONE ###
        h3 = self.addHost("h3", ip="100.0.0.50/24")
        h4 = self.addHost("h4", ip="100.0.0.51/24")
        self.addLink(h3, sw3)
        self.addLink(h4, sw3)

        ### DEMILITARIZED ZONE ###
        ws1 = self.addHost("ws1", ip="100.0.0.40/24")
        ws2 = self.addHost("ws2", ip="100.0.0.41/24")
        ws3 = self.addHost("ws3", ip="100.0.0.42/24")
        self.addLink(ws1, sw4)
        self.addLink(ws2, sw4)
        self.addLink(ws3, sw4)
        self.addLink(sw2, sw4)

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

    # start cli
    CLI(net)




if __name__ == "__main__":
    setup()
