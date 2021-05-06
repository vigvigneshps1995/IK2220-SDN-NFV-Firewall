from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import RemoteController, OVSSwitch, Switch
import random

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

def start_arp(net):
    for host in ["h1","h2","h3","h4"]:
	client = net.get(host)
	# access web server through 100.0.0.30 for loadbalance
	client.cmd("arp -s 100.0.0.30 00:00:00:00:00:14")

def test(net):
	
    def succeed():
        global numberTest
        global scoreTest
        numberTest += 1
        scoreTest += 1
        return "SUCCEED!\n"

    def fail():
    	global numberTest
    	numberTest += 1
        return "FAIL!\n"
    ## testing start ##
    with  open('../results/phase_1_report.txt','w') as f:
        f.write('Hello,testing starts!\n')
        #Network links test

        for PbZ_h in ["h1", "h2"]:
            PbZ_h = net.get(PbZ_h)
            
            for PrZ_h in ['100.0.0.50', '100.0.0.51']:
                f.write('[Test1]From PbZ: {} ping PrZ: {}: it should not work!\n'.format(PbZ_h, PrZ_h))
                f.write('{} ping -c 1 -W 1 {}\n'.format(PbZ_h,PrZ_h))
                log = int(PbZ_h.cmd('ping -c 1 -W 1 {}'.format(PrZ_h) + '> /dev/null; echo $?'))
                f.write( succeed() if log != 0 else fail())
                
            for DmZ_s in ['100.0.0.40','100.0.0.41','100.0.0.42']:
                f.write('[Test2]From PbZ: {} ping DmZ: {} port = 80: it should work!\n'.format(PbZ_h, DmZ_s))
                f.write('{} curl --connect-timeout 2 {}:80 -I\n'.format(PbZ_h,DmZ_s))
                std = str(PbZ_h.cmd('curl --connect-timeout 2 {}:80 -I'.format(DmZ_s)))
                log = str(PbZ_h.cmd('curl --connect-timeout 2 {}:80 -I'.format(DmZ_s)))
                f.write( succeed() if log[1:20] == std[1:20] else fail())
                
                for a in range(5):
                    port = random.randint(1,10000)
                    f.write('[Test2]From PbZ: {} ping DmZ: {} random port = {}: it should not work!\n'.format(PbZ_h, DmZ_s,port))
                    f.write('{} curl --connect-timeout 2 {}:{} -I\n'.format(PbZ_h,DmZ_s,port))
                    log = str(PbZ_h.cmd('curl --connect-timeout 2 {}:{} -I'.format(DmZ_s,port)))
                    f.write( succeed() if log != std else fail())
                
        
        f.write("[Test3]: From PrZ to PbZ, it should be ok\n")
        for PrZ_h in ["h3", "h4"]:
            PrZ_h = net.get(PrZ_h)
            
            for PbZ_h in ['100.0.0.10', '100.0.0.11']:
                f.write('[Test3]From PrZ: {} ping PbZ: {}: it should work!\n'.format(PrZ_h, PbZ_h))
                f.write('{} ping -c 1 -W 1 {}\n'.format(PrZ_h,PbZ_h))
                log = int(PrZ_h.cmd('ping -c 1 -W 1 {}'.format(PbZ_h) + '> /dev/null; echo $?'))
                f.write( succeed() if log == 0 else fail())
                
            for DmZ_s in ['100.0.0.40','100.0.0.41','100.0.0.42']:
                f.write('[Test2]From PrZ: {} ping DmZ: {} port = 80: it should work!\n'.format(PrZ_h, DmZ_s))
                f.write('{} curl --connect-timeout 2 {}:80 -I\n'.format(PrZ_h,DmZ_s))
                std = str(PrZ_h.cmd('curl --connect-timeout 2 {}:80 -I'.format(DmZ_s)))
                log = str(PrZ_h.cmd('curl --connect-timeout 2 {}:80 -I'.format(DmZ_s)))
                f.write( succeed() if log[1:20] == std[1:20] else fail())
                
                for a in range(5):
                    port = random.randint(1,10000)
                    f.write('[Test2]From PrZ: {} ping DmZ: {} random port = {}: it should not work!\n'.format(PrZ_h, DmZ_s,port))
                    f.write('{} curl --connect-timeout 2 {}:{} -I\n'.format(PrZ_h,DmZ_s,port))
                    log = str(PrZ_h.cmd('curl --connect-timeout 2 {}:{} -I'.format(DmZ_s,port)))
                    f.write( succeed() if log != std else fail())
        
        f.write('Testing finished\n The final score is {}/{}\n'.format(scoreTest,numberTest))
        f.close()

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
    # test
    test(net)
    # start cli
    CLI(net)



if __name__ == "__main__":
    numberTest = 0
    scoreTest = 0
    setup()
