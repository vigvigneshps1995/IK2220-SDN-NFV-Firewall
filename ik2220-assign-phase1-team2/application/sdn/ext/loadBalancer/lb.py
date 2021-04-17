from pox.core import core
from pox.lib.addresses import IPAddr,EthAddr,parse_cidr
from pox.lib.revent import EventContinue,EventHalt
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpidToStr

virtual_ip = IPAddr("100.0.0.30")
virtual_mac = EthAddr("00:00:00:00:00:014")

server = {}
server[0] = {'ip':IPAddr("100.0.0.40"), 'mac':EthAddr("00:00:00:00:00:05"), 'outport': 1}
server[1] = {'ip':IPAddr("100.0.0.41"), 'mac':EthAddr("00:00:00:00:00:06"), 'outport': 2}
server[2] = {'ip':IPAddr("100.0.0.42"), 'mac':EthAddr("00:00:00:00:00:07"), 'outport': 3}
total_servers = len(server)

server_index = 0 

class load_balancer (object):
    def __init__ (self, connection):
	self.connection = connection
	
        # Listen to the connection
	connection.addListeners(self)

    def _handle_PacketIn (self, event):
        global server_index 
        packet = event.parsed

        # IPv4 check
        if (not event.parsed.find("ipv4")):
            
            return EventContinue

        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)

        # IP check
        if (msg.match.nw_dst != virtual_ip):
            return EventContinue

        # Roundrobin 
        index = server_index % total_servers
        print index
        selected_server_ip = server[index]['ip']
        selected_server_mac = server[index]['mac']
        selected_server_outport = server[index]['outport']
        server_index += 1

        # Setup route to server
        msg.buffer_id = event.ofp.buffer_id
        msg.in_port = event.port

        msg.actions.append(of.ofp_action_dl_addr(of.OFPAT_SET_DL_DST, selected_server_mac))
        msg.actions.append(of.ofp_action_nw_addr(of.OFPAT_SET_NW_DST, selected_server_ip))
        msg.actions.append(of.ofp_action_output(port = selected_server_outport))
        event.connection.send(msg)

        # Setup reverse route from server
        reverse_msg = of.ofp_flow_mod()
        reverse_msg.buffer_id = None
        reverse_msg.in_port = selected_server_outport

        reverse_msg.match = of.ofp_match()
        reverse_msg.match.dl_src = selected_server_mac
        reverse_msg.match.nw_src = selected_server_ip
        reverse_msg.match.tp_src = msg.match.tp_dst

        reverse_msg.match.dl_dst = msg.match.dl_src
        reverse_msg.match.nw_dst = msg.match.nw_src
        reverse_msg.match.tp_dst = msg.match.tp_src

        reverse_msg.actions.append(of.ofp_action_dl_addr(of.OFPAT_SET_DL_SRC, virtual_mac))
        reverse_msg.actions.append(of.ofp_action_nw_addr(of.OFPAT_SET_NW_SRC, virtual_ip))
        reverse_msg.actions.append(of.ofp_action_output(port = msg.in_port))
        event.connection.send(reverse_msg)

        return EventHalt  
    
    def launch ():
        core.openflow.addListenerByName("PacketIn", _handle_PacketIn, priority=2)
        log.debug("Load Balancer is running")
