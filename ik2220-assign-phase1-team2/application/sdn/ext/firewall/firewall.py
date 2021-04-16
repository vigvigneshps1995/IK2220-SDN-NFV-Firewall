import re
import sys
import json

# pox
from pox.core import core
import pox.lib.packet as PKT
import pox.openflow.libopenflow_01 as of

# helper functions
from firewallhelper import PolicyParser

# logger
logger = core.getLogger()


class FirewallSwitch():

    def __init__(self, connection, policy_file=None, stateful=False):
        self.connection = connection
        self.dpid = connection.dpid
        self.policy_file = policy_file
        self.stateful = False
        core.openflow.addListeners(self)
        if self.policy_file:
            logger.debug("Configuring firewall %s with the following static policies:" % self.dpid)
            policy_parser = PolicyParser().parse
            policies = policy_parser(self.policy_file)
            for p in policies:
                self.install_rule(**p)
        if stateful:
            logger.debug("Configuring firewall %s as a stateful firewall" % self.dpid)
            self.stateful = True

    def log_policy(self, dl_type=None, nw_src=None, nw_dst=None, nw_proto=None, tp_src=None, tp_dst=None,
                            in_port=None, out_port=None, priority=None, idle_timeout=None, hard_timeout=None):
        protocol_type = ""
        if dl_type == PKT.ethernet.IP_TYPE: dl_type = "IPV4"
        if nw_proto == PKT.ipv4.TCP_PROTOCOL: protocol_type = "TCP" 
        if nw_proto == PKT.ipv4.UDP_PROTOCOL: protocol_type = "UDP"
        if nw_proto == PKT.ipv4.ICMP_PROTOCOL: protocol_type = "ICMP"
        tp_src =  str(tp_src) if tp_src else ""
        src_ip = nw_src.toStr() if nw_src else ""
        dst_ip = nw_dst.toStr() if nw_dst else ""
        tp_dst =  str(tp_dst) if tp_dst else ""
        rule_action = "ALLOW" if out_port else "DENY"
        msg = "PROTO[{},{}] [{}:{}]->[{}:{}] SW_PORTS=[{}->{}] PROIR={} TIMOUTS=[{}, {}] ----- {}]"
        msg = msg.format(dl_type, protocol_type, src_ip, tp_src, dst_ip, tp_dst, str(in_port),
                         str(out_port), str(priority), str(idle_timeout), str(hard_timeout), rule_action)
        logger.debug(msg)

    def install_rule(self, dl_type=None, nw_src=None, nw_dst=None, nw_proto=None, tp_src=None, tp_dst=None,
                            in_port=None, out_port=None, priority=None, idle_timeout=None, hard_timeout=None):
        # log
        self.log_policy(dl_type, nw_src, nw_dst, nw_proto, tp_src, tp_dst, in_port, out_port, priority, idle_timeout, hard_timeout)
        # match object
        match = of.ofp_match()
        if dl_type: match.dl_type = dl_type
        if nw_src: match.nw_src = nw_src
        if nw_dst: match.nw_dst = nw_dst
        if nw_proto: match.nw_proto = nw_proto
        if tp_src: match.tp_src = tp_src
        if tp_dst: match.tp_dst = tp_dst
        if in_port: match.in_port = in_port
        # flow mod message
        msg = of.ofp_flow_mod()
        msg.match = match
        if priority: msg.priority = priority
        if idle_timeout: msg.idle_timeout = idle_timeout
        if hard_timeout: msg.hard_timeout = hard_timeout
        # action
        if out_port:
            msg.actions.append(of.ofp_action_output(port=out_port))
        # send message
        self.connection.send(msg)

    def resend_packet(self, packet, out_port):
        msg = of.ofp_packet_out()
        msg.data = packet
        msg.actions.append(of.ofp_action_output(port=out_port))
        logger.debug("Packet resend to %s to port %s", self.dpid, out_port)
        self.connection.send(msg)

    def _handle_PacketIn(self, event):
        if not (event.connection.dpid == self.dpid and self.stateful):
            return
        packet = event.parsed
        if not packet.parsed:
            logger.warning("Packet parsing failed")
            return
        packet_in = event.ofp

        if event.port == 2:
            logger.debug("Packet arrived on firewall %s on port %s (from inside private network)", self.dpid, event.port)

            if packet.type == PKT.ethernet.IP_TYPE:	
                ip_pkt = packet.payload
                STATEFUL_EXPIRE_TIMEOUT = 1
                # install a temporary flow from inside to outside
                self.install_rule(dl_type=packet.type, nw_src=ip_pkt.srcip, nw_dst=ip_pkt.dstip,
                                  nw_proto=ip_pkt.protocol, in_port=2, out_port=1, 
                                  priority=50, idle_timeout=STATEFUL_EXPIRE_TIMEOUT)
                # install a temporary flow from outside to inisde with reversed ips
                self.install_rule(dl_type=packet.type, nw_src=ip_pkt.dstip, nw_dst=ip_pkt.srcip,
                                  nw_proto=ip_pkt.protocol, in_port=1, out_port=2,
                                  priority=50, idle_timeout=STATEFUL_EXPIRE_TIMEOUT)
                # resend packet back to firewall
                self.resend_packet(packet, 1)

        elif event.port == 1:
            logger.debug("Packet arrived on firewall %s on port %s (from outside private network)", self.dpid, event.port)

            # print drop packet
        

if __name__ == "__main__":
    fw = FirewallSwitch(connection=None, policy_file="fw1_policies.conf")
