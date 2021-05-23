import os
import subprocess

from pox.core import core
from pox.lib.util import dpid_to_str
import pox.openflow.libopenflow_01 as of

# pox components
from pox.forwarding.l2_learning import LearningSwitch
from firewall.firewall import FirewallSwitch
from loadBalancer.lb import load_balancer

# logger
logger = core.getLogger()

# CONSTANTS
switches = [1, 2, 3, 4]
firewall_1 = 5
firewall_2 = 6
loadbalancer = [80]
ids = 7
napt = 8
fw1_policyfile = os.path.join(os.getcwd(), "ext/firewall/fw1_policies.conf")
fw2_policyfile = os.path.join(os.getcwd(), "ext/firewall/fw2_policies.conf")


class FirewallController():
    def __init__(self):
        core.openflow.addListeners(self)

    def _handle_ConnectionUp(self, event):
        # logger.debug("Switch has come up [%s, %s]" % (event.connection.dpid, dpid_to_str(event.dpid)))
        if event.dpid in switches:
            logger.debug("Registering l2 learning switch module for switch %s" % (event.dpid))
            LearningSwitch(event.connection, transparent=False)
        elif event.dpid == firewall_1:
            logger.debug("Initializing firewall 1 on switch %s" % (event.dpid))
            FirewallSwitch(event.connection, policy_file=fw1_policyfile, stateful=False)
        elif event.dpid == firewall_2:
            logger.debug("Initializing firewall 2 on switch %s" % (event.dpid))
            FirewallSwitch(event.connection, policy_file=fw2_policyfile, stateful=True)
        #elif event.dpid == loadbalancer:
        #    logger.debug("Initializing load balancer on switch %s" % (event.dpid))
        #    load_balancer(event.connection)
        elif event.dpid == ids:
            logger.debug("Initializing IDS on switch %s" % (event.dpid))
            subprocess.Popen(["sudo", "click", "../nfv/ids.click", "in_intf=sw7-eth1", "out_intf=sw7-eth2", "insp_intf=sw7-eth3"])
        elif event.dpid == napt:
            logger.debug("Initializing napt on switch %s" % (event.dpid))
            subprocess.Popen(["sudo", "click", "../nfv/napt.click", "sw_int_ip=10.0.0.1", "sw_ext_ip=100.0.0.1"])
        else:
            logger.debug("Unknown switch dpid %s" % (event.dpid))

def launch():
    core.registerNew(FirewallController)
    core.registerNew(click_device,loadbalancer)
