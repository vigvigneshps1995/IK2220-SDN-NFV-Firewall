import os

from pox.core import core
from pox.lib.util import dpid_to_str
import pox.openflow.libopenflow_01 as of

# pox components
from pox.forwarding.l2_learning import LearningSwitch
from firewall.firewall import FirewallSwitch


# logger
logger = core.getLogger()

# CONSTANTS
switches = [1, 2, 3, 4]
firewall_1 = 5
firewall_2 = 6
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
        else:
            logger.debug("Unknown switch dpid %s" % (event.dpid))

def launch():
    core.registerNew(FirewallController)
