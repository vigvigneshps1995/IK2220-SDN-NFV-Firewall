from pox.core import core
from pox.lib.util import dpid_to_str
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as PKT
from pox.lib.packet import *
from pox.lib.addresses import IPAddr
import subprocess

log = core.getLogger()
import shlex, os, signal

#
# click router component
#
class click_device (object):
	def __init__(self, clics_dpid = None):
		core.openflow.addListeners(self)
		self.click_dpid = set(click_dpid) if click_dpid else ()
		self.click_proc = None

	def _handle_ConnectionUp (self, event):
		if event.dpid not in self.click_dpid:
			return
		log.debug("Connection from CLICK: [{}] - {} ".format(event.dpid, event.connection))

		click_path = "../nfv"
		args = ""
		if event.dpid == 80:
			args = "sudo /usr/local/bin/click -f " + click_path + "/lb.click in_if=lb1-eth2 out_if=lb1-eth1 sw_ip=100.0.0.45 s1=100.0.0.40 s2=100.0.0.41 s3=100.0.0.42 port=80 proto=tcp lb=1"
			
		log.debug("[{}] RUN: {}".format(event.dpid, args ))
		args = shlex.split(args)
		self.click_proc = subprocess.Popen(args)

	def _handle_ConnectionDown(self, event):
		if event.dpid in self.click_dpid:
			log.debug("[CLICK: {}] Terminating..".format(event.dpid))
