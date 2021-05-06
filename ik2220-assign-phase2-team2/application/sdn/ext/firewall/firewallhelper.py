import re
import sys
import json
import copy

# from pox
import pox.lib.packet as PKT
from pox.lib.addresses import IPAddr


class PolicyParser:
    """
    Class for parsing firewall policy files
    """

    def __init__(self):
        self.policy_fields = {
            "dl_type": None,
            "nw_src": None,
            "nw_dst": None,
            "nw_proto": None,
            "tp_src": None,
            "tp_dst": None,
            "in_port": None,
            "out_port": None,
            "priority": None
        }

    def parse(self, policy_file):
        with open(policy_file, "rb") as f:
            polices  = f.read()
            lines = polices.split("\n")
            lines = [re.sub(r"#\s*.*", "", l) for l in lines]                # remove comments
            lines = [re.sub(r"\s{2,}", " ", l).strip() for l in lines]       # remove mulitple spaces in the line
            lines = [ l for l in lines if l]                                 # remove empty lines
            rules = [l.split(" ") for l in lines]                            # split to rules

            # preprocess rules
            parsed_rules = [copy.deepcopy(self.policy_fields) for i in rules]
            for i, l in enumerate(rules):
                if len(l) != 9:
                    print ("Arguments Missing - ", str(l))
                    continue

                # parse dl_type
                if l[0] == '-':
                    parsed_rules[i].pop("dl_type")
                else:
                    if l[0] == "IP":
                        parsed_rules[i]["dl_type"] = PKT.ethernet.IP_TYPE
                # parse nw_src
                if l[1] == '-':
                    parsed_rules[i].pop("nw_src")
                else:
                    parsed_rules[i]["nw_src"] = IPAddr(l[1])
                # parse nw_dst
                if l[2] == '-':
                    parsed_rules[i].pop("nw_dst")
                else:
                    parsed_rules[i]["nw_dst"] = IPAddr(l[2])
                # parse nw_proto
                if l[3] == '-':
                    parsed_rules[i].pop("nw_proto")
                else:
                    if l[3] == "TCP":
                        parsed_rules[i]["nw_proto"] = PKT.ipv4.TCP_PROTOCOL
                    elif l[3] == "UDP":
                        parsed_rules[i]["nw_proto"] = PKT.ipv4.UDP_PROTOCOL
                    elif l[3] == "ICMP":
                        parsed_rules[i]["nw_proto"] = PKT.ipv4.ICMP_PROTOCOL
                # parse tp_src
                if l[4] == '-':
                    parsed_rules[i].pop("tp_src")
                else:
                    parsed_rules[i]["tp_src"] = int(l[4])
                # parse tp_dst
                if l[5] == '-':
                    parsed_rules[i].pop("tp_dst")
                else:
                    parsed_rules[i]["tp_dst"] = int(l[5])
                # parse in_port
                if l[6] == '-':
                    parsed_rules[i].pop("in_port")
                else:
                    parsed_rules[i]["in_port"] = int(l[6])
                # parse out_port
                if l[7] == '-':
                    parsed_rules[i].pop("out_port")
                else:
                    parsed_rules[i]["out_port"] = int(l[7])
                # parse proirity
                if l[8] == '-':
                    parsed_rules[i].pop("priority")
                else:
                    parsed_rules[i]["priority"] = int(l[8])                    
            
            return parsed_rules

        print ("unable to open the policy files: %s" % policy_file)
        

def main():
    parser = PolicyParser()
    parser.parse('/Users/vigneshps/IK2220-SDN-NFV-Firewall/firewall_policies.txt')


if __name__ == "__main__":
    main()