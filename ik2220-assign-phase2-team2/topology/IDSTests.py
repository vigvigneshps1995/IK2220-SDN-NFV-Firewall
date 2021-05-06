import random
import time
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import RemoteController, OVSSwitch, Switch



class TestIDS:

    HOSTS = ['h1', 'h2', 'h3', 'h4']
    WEB_SERVERS = ['100.0.0.40', '100.0.0.41', '100.0.0.42']
    LOAD_BALANCER_IP = '100.0.0.45'
    INSPECTER_HOST = 'insp'

    def __init__(self, mininet_ctrl):
        self.ctrl = mininet_ctrl
        self.tests = []
        self.sub_tests = []
        self.commands = []
        self.status = []
        self._PASS = 1
        self._FAIL = 0

    def _get_ping_cmd(self, dst, count=5):
        return 'ping -c {0} -W 1 {1} > /dev/null; echo $?'.format(count, dst)

    def _flush_std_out(self, host):
        mn_host = self.ctrl.get(host)
        mn_host.cmd("\n")

    def _restart_web_server(self, host):
        return "{} pkill -9 python2;python2 -m SimpleHTTPServer 80 &".format(host)

    def _get_http_request(self, web_server, method, data=None, max_time=2, connect_time=5, keepalive=0):
        cmd = "curl --max-time {0} --connect-time {1} --keepalive-time {2}".format(max_time, connect_time, keepalive)
        cmd = cmd + " -X {0} ".format(method.upper())
        if data is not None:
            cmd = cmd + " -d '{}' ".format(data)
        cmd = cmd + web_server
        return cmd
    
    def _get_filesize_cmd(self, file):
        return "du -h {}".format(file)

    def run_tests(self):
        print ("\n\n")

        # [h1, h2, h3, h4] arp traffic should reach the LB
        print("Outside host must be able to send ARP requests to Load Balancer")
        self.tests.append("Outside host must be able to send ARP requests to Load Balancer")
        tmp1, tmp2, tmp3 = [], [], []
        for host in TestIDS.HOSTS:
           self._flush_std_out(host)
           print("\tARP [%s -> %s]" % (host, TestIDS.LOAD_BALANCER_IP)),
           tmp1.append("ARP [%s -> %s]" % (host, TestIDS.LOAD_BALANCER_IP))
           clear_arp_cache_cmd = 'sudo ip link set arp off dev {0}-eth0; sudo ip link set arp on dev {0}-eth0'.format(host)
           test_cmd = self._get_ping_cmd(TestIDS.LOAD_BALANCER_IP)
           tmp2.append(test_cmd)
           mininet_host = self.ctrl.get(host)
           mininet_host.cmd(clear_arp_cache_cmd)
           res = int(mininet_host.cmd(test_cmd))
           print ("\t\t%s" % ('PASS' if res == 0 else 'FAIL'))
           tmp3.append(self._PASS if res == 0 else self._FAIL)
        self.sub_tests.append(tmp1)
        self.commands.append(tmp2)
        self.status.append(tmp3)
        print ("\n")


        # [h1, h2, h3, h4] ping should reach LB
        print("Outside host must be able to reach Load Balancer through ping")
        self.tests.append("Outside host must be able to reach Load Balancer through ping")
        tmp1, tmp2, tmp3 = [], [], []
        for host in TestIDS.HOSTS:
            self._flush_std_out(host)
            print ("\tPing [{0} -> LB]".format(host)),
            tmp1.append("Ping [%s -> LB]" % host)
            test_cmd = self._get_ping_cmd(dst=TestIDS.LOAD_BALANCER_IP)
            tmp2.append(test_cmd)
            mininet_host = self.ctrl.get(host)
            res = int(mininet_host.cmd(test_cmd))
            print ("\t\t%s" % ('PASS' if res == 0 else 'FAIL'))
            tmp3.append(self._PASS if res == 0 else self._FAIL)
        self.sub_tests.append(tmp1)
        self.commands.append(tmp2)
        self.status.append(tmp3)
        print ("\n")

        
        # [h1, h2, h3, h4] ping should not be able to reach any webserver directly
        print("Outside host must NOT be able to reach any web server directly through ping")
        self.tests.append("Outside host must NOT be able to reach any web server directly through ping")
        tmp1, tmp2, tmp3 = [], [], []
        for host in TestIDS.HOSTS:
            for web_server in TestIDS.WEB_SERVERS:
                self._flush_std_out(host)
                print("\tPing [%s -> %s]" % (host, web_server)),
                tmp1.append("Ping [%s -> %s]" % (host, web_server))
                test_cmd = self._get_ping_cmd(dst=web_server)
                tmp2.append(test_cmd)
                mininet_host = self.ctrl.get(host)
                res = int(mininet_host.cmd(test_cmd))
                print ("\t\t%s" % ('PASS' if res != 0 else 'FAIL'))
                tmp3.append(self._PASS if res != 0 else self._FAIL)
        self.sub_tests.append(tmp1)
        self.commands.append(tmp2)
        self.status.append(tmp3)
        print ("\n")

    
        # [h1, h2, h3, h4] -> should reach LB with PUT and POST requests
        print("Hosts must be able to issue POST and PUT requests to LB")
        self.tests.append("Hosts must be able to issue POST and PUT requests to LB")
        tmp1, tmp2, tmp3 = [], [], []
        for host in TestIDS.HOSTS:
            for method in ["POST", "PUT"]:
                self._flush_std_out(host)
                print("\tHTTP %s [%s -> %s]" % (method, host, TestIDS.LOAD_BALANCER_IP)),
                tmp1.append("\tHTTP %s [%s -> %s]" % (method, host, TestIDS.LOAD_BALANCER_IP))
                restart_ws_cmd = self._restart_web_server("h2")                                                         #### restart all web servers here
                mininet_host = self.ctrl.get("h2")
                mininet_host.cmd(restart_ws_cmd)
                time.sleep(2)
                self._flush_std_out(host)
                http_req_cmd = self._get_http_request(web_server=TestIDS.LOAD_BALANCER_IP, method=method)
                tmp2.append(http_req_cmd)
                mininet_host = self.ctrl.get(host)
                res = mininet_host.cmd(http_req_cmd)
                res = self._PASS if "Unsupported method ('%s')"  % method.upper() in res else self._FAIL
                print ("\t\t%s" % ('PASS' if res == self._PASS else 'FAIL'))
                tmp3.append(res)
        self.sub_tests.append(tmp1)
        self.commands.append(tmp2)
        self.status.append(tmp3)
        print ("\n")

        
        # [h1, h2, h3, h4] -> should not reach reach LB with GET, DELETE, HEAD, OPTIONS, TRACE, CONNECT requests 
        print("Hosts must be able to issue GET, DELETE, HEAD, OPTIONS, TRACE, CONNECT requests to LB")
        self.tests.append("Hosts must be able to issue GET, DELETE, HEAD, OPTIONS, TRACE, CONNECT requests to LB")
        tmp1, tmp2, tmp3 = [], [], []
        for host in TestIDS.HOSTS:
            for method in ["GET", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT"]:
                self._flush_std_out(host)
                print("\tHTTP %s [%s -> %s]" % (method, host, TestIDS.LOAD_BALANCER_IP)),
                tmp1.append("\tHTTP %s [%s -> %s]" % (method, host, TestIDS.LOAD_BALANCER_IP))
                restart_ws_cmd = self._restart_web_server("h2")                                                         #### restart all web servers here
                mininet_host = self.ctrl.get("h2")
                mininet_host.cmd(restart_ws_cmd)
                time.sleep(2)
                self._flush_std_out(host)
                http_req_cmd = self._get_http_request(web_server=TestIDS.LOAD_BALANCER_IP, method=method)
                tmp2.append(http_req_cmd)
                mininet_host = self.ctrl.get(host)
                res = mininet_host.cmd(http_req_cmd)
                res = self._PASS if "Operation timed out" in res else self._FAIL
                print ("\t\t%s" % ('PASS' if res == self._PASS else 'FAIL'))
                tmp3.append(res)
        self.sub_tests.append(tmp1)
        self.commands.append(tmp2)
        self.status.append(tmp3)
        print ("\n")


        # [h1, h2, h3, h4] -> injection tests
        print("IDS must block SQL and LINUX Injection PUT requests")
        self.tests.append("IDS must block SQL and LINUX Injection PUT requests")
        tmp1, tmp2, tmp3 = [], [], []
        for host in TestIDS.HOSTS:
            for inj_req in ["cat /etc/passwd", "cat /var/log/", "INSERT", "UPDATE", "DELETE"]:
                self._flush_std_out(host)
                print("\tHTTP %s [%s -> %s] data='%s'" % ("PUT", host, TestIDS.LOAD_BALANCER_IP, inj_req)),
                tmp1.append("\tHTTP %s [%s -> %s] data='%s'" % ("PUT", host, TestIDS.LOAD_BALANCER_IP, inj_req))
                restart_ws_cmd = self._restart_web_server("h2")                                                         #### restart all web servers here
                mininet_host = self.ctrl.get("h2")
                mininet_host.cmd(restart_ws_cmd)
                time.sleep(2)
                self._flush_std_out(host)
                http_req_cmd = self._get_http_request(web_server=TestIDS.LOAD_BALANCER_IP, method="PUT", data=inj_req)
                tmp2.append(http_req_cmd)
                mininet_host = self.ctrl.get(host)
                res = mininet_host.cmd(http_req_cmd)
                res = self._PASS if "Operation timed out" in res else self._FAIL
                print ("\t\t%s" % ('PASS' if res == self._PASS else 'FAIL'))
                tmp3.append(res)
        self.sub_tests.append(tmp1)
        self.commands.append(tmp2)
        self.status.append(tmp3)
        print ("\n")


        # inspector packect count should not be empty
        print("Inspector packect count should not be empty")
        self.tests.append("Inspector packect count should not be empty")
        tmp1, tmp2, tmp3 = [], [], []
        self._flush_std_out(TestIDS.INSPECTER_HOST)
        print("\tChecking packet counts on %s for file %s" % (TestIDS.INSPECTER_HOST, "/opt/IDS.pcap")),
        tmp1.append("Checking packet counts on %s for file %s" % (TestIDS.INSPECTER_HOST, "/opt/IDS.pcap"))
        test_cmd = self._get_filesize_cmd(file="/opt/IDS.pcap")
        tmp2.append(test_cmd)
        mininet_host = self.ctrl.get(TestIDS.INSPECTER_HOST)
        res = mininet_host.cmd(test_cmd)
        res = self._PASS if not res.strip().startswith("0") else self._FAIL
        print ("\t\t%s" % ('PASS' if res == self._PASS else 'FAIL'))
        tmp3.append(res)
        self.sub_tests.append(tmp1)
        self.commands.append(tmp2)
        self.status.append(tmp3)
        print ("\n")


    def get_results(self):
        total_test = 0
        pass_test = 0
        summary = ""
        for i, test in enumerate(self.tests):
            summary += "[Test%s] %s\n" % (str(i), test)
            for j, subtest in enumerate(self.sub_tests[i]):
                if self.status[i][j] == self._PASS:
                    res = "SUCCEED!"
                    pass_test += 1 
                else:
                    res = "FAIL!"
                summary += "    %s --- %s\n" % (self.sub_tests[i][j], res)
                # summary += "    %s --- %s --- %s\n" % (self.sub_tests[i][j], self.commands[i][j], res)
                total_test += 1
            summary += "\n"
        return summary, total_test, pass_test    
