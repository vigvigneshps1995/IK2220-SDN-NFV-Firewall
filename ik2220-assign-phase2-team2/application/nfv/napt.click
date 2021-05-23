AddressInfo(
	DmZ		100.0.0.1 $ext_if,
	PrZ		10.0.0.1 $int_if,
);


//initialize parameters
icmp_rw :: ICMPPingRewriter(pattern $sw_ext_ip - - - 0 1);
icmp_rw[1] -> icmp_in2 ->  destin_in_arp_queue;
icmp_rw[0] -> icmp_out2 -> destin_ext_arp_queue;

tcp_rw :: IPRewriter(pattern $sw_ext_ip 1024-65534 - - 0 1);
tcp_rw[1] -> SetTCPChecksum -> destin_in_arp_queue;
tcp_rw[0] -> SetTCPChecksum -> destin_ext_arp_queue;


// ARP request sent to output 0
// ARP response sent to output 1
// IP packets to output 2
// All others to output 3

// ARP and  MACHINERY
FromDevice($ext_if, METHOD LINUX, SNIFFER false) -> count_in1 -> c :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, -);
    destin_ext_queue :: Queue() -> count_out1 :: AverageCounter -> ToDevice($ext_if, METHOD LINUX);
    
    c[0] -> arp_request_1 :: Counter -> ARPResponder(DmZ) -> Print("ARP external interface",-1) -> destin_ext_queue;
    c[1] -> arp_response_1 :: Counter -> ARPQuerier(DmZ) -> [1]arp1  :: ARPQuerier(DmZ);
    destin_ext_arp_queue :: GetIPAddress(16) -> CheckIPHeader -> [0]arp1 -> destin_ext_queue;
    
    c[2] -> ip_in :: Counter ->  Strip(14) -> CheckIPHeader -> external_ipc :: IPClassifier(
		icmp && icmp type echo and dst $sw_ext_ip,
		dst $sw_ext_ip and (tcp or udp),
		proto icmp && icmp type echo-reply,
		-
	);
    external_ipc[0] -> Print("ICMP FROM EXTERNAL->GW",-1) -> ICMPPingResponder -> icmp_in1 :: Counter -> destin_ext_arp_queue;
    external_ipc[1] -> Print("IP Traffic from EXT to INT",-1) -> [0]tcp_rw;
    external_ipc[2] -> Print("ICMP Traffic from EXT to INT",-1) -> [0]icmp_rw;
    external_ipc[3] -> Print("Other PACKET",-1) -> drop1 :: Counter -> Discard;
    
    c[3] -> Print("Other PACKET",-1) -> drop2 :: Counter -> Discard;


FromDevice($int_if, METHOD LINUX, SNIFFER false) -> count_in2 -> d :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, -);
    destin_int_queue :: Queue() -> count_out1 :: AverageCounter -> ToDevice($ext_if, METHOD LINUX);

    d[0] -> arp_request_2 :: Counter -> ARPResponder(PrZ) -> Print("ARP internal interface",-1) -> destin_int_queue;
    d[1] -> arp_response_2 :: Counter -> ARPQuerier(PrZ) -> [1]arp2  :: ARPQuerier(PrZ);
    destin_int_arp_queue :: GetIPAddress(16) -> CheckIPHeader -> [0]arp2 -> destin_int_queue;
    
    d[2] -> ip_out :: Counter ->  Strip(14) -> CheckIPHeader -> internal_ipc :: IPClassifier(
		icmp && icmp type echo and dst $sw_ext_ip,
		dst $sw_ext_ip and (tcp or udp),
		proto icmp && icmp type echo-reply,
		-
	);
    internal_ipc[0] -> Print("ICMP FROM INTERNAL->INT",-1) -> ICMPPingResponder -> icmp_out1 :: Counter -> destin_in_arp_queue;
    internal_ipc[1] -> Print("IP Traffic from EXT to INT",-1) -> [0]tcp_rw;
    internal_ipc[2] -> Print("ICMP Traffic from EXT to INT",-1) -> [0]icmp_rw;
    internal_ipc[3] -> Print("Other PACKET",-1) -> drop3 :: Counter -> Discard;
    
    d[3] -> Print("Other PACKET",-1) -> drop4 :: Counter -> Discard;

// output the result of counter as report napt.report
DriverManager(wait , print > ../../results/napt.report  "
	=================== NAPT Report ===================
	Input Packet Rate (pps): $(add $(count_in1.rate) $(count_in2.rate))
	Output Packet Rate(pps): $(add $(count_out1.rate) $(count_out2.rate))
	Total # of input packets: $(add $(count_in1.count) $(count_in2.count))
	Total # of output packets: $(add $(count_out1.count) $(count_out2.count))
	Total # of dropped packets: $(add $(drop1.count) $(drop2.count) $(drop3.count) $(drop4.count))
	
	Total # of service requests packets: $(add $(ip_in.count) $(ip_out.count))
	Total # of ICMP packets: $(add $(icmp_in1.count) $(icmp_out1.count) $(icmp_in2.count) $(icmp_out2.count))
	
	Total # of ARP requests packets: $(add $(arp_request_1.count) $(arp_request_2.count))
	Total # of ARP responses packets: $(add $(arp_response_1.count) $(arp_response_2.count))
	==================================================
" , stop);
