
counter_in1, counter_in2, counter_out1, counter_out2 :: AverageCounter;
arp_req1, arp_res1, icmp1, ip1 :: Counter;
arp_req2, arp_res2, icmp2, ip2, icmp3 :: Counter;
to_drop1, to_drop2, to_drop3, to_drop4 :: Counter;

//interfaces
from_ext  :: FromDevice($out_if, METHOD LINUX, SNIFFER false);
from_int  :: FromDevice($in_if, METHOD LINUX, SNIFFER false);
to_ext	:: ToDevice($out_if, METHOD LINUX);
to_int  :: ToDevice($in_if, METHOD LINUX);

// QUEUES
to_out_queue :: Queue(1024) -> Print("Send To EXT", -1) -> counter_out1 -> to_ext;
to_in_queue :: Queue(1024) -> Print("Send To INT", -1) -> counter_out2 -> to_int;



//Classifiers
from_ext -> Print("Recieve from EXT", -1) -> counter_in1 
		 -> out_cl :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, -);
from_int -> Print("Recieve from INT", -1) -> counter_in2
		 -> in_cl :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, -);


//outside ARP response

out_cl[0] -> arp_req1 -> ARPResponder($sw_ip $out_if) -> to_out_queue ;
out_cl[1] -> arp_res1 -> [1]arp :: ARPQuerier($sw_ip, $out_if);

//inside ARP response
in_cl[0] -> arp_req2 -> ARPResponder($sw_ip $in_if) -> to_in_queue ;
in_cl[1] -> arp_res2 -> [1]in_arp :: ARPQuerier($sw_ip, $in_if);


to_out_arp_queue :: GetIPAddress(16) -> CheckIPHeader -> [0]arp -> to_out_queue;
to_in_arp_queue :: GetIPAddress(16) -> CheckIPHeader -> [0]in_arp -> to_in_queue;

//IP classifier
out_cl[2] -> ip1 -> Strip(14) -> CheckIPHeader
	-> out_ipcl :: IPClassifier(
	// ping from out to gateway
		icmp && icmp type echo and dst $sw_ip,
	// ping from out to server
		icmp && icmp type echo and (dst $s1 or dst $s2 or dst $s3),
	// tcp form out to loadbalancer
		dst $sw_ip and $proto port $port,
	// ping response
		proto icmp && icmp type echo-reply,
	// others
		-
	);

in_cl[2] -> ip2 -> Strip(14) -> CheckIPHeader
	-> in_ipcl :: IPClassifier(
	// internal ping
		icmp && icmp type echo and dst $sw_ip, 
	// from in to out
		$proto,
	// rewrite pings
		icmp && icmp type echo and dst != $sw_ip,
	// others
		-
		);


// response pings to outside

out_ipcl[0] -> Print("ICMP ECHO FROM EXT->GW")
	-> icmp3
    -> ICMPPingResponder
    -> to_out_arp_queue ;

// send error to outside
out_ipcl[1] -> Print("ICMP ECHO FROM EXT-> IN")
    -> ICMPError($sw_ip, 3, 1 ) //host - unreachable
    -> icmp1
    -> to_out_arp_queue ;

// send back pings to inside from inside
in_ipcl[0] -> Print("ICMP ECHO FROM INT -> INT")
	-> ICMPPingResponder
	-> icmp2
	-> to_in_arp_queue;

//Discard
out_cl[3] -> Print("DISCARDING NON IP PACKET") -> to_drop1 -> Discard;
in_cl[3] -> Print("DISCARDING NON IP PACKET") -> to_drop2 -> Discard;

out_ipcl[4] -> Print("DISCARDING UNWANTED IP PACKET") -> to_drop3 -> Discard;
in_ipcl[3] -> Print("DISCARDING UNWANTED IP PACKET") -> to_drop4 -> Discard;
 
ping_rw :: ICMPPingRewriter(pattern $sw_ip 1025-65535# - - 0 1)

ping_rw[1] 	-> to_in_arp_queue
ping_rw[0] ->  to_out_arp_queue

rr :: RoundRobinIPMapper( $sw_ip - $s1 - 0 1,
						  $sw_ip - $s2 - 0 1,
						  $sw_ip - $s3 - 0 1
						)

rw :: IPRewriter(rr);


rw[0] -> SetTCPChecksum -> to_in_arp_queue;
rw[1] -> SetTCPChecksum -> to_out_arp_queue;

// FROM EXTERNAL

out_ipcl[2] -> Print("IP from EXT to INT", -1) -> [0]rw;
out_ipcl[3] -> Print("ICMP from EXT to INT") -> [0]ping_rw;

// FROM INTERNAL

in_ipcl[1] -> Print("IP from INT to EXT", -1) -> [0]rw;
in_ipcl[2] -> Print("ICMP from INT to EXT") -> [0]ping_rw;


// report
DriverManager(wait , print > ../../results/lb$lb.counter  "
	=================== LB $lb Report ===================
	Input Packet Rate (pps): $(add $(counter_in1.rate) $(counter_in2.rate))
	Output Packet Rate(pps): $(add $(counter_out1.rate) $(counter_out2.rate))

	Total # of ARP requests packets: $(add $(arp_req1.count) $(arp_req2.count))
	Total # of ARP responses packets: $(add $(arp_res1.count) $(arp_res2.count))
	Total # of service requests packets: $(add $(ip1.count) $(ip2.count))
	Total # of ICMP packets: $(add $(icmp1.count) $(icmp2.count) $(icmp3.count))

	Total # of input packets: $(add $(counter_in1.count) $(counter_in2.count))
	Total # of output packets: $(add $(counter_out1.count) $(counter_out2.count))
	Total # of dropped packets: $(add $(to_drop1.count) $(to_drop2.count) $(to_drop3.count) $(to_drop4.count) )
	==================================================
" , stop);
