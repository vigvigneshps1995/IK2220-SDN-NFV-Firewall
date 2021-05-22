define ($sw_int_ip 10.0.0.1,
		$sw_ext_ip 100.0.0.1,
		)

AddressInfo(
	DmZ		$sw_ext_ip $ext_if,
	PrZ		$sw_int_ip $int_if,
);


//init counter 
//1 means in && 2 means out

counter_in1, counter_in2, counter_out1, counter_out2 :: AverageCounter;
drop1, drop2, drop3, drop4 :: Counter;
arp_request1, arp_response1, icmp1,icmp3, ip1 :: Counter;
arp_request2, arp_response2, icmp2,icmp4, ip2 :: Counter;


//init interfaces 
destin_ext	:: ToDevice($ext_if, METHOD LINUX);
destin_int  :: ToDevice($int_if, METHOD LINUX);
source_ext  :: FromDevice($ext_if, METHOD LINUX, SNIFFER false);
source_int  :: FromDevice($int_if, METHOD LINUX, SNIFFER false);


// outgoing traffic queue init
destin_ext_queue :: Queue(1024) -> counter_out1 -> destin_ext;
destin_int_queue :: Queue(1024) -> counter_out2 -> destin_int;


//ARP

// 12/0806 20/0001 ARP request
// 12/0806 20/0002 ARP response
// 12/0800 IP traffic

// ARPR, ARR , IP Classifiers
source_ext -> counter_in1 
		 -> ext_cl :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, -);
source_int -> counter_in2
		 -> in_cl :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, -);

// respond to ARP queries  for the router external interface

ext_cl[0] -> arp_request1 -> ARPResponder(DmZ) -> Print("ARP_R_ext") -> destin_ext_queue ;
ext_cl[1] -> arp_response1 -> [1]arp :: ARPQuerier(DmZ);

// respond to ARP queries for the router internal interface
in_cl[0] -> arp_request2 -> ARPResponder(PrZ) -> Print("ARP_R_int") ->destin_int_queue ;
in_cl[1] -> arp_response2 -> [1]in_arp :: ARPQuerier(PrZ);


destin_ext_arp_queue :: GetIPAddress(16) -> CheckIPHeader -> [0]arp -> destin_ext_queue;
to_in_arp_queue :: GetIPAddress(16) -> CheckIPHeader -> [0]in_arp -> destin_int_queue;

// Classifying IP traffic
ext_cl[2] -> ip1 ->  Strip(14) -> CheckIPHeader
	-> ext_ipc :: IPClassifier(
	// ping from out to gw
		icmp && icmp type echo and dst $sw_ext_ip,
	// tcp udp traffic  from ext to inside
		dst $sw_ext_ip and (tcp or udp),
	// ping resp to rewrited ping
		proto icmp && icmp type echo-reply,
	// others
		-
	);

in_cl[2] -> ip2 -> Strip(14) -> CheckIPHeader
	-> int_ipc :: IPClassifier(
	// ping from in to gw
		icmp && icmp type echo and dst $sw_int_ip, 
	// tcp udp from int to ext
		tcp or udp,
	// pings req to rewrite
		icmp && icmp type echo and dst != $sw_int_ip,
	// others
		-
		);

// PING BACK
// send back pings gw to outside
ext_ipc[0] -> Print("ICMP ECHO FROM EXT->GW")
    -> ICMPPingResponder
    -> icmp1
    -> destin_ext_arp_queue ;

// send back pings to inside from inside
int_ipc[0] -> Print("ICMP ECHO FROM INT -> INT")
	-> ICMPPingResponder
	-> icmp2
	-> to_in_arp_queue;

//Discard non-IP, non-ARP packets 
ext_cl[3] -> Print("DISCARDING NON IP PACKET") -> drop1 -> Discard;
in_cl[3] -> Print("DISCARDING NON IP PACKET") -> drop2 -> Discard;

ext_ipc[3] -> Print("DISCARDING UNWANTED IP PACKET") -> drop3 -> Discard;
int_ipc[3] -> Print("DISCARDING UNWANTED IP PACKET") -> drop4 -> Discard;

ping_rw :: ICMPPingRewriter(pattern $sw_ext_ip - - - 0 1)

ping_rw[1] -> icmp3 ->  to_in_arp_queue
ping_rw[0] -> icmp4 -> destin_ext_arp_queue

rw :: IPRewriter(pattern $sw_ext_ip 1024-65534 - - 0 1);

rw[1] -> SetTCPChecksum -> to_in_arp_queue;
rw[0] -> SetTCPChecksum -> destin_ext_arp_queue;

// FROM INTERNAL

int_ipc[1] -> Print("IP from INT to EXT") -> [0]rw;
int_ipc[2] -> Print("ICMP from INT to EXT") -> [0]ping_rw;

// FROM EXTERNAL

ext_ipc[1] -> Print("IP from EXT to INT") -> [0]rw;
ext_ipc[2] -> Print("ICMP from EXT to INT") -> [0]ping_rw;



// output the result of counter as report
DriverManager(wait , print > ../../results/nat.counter  "
	=================== NAPT Report ===================
	Input Packet Rate (pps): $(add $(counter_in1.rate) $(counter_in2.rate))
	Output Packet Rate(pps): $(add $(counter_out1.rate) $(counter_out2.rate))
	Total # of input packets: $(add $(counter_in1.count) $(counter_in2.count))
	Total # of output packets: $(add $(counter_out1.count) $(counter_out2.count))
	Total # of dropped packets: $(add $(drop1.count) $(drop2.count) $(drop3.count) $(drop4.count))
	
	Total # of service requests packets: $(add $(ip1.count) $(ip2.count))
	Total # of ICMP packets: $(add $(icmp1.count) $(icmp2.count) $(icmp3.count) $(icmp4.count))
	
	Total # of ARP requests packets: $(add $(arp_request1.count) $(arp_request2.count))
	Total # of ARP responses packets: $(add $(arp_response1.count) $(arp_response2.count))
	==================================================
" , stop);
