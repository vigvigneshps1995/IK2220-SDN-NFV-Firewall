define ($sw_int_ip 10.0.0.1,
		$sw_ext_ip 100.0.0.1,
		)

AddressInfo(
	DmZ		$sw_ext_ip $ext_if,
	PrZ		$sw_int_ip $int_if,
);

//Set up


//init count number
//total input && output packets
count_in1, count_in2, count_out1, count_out2 :: AverageCounter;

//dropped packets
drop1, drop2, drop3, drop4 :: Counter;

//IP, ICMP, ARP packets
ip_in, icmp_in1, icmp_in2, arp_request_1, arp_response_1 :: Counter;
ip_out, icmp_out1, icmp_out2, arp_request_2, arp_response_2 :: Counter;

//init interfaces 
destin_ext	:: ToDevice($ext_if, METHOD LINUX);
destin_int  :: ToDevice($int_if, METHOD LINUX);
source_ext  :: FromDevice($ext_if, METHOD LINUX, SNIFFER false);
source_int  :: FromDevice($int_if, METHOD LINUX, SNIFFER false);

// outgoing traffic queue init
destin_ext_queue :: Queue(1024) -> count_out1 -> destin_ext;
destin_int_queue :: Queue(1024) -> count_out2 -> destin_int;


//Test


// ARP request sent to output 0
// ARP response sent to output 1
// IP packets to output 2
// All others to output 3

// Test ARPR, ARR , IP Classifiers
source_ext -> count_in1 
		 -> external_class :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, -);
source_int -> count_in2
		 -> internal_class :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, -);

// response to the routers external interface

external_class[0] -> arp_request_1 -> ARPResponder(DmZ) -> Print("ARP external interface") -> destin_ext_queue ;
external_class[1] -> arp_response_1 -> [1]arp :: ARPQuerier(DmZ);

// response to the routers internal interface
internal_class[0] -> arp_request_2 -> ARPResponder(PrZ) -> Print("ARP internal interface") ->destin_int_queue ;
internal_class[1] -> arp_response_2 -> [1]in_arp :: ARPQuerier(PrZ);


destin_ext_arp_queue :: GetIPAddress(16) -> CheckIPHeader -> [0]arp -> destin_ext_queue;
to_in_arp_queue :: GetIPAddress(16) -> CheckIPHeader -> [0]in_arp -> destin_int_queue;

// Classifying IP traffic
external_class[2] -> ip_in ->  Strip(14) -> CheckIPHeader
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

internal_class[2] -> ip_out -> Strip(14) -> CheckIPHeader
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
    -> icmp_in1
    -> destin_ext_arp_queue ;

// send back pings to inside from inside
int_ipc[0] -> Print("ICMP ECHO FROM INT -> INT")
	-> ICMPPingResponder
	-> icmp_out1
	-> to_in_arp_queue;

//Discard non-IP, non-ARP packets 
external_class[3] -> Print("DISCARDING NON IP PACKET") -> drop1 -> Discard;
internal_class[3] -> Print("DISCARDING NON IP PACKET") -> drop2 -> Discard;

ext_ipc[3] -> Print("DISCARDING UNWANTED IP PACKET") -> drop3 -> Discard;
int_ipc[3] -> Print("DISCARDING UNWANTED IP PACKET") -> drop4 -> Discard;

ping_rw :: ICMPPingRewriter(pattern $sw_ext_ip - - - 0 1)

ping_rw[1] -> icmp_in2 ->  to_in_arp_queue
ping_rw[0] -> icmp_out2 -> destin_ext_arp_queue

rw :: IPRewriter(pattern $sw_ext_ip 1024-65534 - - 0 1);

rw[1] -> SetTCPChecksum -> to_in_arp_queue;
rw[0] -> SetTCPChecksum -> destin_ext_arp_queue;

// FROM INTERNAL

int_ipc[1] -> Print("IP Traffic from INT to EXT") -> [0]rw;
int_ipc[2] -> Print("ICMP Traffic from INT to EXT") -> [0]ping_rw;

// FROM EXTERNAL

ext_ipc[1] -> Print("IP Traffic from EXT to INT") -> [0]rw;
ext_ipc[2] -> Print("ICMP Traffic from EXT to INT") -> [0]ping_rw;



// output the result of counter as report napt.counter
DriverManager(wait , print > ../../results/napt.counter  "
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
