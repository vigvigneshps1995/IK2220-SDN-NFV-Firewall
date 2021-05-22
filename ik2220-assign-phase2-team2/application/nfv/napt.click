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

// Test ARP request and response Traffic
source_int -> count_in2
		 -> internal_class :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, -);
source_ext -> count_in1 
		 -> external_class :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, -);

// response to the routers external interface
external_class[1] -> arp_response_1 -> [1]arp :: ARPQuerier(DmZ);
external_class[0] -> arp_request_1 -> ARPResponder(DmZ) -> Print("ARP external interface") -> destin_ext_queue ;

// response to the routers internal interface
internal_class[1] -> arp_response_2 -> [1]in_arp :: ARPQuerier(PrZ);
internal_class[0] -> arp_request_2 -> ARPResponder(PrZ) -> Print("ARP internal interface") ->destin_int_queue ;

destin_ext_arp_queue :: GetIPAddress(16) -> CheckIPHeader -> [0]arp -> destin_ext_queue;
destin_in_arp_queue :: GetIPAddress(16) -> CheckIPHeader -> [0]in_arp -> destin_int_queue;

//Test IP traffic
external_class[2] -> ip_in ->  Strip(14) -> CheckIPHeader
	-> external_ipc :: IPClassifier(
		icmp && icmp type echo and dst $sw_ext_ip,
		dst $sw_ext_ip and (tcp or udp),
		proto icmp && icmp type echo-reply,
		-
	);

internal_class[2] -> ip_out -> Strip(14) -> CheckIPHeader
	-> internal_ipc :: IPClassifier(
		icmp && icmp type echo and dst $sw_int_ip, 
		tcp or udp,
		icmp && icmp type echo and dst != $sw_int_ip,
		-
		);

external_ipc[0] -> Print("ICMP FROM EXTERNAL->GW")
    -> ICMPPingResponder
    -> icmp_in1
    -> destin_ext_arp_queue ;

// send back pings to inside from inside
internal_ipc[0] -> Print("ICMP ECHO FROM INTERNAL -> INT")
	-> ICMPPingResponder
	-> icmp_out1
	-> destin_in_arp_queue;

//Ignore packets which not IP nor ARP  
external_class[3] -> Print("Other PACKET") -> drop1 -> Discard;
internal_class[3] -> Print("Other PACKET") -> drop2 -> Discard;

external_ipc[3] -> Print("Other PACKET") -> drop3 -> Discard;
internal_ipc[3] -> Print("Other PACKET") -> drop4 -> Discard;

ping_rw :: ICMPPingRewriter(pattern $sw_ext_ip - - - 0 1)

ping_rw[1] -> icmp_in2 ->  destin_in_arp_queue
ping_rw[0] -> icmp_out2 -> destin_ext_arp_queue

rw :: IPRewriter(pattern $sw_ext_ip 1024-65534 - - 0 1);

rw[1] -> SetTCPChecksum -> destin_in_arp_queue;
rw[0] -> SetTCPChecksum -> destin_ext_arp_queue;

internal_ipc[1] -> Print("IP Traffic from INT to EXT") -> [0]rw;
internal_ipc[2] -> Print("ICMP Traffic from INT to EXT") -> [0]ping_rw;

external_ipc[1] -> Print("IP Traffic from EXT to INT") -> [0]rw;
external_ipc[2] -> Print("ICMP Traffic from EXT to INT") -> [0]ping_rw;


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
