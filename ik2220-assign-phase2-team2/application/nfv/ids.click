define (
    $in_intf sw1-eth1,
    $out_intf sw1-eth2,
    $insp_intf sw1-eth3,
)


// counters
read_in_ctr, write_in_ctr, read_out_ctr, write_out_ctr, write_insp_ctr :: AverageCounter;
arp_request, arp_response :: Counter;
icmp_request, icmp_response :: Counter;
http_post_ctr, http_put_ctr, http_get_ctr, http_delete_ctr, http_head_ctr, http_trace_ctr, http_options_ctr, http_connect_ctr :: Counter;
injection_ctr:: Counter;
fw_drop_ctr, bw_drop_ctr :: Counter;


// interface and pipelines
read_input :: FromDevice($in_intf, METHOD LINUX);
write_input :: Queue -> write_in_ctr -> ToDevice($in_intf, METHOD LINUX);
read_output :: FromDevice($out_intf, METHOD LINUX);
write_output :: Queue -> write_out_ctr -> ToDevice($out_intf, METHOD LINUX);
write_insp :: Queue -> write_insp_ctr -> ToDevice($insp_intf, METHOD LINUX);
forward_drop_queue :: Queue -> fw_drop_ctr -> Discard;
backward_drop_queue :: Queue -> bw_drop_ctr -> Discard;
inject_drop_queue :: Queue -> injection_ctr -> Discard;


//forward pipeline
forward_classifier :: Classifier(12/0806 20/0001, 12/0800, -)       // [arp requests, ip packets]
forward_ip_classifier :: IPClassifier(proto icmp && icmp type echo, proto tcp && (syn || fin || rst || (ack && !psh)), -) //[ICMP, TCP, ALL]
forward_http_classifier :: Classifier(66/504F5354, 66/505554, 66/474554, 66/44454C455445, 66/48454144, 66/5452414345, 66/4F5054494F4E, 66/434F4E4E4543, -) // [POST, PUT, GET, DELETE, HEAD, TRACE, OPTIONS CONNECT]
put_injection_classifier :: Classifier(209/636174202F6574632F706173737764, 209/636174202F7661722F6C6F672F, 208/494E53455254, 208/555044415445, 208/44454C455445, -) // [cat /etc/passwd, cat /var/log, INSERT, UPDATE, DELETE, other]

read_input -> read_in_ctr -> forward_classifier;
forward_classifier[0] -> Print("[Forward]: Allowing ARP request", -1) -> arp_request -> write_output;
forward_classifier[1] -> Strip(14) -> CheckIPHeader -> forward_ip_classifier;  
forward_classifier[2] -> Print("[Forward]: Droping packet", -1) -> forward_drop_queue;

forward_ip_classifier[0] -> Unstrip(14) -> Print("[Forward]: Allowing ICMP echo request", -1) -> icmp_request -> write_output;
forward_ip_classifier[1] -> Unstrip(14) -> Print("[Forward]: TCP signalling", -1) -> write_output;
forward_ip_classifier[2] -> Unstrip(14) -> forward_http_classifier;

forward_http_classifier[0] -> Print("[Forward]: Allow HTTP POST request", -1) -> http_post_ctr -> write_output;
forward_http_classifier[1] -> put_injection_classifier;
forward_http_classifier[2] -> Print("[Forward]: Dropping HTTP GET request", -1) -> http_get_ctr -> write_insp;
forward_http_classifier[3] -> Print("[Forward]: Dropping HTTP DELETE request", -1) -> http_delete_ctr -> write_insp;
forward_http_classifier[4] -> Print("[Forward]: Dropping HTTP HEAD request", -1) -> http_head_ctr -> write_insp;
forward_http_classifier[5] -> Print("[Forward]: Dropping HTTP TRACE request", -1) -> http_trace_ctr -> write_insp;
forward_http_classifier[6] -> Print("[Forward]: Dropping HTTP OPTIONS request", -1) -> http_options_ctr -> write_insp;
forward_http_classifier[7] -> Print("[Forward]: Dropping HTTP CONNECT request", -1) -> http_connect_ctr -> write_insp;
forward_http_classifier[8] -> Print("[Forward]: Dropping unknown TCP traffic", -1) -> forward_drop_queue;

put_injection_classifier[0] -> Print("[Forward]: PUT Injection code - cat /etc/passwd detected. dropping", -1) -> inject_drop_queue;
put_injection_classifier[1] -> Print("[Forward]: PUT Injection code - cat /var/log/ detected. dropping", -1) -> inject_drop_queue;
put_injection_classifier[2] -> Print("[Forward]: PUT Injection code - INSERT detected. dropping", -1) -> inject_drop_queue;
put_injection_classifier[3] -> Print("[Forward]: PUT Injection code - UPDATE detected. dropping", -1) -> inject_drop_queue;
put_injection_classifier[4] -> Print("[Forward]: PUT Injection code - DELETE detected. dropping", -1) -> inject_drop_queue;
put_injection_classifier[5] -> Print("[Forward]: Allow HTTP PUT request", -1) -> http_put_ctr -> write_output;


//backward pipeline
backward_classifier :: Classifier(12/0806 20/0002, 12/0800, -);
backward_ip_classifier :: IPClassifier(proto icmp && icmp type echo-reply, proto tcp , -)

read_output -> read_out_ctr -> backward_classifier;
backward_classifier[0] -> Print("[Backward]: Allowing ARP response", -1) -> arp_response -> write_input;
backward_classifier[1] -> Strip(14) -> CheckIPHeader -> backward_ip_classifier; 
backward_classifier[2] -> Print("[Backward]: Droping packet", -1) -> backward_drop_queue;

backward_ip_classifier[0] -> Unstrip(14) -> Print("[Backward]: Allowing ICMP echo reply", -1) -> icmp_response -> write_input;
backward_ip_classifier[1] -> Unstrip(14) -> Print("[Backward]: TCP packet", -1) -> write_input;
backward_ip_classifier[2] -> Unstrip(14) -> Print("[Backward]: Dropping IP packet", -1) -> backward_drop_queue;


// Generate IDS report 
DriverManager(wait , print > ../../results/ids.report "
========================= IDS Report ===================

    Number of packets arriving at IDS input interface: $(read_in_ctr.count)
    Number of packets leaving at IDS input interface: $(write_in_ctr.count)
    Input Interface IN throughput: $(read_in_ctr.rate) Bps
    Input Interface OUT throughput: $(write_in_ctr.rate) Bps
    
    Number of packets arriving at IDS output interface: $(read_out_ctr.count)
    Number of packets leaving at IDS output interface: $(write_out_ctr.count)
    Output Interface IN throughput: $(read_out_ctr.rate) Bps
    Output Interface OUT throughput: $(write_out_ctr.rate) Bps

    Number of ARP Request: $(arp_request.count)
    Number of ARP Response: $(arp_response.count)

    Number of ICMP Echo Request: $(icmp_request.count)
    Number of ECMP Echo Response: $(icmp_response.count)

    HTTP Request Statistics:
        GET:        $(http_get_ctr.count)
        POST:       $(http_post_ctr.count)
        PUT:        $(http_put_ctr.count)
        DELETE:     $(http_delete_ctr.count)
        HEAD:       $(http_head_ctr.count)
        OPTIONS:    $(http_options_ctr.count)
        TRACE:      $(http_trace_ctr.count)
        CONNECT:    $(http_connect_ctr.count)

    Number of SQL/Linux Injection packects: $(injection_ctr.count)

    Number of forward dropped packets: $(add $(fw_drop_ctr.count) $(injection_ctr.count))
    Number of backward dropped packets: $(bw_drop_ctr.count)

    Number of packets forwarded to inspector: $(write_insp_ctr.count)

=======================================================
" , stop);
