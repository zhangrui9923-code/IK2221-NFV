// 2 variables to hold ports names
define($PORT1 napt-eth1, $PORT2 napt-eth2)
// (My Code) Interfaces Declaration
        define($NAPT_IP1 10.0.0.1)
        define($NAPT_IP2 100.0.0.1)
        AddressInfo(
            user_zone $NAPT_IP1 $PORT1,
            infr_zone $NAPT_IP2 $PORT2
        )

//require(library ./forwarder.click)
//Forwarder($PORT1, $PORT2, $VERBOSE)
// Script will run as soon as the router starts
Script(print "Click forwarder on $PORT1 $PORT2")

// (My Code) Not Using Element Class Style
        // // Group common elements in a single block. $port is a parameter used just to print
        // elementclass L2Forwarder {$port|
        // 	input
        // 	->cnt::Counter
        //         ->Print
        // 	->Queue
        // 	->output
        // }

// (My Code) Initialize Scheduler Element
    // Exit Scheduler
        to_port1::RoundRobinSched
        to_port2::RoundRobinSched
    // ARP Query Scheduler
        to_aq1::RoundRobinSched
        to_aq2::RoundRobinSched

// From where to pick packets
fd1::FromDevice($PORT1, SNIFFER false, METHOD LINUX, PROMISC true)
fd2::FromDevice($PORT2, SNIFFER false, METHOD LINUX, PROMISC true)
// Instantiate 2 forwarders, 1 per directions
// (My Code) Unused
        // fd1->fwd1::L2Forwarder($PORT1)->td2
        // fd2->fwd2::L2Forwarder($PORT2)->td1

// (My Code) Layer 2 Functions
// (My Code) Declare/Create Classifier Element and Feed FromDevice element to Classifier
        c1::Classifier(
            12/0806 20/0001,    // ARP Request
            12/0806 20/0002,    // ARP Reply
            12/0800,            // IPv4 Packet
            -                   // Everything Else
        )
        c2::Classifier(
            12/0806 20/0001,    // ARP Request
            12/0806 20/0002,    // ARP Reply
            12/0800,            // IPv4 Packet
            -                   // Everything Else
        )
        fd1 -> in_userzone_ctr_avg::AverageCounter -> c1
        fd2 -> in_infrzone_ctr_avg::AverageCounter -> c2
// (My Code) (Func 0) Respond to ARP Request ARPResponder Element
        arp1::ARPResponder(user_zone)
        arp2::ARPResponder(infr_zone)
        c1[0] -> class_arp_req_user_ctr::Counter -> Print("Received ARP Req on User Zone") -> arp1 -> Queue -> [0]to_port1
        c2[0] -> class_arp_req_infr_ctr::Counter -> Print("Received ARP Req on Infr Zone") -> arp2 -> Queue -> [0]to_port2

// (My Code) (Func 1)  Handle ARP replies and send packets after ARP resolution
        aq1::ARPQuerier(user_zone)
        aq2::ARPQuerier(infr_zone)
        c1[1] -> [1]aq1
        c2[1] -> [1]aq2
        aq1[0] -> Queue -> [1]to_port1
        aq1[1] -> Queue -> [2]to_port1
        aq2[0] -> Queue -> [1]to_port2
        aq2[1] -> Queue -> [2]to_port2

// (My Code) Layer 3 Functions
// (My Code) (Func 2) Ping and NAT Function
    // Check If the Packet is Destined to NAPT and it is PING Packet
        c1[2] -> class_ipv4_user_ctr::Counter -> CheckIPHeader(14) -> ip_to_me1::IPClassifier(dst host $NAPT_IP1 and icmp type echo, -)
        c2[2] -> class_ipv4_infr_ctr::Counter -> CheckIPHeader(14) -> ip_to_me2::IPClassifier(dst host $NAPT_IP2 and icmp type echo, -)
    // If yes respond the PING
        ip_to_me1[0] -> Print("Received PING on User Port") -> ICMPPingResponder -> EtherMirror -> Queue -> [3]to_port1
        ip_to_me2[0] -> Print("Received PING on Infr Port") -> ICMPPingResponder -> EtherMirror -> Queue -> [3]to_port2
    // Else
        // Check IP Packet
        ip_to_me1[1] -> Strip(14) -> CheckIPHeader -> from_user_ip::IPClassifier(
            src net 10.0.0.0/24 and icmp type echo,
            src net 10.0.0.0/24 and tcp,
            -
        )
        ip_to_me2[1] -> Strip(14) -> CheckIPHeader -> from_infr_ip::IPClassifier(
            dst host $NAPT_IP2 and icmp type echo-reply,
            dst host $NAPT_IP2 and tcp,
            -
        )
        // NAT Element
        icmp_rw::ICMPPingRewriter(
            pattern $NAPT_IP2 1024-65535 - - 0 1,
            drop
        )
        tcp_rw::IPRewriter(
            pattern $NAPT_IP2 1024-65535 - - 0 1,
            drop
        )
        // If it is ICMP, perform ICMP NAT
            from_user_ip[0] -> Print("ICMP Outbound User to Infr") -> [0]icmp_rw
            // New packet will be dropped by Rewriter 2nd rule
            from_infr_ip[0] -> Print("ICMP Inbound Infr to User") -> [1]icmp_rw   
            icmp_rw[0] -> Queue -> [0]to_aq2
            icmp_rw[1] -> Queue -> [0]to_aq1
        // If it is TCP, perform IP NAT
            from_user_ip[1] -> Print("TCP Outbound User to Infr") -> [0]tcp_rw
            // New packet will be dropped by Rewriter 2nd rule
            from_infr_ip[1] -> Print("TCP Inbound Infr to User") -> [1]tcp_rw
            tcp_rw[0] -> cnt_napt_fwd::Counter -> Queue -> [1]to_aq2
            tcp_rw[1] -> cnt_napt_rev::Counter -> Queue -> [1]to_aq1
        // Else Discard
            from_user_ip[2] -> Discard
            from_infr_ip[2] -> Discard
    // ARPQuerier resolves destination MAC and rebuilds the Ethernet header
        to_aq2 -> Unqueue -> aq2
        to_aq1 -> Unqueue -> aq1

// Where to send packets
td1::ToDevice($PORT1, METHOD LINUX)
td2::ToDevice($PORT2, METHOD LINUX)
// (My Code) Exit Part 
        to_port1 -> out_userzone_ctr_avg::AverageCounter -> td1
        to_port2 -> out_infrzone_ctr_avg::AverageCounter -> td2

// (My Code) (Func 3) Else Discard Everything
        c1[3] -> Discard
        c2[3] -> Discard

// Print something on exit
// DriverManager will listen on router's events
// The pause instruction will wait until the process terminates
// Then the prints will run an Click will exit
DriverManager(
    print "Router starting",
    pause,
// (My Code) Report
        print >napt.report  "=================== NAPT Report ===================",
        print >>napt.report "Input rate  int (pps):  $(in_userzone_ctr_avg.rate)",
        print >>napt.report "Input rate  ext (pps):  $(in_infrzone_ctr_avg.rate)",
        print >>napt.report "Output rate int (pps):  $(out_userzone_ctr_avg.rate)",
        print >>napt.report "Output rate ext (pps):  $(out_infrzone_ctr_avg.rate)",
        print >>napt.report "Internal ARP requests:  $(class_arp_req_user_ctr.count)",
        print >>napt.report "External ARP requests:  $(class_arp_req_infr_ctr.count)",
        print >>napt.report "Internal IP packets:    $(class_ipv4_user_ctr.count)",
        print >>napt.report "External IP packets:    $(class_ipv4_infr_ctr.count)",
        print >>napt.report "NAPT forwarded:         $(cnt_napt_fwd.count)",
        print >>napt.report "NAPT reversed:          $(cnt_napt_rev.count)",
        print >>napt.report "===================================================",
        print "Router stopping"
)
