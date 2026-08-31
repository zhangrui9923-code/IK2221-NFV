// =============================================================================
// IK2221 - Phase 1: Load Balancer (lb1.click)
//
// Interfaces:
//   PORT1 (lb1-eth1) — client-facing (towards s2/IDS)
//   PORT2 (lb1-eth2) — server-facing (towards s3/LLM cluster)
//
// Virtual service: IP 100.0.0.45, MAC 00:00:00:00:00:45 (VIP/VMAC)
// Backend servers: llm1=100.0.0.40, llm2=100.0.0.41, llm3=100.0.0.42
//
// Behaviour:
//   - ARP for VIP answered on client side with VMAC
//   - ICMP echo to VIP answered locally (ICMPPingResponder)
//   - TCP:80 to VIP load-balanced round-robin across llm1-3 (IPRewriter + mapper)
//   - Server-side proxy ARP: respond to ARP for 100.0.0.1 (NAPT) and VIP with VMAC
//     so that LLM response packets are intercepted and reverse-NATed by IPRewriter
//   - Everything else is dropped
// =============================================================================

// Interface and constant definitions
define($PORT1 lb1-eth1, $PORT2 lb1-eth2)
define($VIP 100.0.0.45)
define($VMAC 00:00:00:00:00:45)
define($LLM1 100.0.0.40, $LLM2 100.0.0.41, $LLM3 100.0.0.42)

// Throughput counters (AverageCounter required by spec: after FromDevice, before ToDevice)
in_avg_cnt1, in_avg_cnt2   :: AverageCounter;
out_avg_cnt1, out_avg_cnt2 :: AverageCounter;

// Per-class packet counters
arp_req_cnt1, arp_req_cnt2 :: Counter;
arp_res_cnt1, arp_res_cnt2 :: Counter;
service_cnt, icmp_cnt, dropped_cnt :: Counter;
in_pkt_cnt1,  in_pkt_cnt2  :: Counter;
out_pkt_cnt1, out_pkt_cnt2 :: Counter;
// Counter for llm1/2/3
cnt_to_llm1, cnt_to_llm2, cnt_to_llm3 :: Counter;


// Devices
fd1 :: FromDevice($PORT1, SNIFFER false, METHOD LINUX, PROMISC true);
fd2 :: FromDevice($PORT2, SNIFFER false, METHOD LINUX, PROMISC true);
td1 :: ToDevice($PORT1, METHOD LINUX);
td2 :: ToDevice($PORT2, METHOD LINUX);

// Output queues and ARP queriers
// Both queriers advertise VIP/VMAC so lb1 appears as the virtual service on both sides
arp_q1 :: ARPQuerier($VIP, $VMAC);
arp_q2 :: ARPQuerier($VIP, $VMAC);

out_q1 :: Queue -> out_avg_cnt1 -> out_pkt_cnt1 -> td1;
out_q2 :: Queue -> out_avg_cnt2 -> out_pkt_cnt2 -> td2;

// Ethernet-level classifier
class1, class2 :: Classifier(
    12/0806 20/0001, // [0] ARP request
    12/0806 20/0002, // [1] ARP reply
    12/0800,         // [2] IP
    -                // [3] other (drop)
);

// Used to route ARP replies from the client side to the correct destination

arp_reply_to_server :: Classifier(38/64000028, 38/64000029, 38/6400002a, -);

// Load balancing: RoundRobinIPMapper cycles through the three backends per new "flow",
lb_mapper :: RoundRobinIPMapper(
    - - $LLM1 80 0 1,
    - - $LLM2 80 0 1,
    - - $LLM3 80 0 1
);

// Single IPRewriter instance driven by lb_mapper

rw :: IPRewriter(lb_mapper, drop);

ping_res :: ICMPPingResponder;

// =============================================================================
// Pipeline
// ========================================================================

// --- Client-facing (eth1) ---
fd1 -> in_avg_cnt1 -> in_pkt_cnt1 -> class1;

// ARP filter: requests for VIP are answered here; others (for LLM IPs) pass to server side
arp_filter1 :: Classifier(38/6400 40/002d, -); // target IP = 100.0.0.45
class1[0] -> arp_req_cnt1 -> arp_filter1;
    arp_filter1[0] -> ARPResponder($VIP $VMAC) -> out_q1; // VIP: reply with VMAC
    arp_filter1[1] -> out_q2;                             // other: forward to server side

// ARP replies from the client side: route to the right querier
class1[1] -> arp_res_cnt1 -> arp_reply_to_server;
    arp_reply_to_server[0] -> out_q2; // reply target is .40 — forward to server side
    arp_reply_to_server[1] -> out_q2; // reply target is .41
    arp_reply_to_server[2] -> out_q2; // reply target is .42
    arp_reply_to_server[3] -> [1]arp_q1; // reply target is VIP — feed into arp_q1

// IP traffic from client side
class1[2] -> Strip(14) -> CheckIPHeader -> ip_class1 :: IPClassifier(
    icmp echo and dst host $VIP,        // [0] ping to VIP → answer locally
    tcp dst port 80 and dst host $VIP,  // [1] HTTP to VIP → load-balance
    -                                   // [2] anything else → drop (spec: "rest must be blocked")
);

ip_class1[0] -> icmp_cnt -> ping_res -> arp_q1 -> out_q1;
ip_class1[1] -> service_cnt -> [0]rw;
ip_class1[2] -> dropped_cnt;

// --- Server-facing (eth2) ---
fd2 -> in_avg_cnt2 -> in_pkt_cnt2 -> class2;

// Proxy ARP on the server side: lb1 claims to own both 100.0.0.1 (NAPT public IP) and VIP.
// This ensures LLM response packets are sent to VMAC (lb1), where IPRewriter can
// rewrite the source back to VIP before forwarding to the client.
class2[0] -> arp_req_cnt2 -> ARPResponder(100.0.0.1 $VMAC, $VIP $VMAC) -> out_q2;

// ARP replies from the server side go into arp_q2 to resolve backend MACs
class2[1] -> arp_res_cnt2 -> [1]arp_q2;

// IP traffic from server side
class2[2] -> Strip(14) -> CheckIPHeader -> ip_class2 :: IPClassifier(
    src host $LLM1 or src host $LLM2 or src host $LLM3, // [0] backend response → reverse NAT
    -                                                     // [1] other → drop
);

// Server responses enter IPRewriter on input 1; the stored reverse mapping rewrites
// src LLM-IP → VIP and sends the packet out on rw[1]
ip_class2[0] -> [1]rw;
ip_class2[1] -> dropped_cnt;

// --- Rewriter outputs ---

// count the number of packets that are forwarded to the backend
dest_rip_cls :: IPClassifier(dst host $LLM1, dst host $LLM2, dst host $LLM3, -);

rw[0] -> CheckIPHeader -> dest_rip_cls

dest_rip_cls[0] -> cnt_to_llm1 -> arp_q2
dest_rip_cls[1] -> cnt_to_llm2 -> arp_q2
dest_rip_cls[2] -> cnt_to_llm3 -> arp_q2
dest_rip_cls[3] -> arp_q2

arp_q2 -> out_q2;
//

rw[1] -> CheckIPHeader -> arp_q1 -> out_q1; // reverse path: src rewritten to VIP, sent to client

// Catch-all drops and ARP query packets from the queriers
class1[3] -> dropped_cnt;
class2[3] -> dropped_cnt;
dropped_cnt -> Discard;

arp_q1[1] -> out_q1;
arp_q2[1] -> out_q2;

DriverManager(
    pause,
    print >lb1.report  "==================== LB1 Report ===================",
    print >>lb1.report "Input rate eth1 (pps):  $(in_avg_cnt1.rate)",
    print >>lb1.report "Input rate eth2 (pps):  $(in_avg_cnt2.rate)",
    print >>lb1.report "Output rate eth1 (pps): $(out_avg_cnt1.rate)",
    print >>lb1.report "Output rate eth2 (pps): $(out_avg_cnt2.rate)",
    print >>lb1.report "",
    print >>lb1.report "Total input  (eth1): $(in_pkt_cnt1.count)",
    print >>lb1.report "Total input  (eth2): $(in_pkt_cnt2.count)",
    print >>lb1.report "Total output (eth1): $(out_pkt_cnt1.count)",
    print >>lb1.report "Total output (eth2): $(out_pkt_cnt2.count)",
    print >>lb1.report "",
    print >>lb1.report "ARP req (eth1 / eth2): $(arp_req_cnt1.count) / $(arp_req_cnt2.count)",
    print >>lb1.report "ARP res (eth1 / eth2): $(arp_res_cnt1.count) / $(arp_res_cnt2.count)",
    print >>lb1.report "",
    print >>lb1.report "Total # of service packets: $(service_cnt.count)",
    print >>lb1.report "Total # of ICMP packets:    $(icmp_cnt.count)",
    print >>lb1.report "Total # of dropped packets: $(dropped_cnt.count)",
    print >>lb1.report "=== Backend Distribution ===",
    print >>lb1.report "Forwarded to LLM1 (100.0.0.40): $(cnt_to_llm1.count)",
    print >>lb1.report "Forwarded to LLM2 (100.0.0.41): $(cnt_to_llm2.count)",
    print >>lb1.report "Forwarded to LLM3 (100.0.0.42): $(cnt_to_llm3.count)",
    print >>lb1.report "=================================================="
);
