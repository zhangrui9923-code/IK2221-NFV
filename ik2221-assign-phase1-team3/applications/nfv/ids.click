// IDS - Intrusion Detection System
//
// Port mapping:
//   PORT1 (ids-eth1) — s2         (user zone, incoming traffic)
//   PORT2 (ids-eth3) — lb1        (load balancer, clean traffic)
//   PORT3 (ids-eth2) — insp       (inspection server, suspicious traffic)
//
// Pass-through (no inspection):
//   Non-IP frames (ARP), ICMP, and TCP control packets (SYN/FIN/RST/pure-ACK)
//   from user zone → lb1 transparently.
//   All return traffic from lb1 → user zone.
//   All traffic from insp → user zone.
//
// Inspection (HTTP TCP:80 data packets, user → server direction only):
//   Step 1 — Method filter (Classifier at byte offset 54 or 66):
//              POST  → lb1  (allowed, no payload check)
//              PUT   → Step 2
//              other → insp (GET, HEAD, DELETE, OPTIONS, TRACE, CONNECT)
//   Step 2 — Payload filter (Search advances past HTTP header, then Classifier at offset 0):
//              clean payload     → lb1
//              malicious payload → insp

define($PORT1 ids-eth1, $PORT2 ids-eth3, $PORT3 ids-eth2)

Script(print "IDS starting: in=$PORT1  lb=$PORT2  insp=$PORT3")

// ── Devices ────────────────────────────────────────────────────────────────
fd_in  :: FromDevice($PORT1, SNIFFER false, METHOD LINUX, PROMISC true)
fd_lb  :: FromDevice($PORT2, SNIFFER false, METHOD LINUX, PROMISC true)
fd_insp:: FromDevice($PORT3, SNIFFER false, METHOD LINUX, PROMISC true)

td_in  :: ToDevice($PORT1, METHOD LINUX)
td_lb  :: ToDevice($PORT2, METHOD LINUX)
td_insp:: ToDevice($PORT3, METHOD LINUX)

// ── AverageCounters (required: after every FromDevice, before every ToDevice) ──
ac_fd_in  :: AverageCounter
ac_fd_lb  :: AverageCounter
ac_fd_insp:: AverageCounter

ac_td_in  :: AverageCounter
ac_td_lb  :: AverageCounter
ac_td_insp:: AverageCounter

// Output queues: multiple upstream paths merge into a single queue per interface
q_in, q_lb, q_insp :: Queue

q_in   -> ac_td_in   -> td_in
q_lb   -> ac_td_lb   -> td_lb
q_insp -> ac_td_insp -> td_insp

fd_in   -> ac_fd_in
fd_lb   -> ac_fd_lb
fd_insp -> ac_fd_insp

// ── Pass-through: return paths ─────────────────────────────────────────────

// lb1 and insp return traffic goes straight back to the user zone
ac_fd_lb   -> q_in
ac_fd_insp -> q_in

// ── Inspection pipeline (user → server direction only) ─────────────────────

// Per-class packet counters
cnt_passthrough, cnt_bad_method, cnt_post, cnt_bad_payload, cnt_clean_put :: Counter

// Separate non-IP frames (ARP etc.) before handing off to IPClassifier.
ac_fd_in -> eth_cls :: Classifier(12/0800, -); // only check IP packet

eth_cls[0] -> MarkIPHeader(14) -> ip_cls :: IPClassifier(tcp dst port 80 and tcp psh, -); // only check TCP packet with PSH
eth_cls[1] -> cnt_passthrough; // non-IP (ARP, for example) pass

// TCP control packets (PSH=0: SYN, FIN, RST, pure ACK) and non-HTTP IP — pass through
ip_cls[1] -> cnt_passthrough;

cnt_passthrough -> q_lb;

// =========================================================================
// Step 1: Method filter.
ip_cls[0]
-> method_cls :: Classifier(
    54/504f535420,   // [0] "POST " at 54
    54/50555420,     // [1] "PUT "  at 54
    66/504f535420,   // [2] "POST " at 66
    66/50555420,     // [3] "PUT "  at 66
    54/47455420,     // [4] "GET "  at 54 bolck it
    66/47455420,     // [5] "GET "  at 66 block it
    54/44454c455445, // [6] "DELETE" at 54 block it
    66/44454c455445, // [7] "DELETE" at 66 block it
    54/4f5054494f4e5320, // [8] "OPTIONS " 54 bolck it
    66/4f5054494f4e5320, // [9] "OPTIONS " 66 ..
    54/545241434520,     // [10] "TRACE " 54 .. 
    66/545241434520,     // [11] "TRACE " 66 ..
    54/434f4e4e45435420, // [12] "CONNECT " 54 ..
    66/434f4e4e45435420, // [13] "CONNECT " 66 ..
    54/4845414420,    // [14]"HEAD " at 54 block it
    66/4845414420,    // [15] "HEAD " at 66 block it
    -                // [16] others
)

// allow POST passing throuth to lb1
method_cls[0], method_cls[2] -> cnt_post -> q_lb

// bad methods to insp
method_cls[4], method_cls[5], method_cls[6], method_cls[7], method_cls[8], method_cls[9], method_cls[10], method_cls[11], method_cls[12], method_cls[13], method_cls[14], method_cls[15] -> cnt_bad_method -> q_insp

// others should let go to insp [?? todo]
method_cls[16] -> q_insp


// PUT Payload check
// Search jump to HTTTP body
method_cls[1], method_cls[3] -> payload_search :: Search("\r\n\r\n")

// A PUT without the \r\n\r\n, go to lb1
payload_search[1] -> q_lb 

// Step 2: Payload filter.
// Search has jump throuth the header
payload_search[0]
-> payload_cls :: Classifier(
    0/636174202f6574632f706173737764,  // cat /etc/passwd
    0/636174202f7661722f6c6f672f,      // cat /var/log/
    0/494e53455254,                    // INSERT
    0/555044415445,                    // UPDATE
    0/44454c455445,                    // DELETE
    -                                  // Safe data
)

// bad payload to insp
payload_cls[0], payload_cls[1], payload_cls[2], payload_cls[3], payload_cls[4] -> cnt_bad_payload -> q_insp

// good payload to lb1
payload_cls[5] -> cnt_clean_put -> q_lb
//payload_cls[5] -> Unstrip -> cnt_clean_put -> q_lb
// ── Report on shutdown 
DriverManager(
    pause,
    print >ids.report   
"=================== IDS Report ===================
        Input rate (pps):           $(ac_fd_in.rate)
        Output lb1 rate (pps):      $(ac_td_lb.rate)
        Output insp rate (pps):     $(ac_td_insp.rate)
        
        Total input packets:        $(ac_fd_in.count)
        Total output to lb1:        $(ac_td_lb.count)
        Total output to insp:       $(ac_td_insp.count)
        Non-HTTP (pass-through):    $(cnt_passthrough.count)
        POST (allowed):             $(cnt_post.count)
        Clean PUT (allowed):        $(cnt_clean_put.count)
        Blocked (bad method):       $(cnt_bad_method.count)
        Blocked (bad payload):      $(cnt_bad_payload.count)
==================================================="
    )
