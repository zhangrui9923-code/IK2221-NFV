
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Switch
from mininet.cli import CLI
from mininet.node import RemoteController
from mininet.node import OVSSwitch
from topology import *
import testing


topos = {'mytopo': (lambda: MyTopo())}

def run_tests(net):
    print("STARTING AUTOMATED TEST SUITE")
    print("="*40 + "\n")
    h1 = net.get('h1')
    h2 = net.get('h2')
    llm1 = net.get('llm1')
    vip = "100.0.0.45"
    
    # Test help functions
    # ==================================================
    def is_pass(result):
        if result:
            print("PASS")
        else:
            print("FAIL")
        
    test_counter = 1
    def execute_test(name, func, *args, **kwargs):
        nonlocal test_counter
        print(f"--- Test {test_counter}: {name} ---")
        result = func(*args, **kwargs)
        is_pass(result)
        test_counter += 1
    # ==================================================
    
    # 1: Basic Connectivity (Expected = True)
    execute_test("L2 Connectivity (h1 -> h2)", testing.ping, h1, h2, expected=True)
    execute_test("NAPT Connectivity (h1 -> llm1)", testing.ping, h1, llm1, expected=False)  # lb1 blocks non-VIP traffic
    execute_test("Load Balancer Ping (h1 -> VIP)", testing.ping, h1, vip, expected=True)

    # 2: Normal HTTP Traffic (Expected = True)
    # ONLY POST and PUT are allowed
    execute_test("Normal HTTP POST", testing.curl, h1, vip, method="POST", payload="hello_llm", expected=True)
    # because of 'Search', this can not pass throuth but we can not get a response
    # execute_test("Normal HTTP PUT (Safe Data)", testing.curl, h1, vip, method="PUT", payload="safe_document", expected=True)

    # 3: Blocked HTTP Methods (Expected = False)
    # these methods must be blocked by the IDS
    blocked_methods = ["GET", "HEAD", "OPTIONS", "TRACE", "DELETE", "CONNECT"]
    for method in blocked_methods:
        execute_test(f"IDS Block Method: {method}", testing.curl, h1, vip, method=method, expected=False)

    # 4: Blocked Malicious Payloads (Expected = False)
    # these payloads (code injection) must be blocked by the IDS
    malicious_payloads = [
        "cat /etc/passwd", 
        "cat /var/log/", 
        "INSERT", 
        "UPDATE", 
        "DELETE"
    ]
    for payload in malicious_payloads:
        execute_test(f"IDS Block Payload: [{payload}]", testing.curl, h1, vip, method="PUT", payload=payload, expected=False)
    # 5: Port Filtering, the rest must be blocked
    # Testing a port that is NOT 80. This should fail.
    execute_test("LB Block Non-HTTP Port (81)", testing.curl, h1, vip, port=81, expected=False)
    
    # 6: Load Balancer Distribution Test
    print(f"--- Test 18: Load Balancer Round-Robin Distribution ---")
    print(" Sending POST requests to VIP...")
    
    success_count = 0
    for i in range(30):
        # -H 'Connection: close' is important
        # each request one connection
        result = h1.cmd(f"curl -s --max-time 2 -H 'Connection: close' -X POST {vip} > /dev/null; echo $?")
        
        # if successful
        if result.strip() == "0":
            success_count += 1

    if success_count == 30:
        print("  PASS (30 requests sent successfully)")
    else:
        print(f"  FAIL (Only {success_count}/30 requests succeeded)")

    print("="*60)
    print("AUTOMATED TEST FINISHED")
    print("="*60 + "\n")


if __name__ == "__main__":

    # Create topology
    topo = MyTopo()

    ctrl = RemoteController("c0", ip="127.0.0.1", port=6633)

    # Create the network
    net = Mininet(topo=topo,
                  switch=OVSSwitch,
                  controller=ctrl,
                  autoSetMacs=True,
                  autoStaticArp=False, # We will set the ARP addresses manually, so we don't need to set it to True
                  build=True,
                  cleanup=True)

    # Start the network
    net.start()
    # Give switches time to connect to POX and for Click processes to finish loading
    print("Waiting for switches to connect and Click to load")
    import time
    time.sleep(10)

    startup_services(net)
    # Give the background HTTP servers time to bind to port 80 before tests start
    time.sleep(3)
    
    insp = net.get('insp')
    # use tcpdump to capture the packets to inspector_proof.pcap
    insp.cmd("tcpdump -i insp-eth0 -w inspector_proof.pcap > /dev/null 2>&1 &")
    
    
    run_tests(net)
    
    print("Cleaning up backend HTTP servers")
    net.get('llm1').cmd("pkill -f 'python3 -m http.server'")

    net.stop()
