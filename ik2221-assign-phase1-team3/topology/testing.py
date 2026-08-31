import topology


def ping(client, server, expected, count=3, wait=2):
    """
    Send ICMP pings from client to server and compare the outcome to expected.
    server can be a Mininet host object or a plain IP string.
    Returns True if the result matches expected, False otherwise.
    count=3 and wait=2 give enough retries to survive a cold ARP cache on first run.
    """
    if not isinstance(server, str):
        server_addr = server.IP()
    else:
        server_addr = server

    cmd = f"ping {server_addr} -c {count} -W {wait} >/dev/null 2>&1; echo $?"
    ret = client.cmd(cmd).strip()
    actual_success = (ret == "0")

    if actual_success != expected:
        return False
    else:
        return True


def curl(client, server, method="GET", payload="", port=80, expected=True):
    """
    Run an HTTP request via curl and compare the outcome to expected.
    server can be a Mininet host object or a plain IP string.
    Returns True if the result matches expected, False otherwise.
    """
    if not isinstance(server, str):
        server_ip = str(server.IP())
    else:
        server_ip = server

    payload_str = f"-d '{payload}'" if payload else ""
    cmd = (
        f"curl --connect-timeout 3 --max-time 5 -s "
        f"-X {method} {payload_str} {server_ip}:{port} "
        f"> /dev/null 2>&1; echo $?"
    )

    ret = client.cmd(cmd).strip()
    actual_success = (ret == "0")

    if actual_success != expected:
        return False
    else:
        return True
