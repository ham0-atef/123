# firewall_rules.py
# Simulates a software firewall protecting the IoT heart-rate monitor

TRUSTED_IPS = [
    "192.168.1.10",
    "192.168.1.20",
    "192.168.1.30",
]

BLOCKED_IPS = []               # Dynamically blocked IPs
MAX_REQUESTS_PER_MINUTE = 10   # Rate limit per IP
request_counter = {}           # Tracks requests per IP

def is_trusted(ip):
    return ip in TRUSTED_IPS

def is_blocked(ip):
    return ip in BLOCKED_IPS

def block_ip(ip):
    if ip not in BLOCKED_IPS:
        BLOCKED_IPS.append(ip)
        print(f"  [FIREWALL] IP BLOCKED: {ip}")

def rate_limit_check(ip):
    if ip not in request_counter:
        request_counter[ip] = 1
    else:
        request_counter[ip] += 1

    if request_counter[ip] > MAX_REQUESTS_PER_MINUTE:
        block_ip(ip)
        return False
    return True

def firewall_check(ip, heart_rate, data_size):
    """
    Main firewall function — checks every incoming connection
    Returns True if allowed, False if blocked
    """

    # Rule 1: Block known bad IPs
    if is_blocked(ip):
        print(f"  [FIREWALL] BLOCKED (blacklist): {ip}")
        return False

    # Rule 2: Only allow trusted IPs
    if not is_trusted(ip):
        print(f"  [FIREWALL] BLOCKED (untrusted): {ip}")
        block_ip(ip)
        return False

    # Rule 3: Rate limiting
    if not rate_limit_check(ip):
        print(f"  [FIREWALL] BLOCKED (rate limit): {ip}")
        return False

    # Rule 4: Reject abnormal data sizes (possible injection)
    if data_size > 400:
        print(f"  [FIREWALL] BLOCKED (large packet {data_size} bytes): {ip}")
        return False

    # Rule 5: Reject impossible heart rate values
    if heart_rate < 20 or heart_rate > 250:
        print(f"  [FIREWALL] BLOCKED (invalid BPM {heart_rate}): {ip}")
        return False

    return True   # All checks passed

def show_firewall_summary():
    print("\n=== FIREWALL SUMMARY ===")
    print(f"Trusted IPs      : {TRUSTED_IPS}")
    print(f"Blocked IPs      : {BLOCKED_IPS if BLOCKED_IPS else 'None'}")
    print(f"Rate limit       : {MAX_REQUESTS_PER_MINUTE} req/min")
