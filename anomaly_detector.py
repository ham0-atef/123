# anomaly_detector.py
# Detects anomalous patterns in heart-rate monitor logs

TRUSTED_IPS = [
    "192.168.1.10",
    "192.168.1.20",
    "192.168.1.30",
]

NORMAL_BPM_MIN = 40
NORMAL_BPM_MAX = 180
RAPID_ATTACK_THRESHOLD = 3    # seconds between requests to flag as rapid

def parse_logs():
    allowed_count = 0
    blocked_count = 0
    attempt_tracker = {}
    time_tracker    = {}
    bpm_tracker     = {}

    log_reader = open("smart_log.txt", "r")

    for record in log_reader:
        columns      = record.strip().split("|")
        timestamp    = columns[0].strip()
        device_ip    = columns[1].strip()
        heart_rate   = int(columns[2].strip().replace(" BPM", ""))
        access_result = columns[4].strip()

        if access_result == "ALLOWED":
            allowed_count += 1
        else:
            blocked_count += 1

            if device_ip not in attempt_tracker:
                attempt_tracker[device_ip] = 1
                time_tracker[device_ip]    = []
                bpm_tracker[device_ip]     = []
            else:
                attempt_tracker[device_ip] += 1

            time_tracker[device_ip].append(timestamp)
            bpm_tracker[device_ip].append(heart_rate)

    log_reader.close()
    return allowed_count, blocked_count, attempt_tracker, time_tracker, bpm_tracker

def detect_anomalies():
    print("\n" + "=" * 50)
    print("   ANOMALY DETECTION - Heart Rate Monitor")
    print("=" * 50)

    allowed_count, blocked_count, attempt_tracker, time_tracker, bpm_tracker = parse_logs()

    total_requests = allowed_count + blocked_count

    # === General Report ===
    print("\n=== TRAFFIC REPORT ===")
    print(f"Total Requests  : {total_requests}")
    print(f"Allowed         : {allowed_count}")
    print(f"Blocked         : {blocked_count}")

    if total_requests > 0:
        success_rate = (allowed_count / total_requests) * 100
        print(f"Success Rate    : {round(success_rate, 2)}%")

    # === Attack Analysis ===
    print("\n=== ATTACK ANALYSIS ===")

    top_threat_ip   = ""
    highest_attempts = 0

    for device_ip in attempt_tracker:
        attempt_count = attempt_tracker[device_ip]

        if attempt_count > highest_attempts:
            highest_attempts = attempt_count
            top_threat_ip    = device_ip

        if attempt_count >= 3:
            print(f"\n  IP       : {device_ip}")
            print(f"  Attempts : {attempt_count}")

            # Risk level based on attempts
            if attempt_count >= 7:
                print("  Risk     : HIGH 🚨")
            elif attempt_count >= 4:
                print("  Risk     : MEDIUM ⚠️")
            else:
                print("  Risk     : LOW ℹ️")

            # Rapid attack detection
            times = time_tracker[device_ip]
            if len(times) >= 3:
                print("  Pattern  : Possible rapid attack ⚡")

    # === BPM Anomaly Detection ===
    print("\n=== HEART RATE ANOMALIES ===")
    anomaly_found = False

    log_reader = open("smart_log.txt", "r")
    for record in log_reader:
        columns    = record.strip().split("|")
        timestamp  = columns[0].strip()
        device_ip  = columns[1].strip()
        heart_rate = int(columns[2].strip().replace(" BPM", ""))

        if heart_rate < NORMAL_BPM_MIN:
            print(f"  [CRITICAL] {device_ip} at {timestamp} → {heart_rate} BPM (Dangerously LOW) 🔴")
            anomaly_found = True
        elif heart_rate > NORMAL_BPM_MAX:
            print(f"  [WARNING]  {device_ip} at {timestamp} → {heart_rate} BPM (Dangerously HIGH) 🟠")
            anomaly_found = True

    log_reader.close()

    if not anomaly_found:
        print("  No BPM anomalies detected ✅")

    # === Most Dangerous IP ===
    print("\n=== MOST DANGEROUS IP ===")
    if top_threat_ip:
        print(f"  {top_threat_ip} with {highest_attempts} blocked attempts")
    else:
        print("  No threats detected ✅")

    print("\n[+] Anomaly detection complete.")
