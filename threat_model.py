# threat_model.py
# Models common cyber threats targeting IoT wearable health monitors

import random
import datetime

def simulate_spoofing_attack():
    """
    Spoofing: Attacker pretends to be a trusted device
    by using a similar IP to the medical server
    """
    print("\n[THREAT] Spoofing Attack Detected!")
    fake_ip = "192.168.1.20"   # Same as trusted medical server
    real_mac = "AA:BB:CC:DD:EE:FF"
    fake_mac = "11:22:33:44:55:66"
    print(f"  Attacker IP : {fake_ip}")
    print(f"  Real MAC    : {real_mac}")
    print(f"  Fake MAC    : {fake_mac}")
    print("  Risk        : HIGH - Attacker may intercept patient data")
    print("  Mitigation  : Use MAC filtering + mutual TLS authentication")

def simulate_replay_attack():
    """
    Replay Attack: Attacker captures old data packets and resends them
    to confuse the medical server with outdated readings
    """
    print("\n[THREAT] Replay Attack Detected!")
    original_time = datetime.datetime(2024, 1, 1, 8, 0)
    replay_time   = datetime.datetime(2024, 1, 1, 10, 30)
    old_heart_rate = 75

    print(f"  Original Packet Time : {original_time}")
    print(f"  Replayed at          : {replay_time}")
    print(f"  Replayed Heart Rate  : {old_heart_rate} BPM")
    print("  Risk        : MEDIUM - Doctor may act on outdated patient data")
    print("  Mitigation  : Use timestamps + sequence numbers in packets")

def simulate_dos_attack():
    """
    DoS: Attacker floods the device with requests to drain battery
    and block legitimate data from reaching the server
    """
    print("\n[THREAT] Denial of Service (DoS) Attack Detected!")
    attacker_ip = "10.0.0.55"
    requests_per_second = random.randint(80, 200)

    print(f"  Attacker IP          : {attacker_ip}")
    print(f"  Requests per second  : {requests_per_second}")
    print("  Risk        : HIGH - Device battery drain + data loss")
    print("  Mitigation  : Rate limiting + firewall blocking")

def simulate_data_tampering():
    """
    Data Tampering: Attacker intercepts and modifies heart rate values
    to trigger false medical alerts
    """
    print("\n[THREAT] Data Tampering Attack Detected!")
    real_rate   = 78
    forged_rate = 195

    print(f"  Real Heart Rate    : {real_rate} BPM")
    print(f"  Tampered Heart Rate: {forged_rate} BPM")
    print("  Risk        : CRITICAL - May cause wrong medical treatment")
    print("  Mitigation  : End-to-end encryption + data integrity checks")

def run_threat_model():
    print("=" * 50)
    print("   THREAT MODEL - IoT Heart Rate Monitor")
    print("=" * 50)
    simulate_spoofing_attack()
    simulate_replay_attack()
    simulate_dos_attack()
    simulate_data_tampering()
    print("\n[+] Threat modeling complete.")
