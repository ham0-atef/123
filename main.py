# main.py
# IoT Wearable Health Monitor - Security Analysis System
# Runs all modules in order

from heart_rate_gen import generate_logs
from threat_model   import run_threat_model
from firewall_rules import firewall_check, show_firewall_summary
from anomaly_detector import detect_anomalies
import random

def run_firewall_simulation():
    print("\n" + "=" * 50)
    print("   FIREWALL SIMULATION")
    print("=" * 50)

    # Sample connections to test the firewall
    test_connections = [
        ("192.168.1.10",  75,  128),   # Trusted - normal
        ("192.168.1.20",  90,  200),   # Trusted - normal
        ("10.0.0.55",     80,  150),   # Attacker IP
        ("192.168.1.99",  72,  100),   # Unknown device
        ("192.168.1.10",  210, 180),   # Trusted but tampered BPM
        ("192.168.1.20",  65,  500),   # Trusted but oversized packet
    ]

    for ip, bpm, size in test_connections:
        print(f"\n  Incoming: {ip} | {bpm} BPM | {size} bytes")
        result = firewall_check(ip, bpm, size)
        if result:
            print(f"  [FIREWALL] ALLOWED ✅")

    show_firewall_summary()

def main():
    print("\n" + "#" * 50)
    print("#   IoT Heart Rate Monitor Security System   #")
    print("#" * 50)

    # Step 1: Generate simulated device logs
    print("\n[STEP 1] Generating device logs...")
    generate_logs(num_entries=50)

    # Step 2: Run threat model
    print("\n[STEP 2] Running threat model...")
    run_threat_model()

    # Step 3: Simulate firewall
    print("\n[STEP 3] Simulating firewall rules...")
    run_firewall_simulation()

    # Step 4: Detect anomalies in logs
    print("\n[STEP 4] Detecting anomalies in logs...")
    detect_anomalies()

    print("\n" + "#" * 50)
    print("#          Security Analysis Complete         #")
    print("#" * 50)

if __name__ == "__main__":
    main()
خلاااصصصصص   