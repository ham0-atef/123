# heart_rate_gen.py
# Simulates a wearable heart-rate monitor sending data to a medical server

import random
import datetime

# Trusted devices allowed to communicate with the monitor
TRUSTED_IPS = [
    "192.168.1.10",   # Doctor's smartphone
    "192.168.1.20",   # Medical server
    "192.168.1.30",   # Nurse tablet
]

# All possible IPs (trusted + potential attackers)
ALL_IPS = TRUSTED_IPS + [
    "192.168.1.99",   # Unknown device
    "10.0.0.55",      # External attacker
    "172.16.0.5",     # Suspicious device
]

def generate_random_ip():
    chance = random.randint(1, 10)
    if chance <= 6:
        return random.choice(TRUSTED_IPS)
    elif chance <= 8:
        return random.choice(ALL_IPS)
    else:
        return (str(random.randint(1, 223)) + "." +
                str(random.randint(0, 255)) + "." +
                str(random.randint(0, 255)) + "." +
                str(random.randint(1, 254)))

def generate_heart_rate():
    scenario = random.randint(1, 10)
    if scenario <= 6:
        return random.randint(60, 100)    # Normal
    elif scenario <= 8:
        return random.randint(101, 180)   # High (exercise/stress)
    elif scenario == 9:
        return random.randint(20, 39)     # Dangerously low
    else:
        return random.randint(181, 250)   # Dangerously high (attack/tampered)

def generate_logs(num_entries=50):
    log_file = open("smart_log.txt", "w")
    current_time = datetime.datetime(2024, 1, 1, 8, 0)

    for entry in range(num_entries):
        device_ip = generate_random_ip()
        heart_rate = generate_heart_rate()
        data_size = random.randint(64, 512)  # bytes

        # Simulate attack: flood with rapid requests
        if random.randint(1, 10) == 1:
            interval = datetime.timedelta(seconds=random.randint(1, 3))   # Very fast
        else:
            interval = datetime.timedelta(seconds=random.randint(20, 60)) # Normal

        if device_ip in TRUSTED_IPS:
            status = "ALLOWED"
        else:
            status = "DENIED"

        record = (str(current_time) + " | " +
                  device_ip + " | " +
                  str(heart_rate) + " BPM | " +
                  str(data_size) + " bytes | " +
                  status)

        log_file.write(record + "\n")
        current_time += interval

    log_file.close()
    print("[+] Log file generated: smart_log.txt")
