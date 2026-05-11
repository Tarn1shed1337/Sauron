import requests
import time 
import os
import io

NEXUS_URL = os.getenv("NEXUS_URL", "http://nexus:8000")
AGENT_NAME = os.getenv("AGENT_NAME", "unnamed-sensor")
AGENT_TYPE = os.getenv("AGENT_TYPE", "General") 
LOG_PATH = os.getenv("LOG_PATH", "/app/sensor.log")
ENFORCE_PATH = os.getenv("ENFORCE_PATH", "/etc/nginx/deny_list/blocklist.conf")

BANNED_IPS = set()

SIGNATURES = {
    "Failed password": "SSH",
    "GET /admin": "Unauthorized-Access",
    "GET /etc/passwd": "Path-Traversal-Attempt",
    "SELECT": "SQL-Injection-Attempt",
    "UNION": "SQL-Injection-Attempt",
    "FAIL LOGIN": "FTP-BruteForce",
    "<script>": "XSS-Attempt",
    "Access denied for user": "MySQL",
    "Invalid command": "Telnet"
}

def report_attack(attacker_ip, service):
    payload = {
        "agent_id": AGENT_NAME,
        "attacker_id": attacker_ip,
        "service": service
    }
    try:
        response = requests.post(f"{NEXUS_URL}/report", json=payload, timeout=5)
        print(f"ALERT SENT: {service} attack from {attacker_ip} | Status: {response.status_code}")
    except Exception as e:
        print(f"Connection to Nexus failed: {e}")

def update_firewall():
    global BANNED_IPS
    try:
        response = requests.get(f"{NEXUS_URL}/banlist", timeout=5)
        if response.status_code == 200:
            data = response.json()
            new_bans = set(data.get("banned_ips", [])) 
            
            if new_bans != BANNED_IPS:
                BANNED_IPS = new_bans
                with open(ENFORCE_PATH, "w") as f:
                    for ip in BANNED_IPS:
                        clean_ip = ip.replace('"', '').strip()
                        if "hosts.deny" in ENFORCE_PATH:
                            f.write(f"vsftpd: {clean_ip}\n")
                        else:
                            f.write(f"deny {clean_ip};\n")
                print(f"[*] {AGENT_TYPE} updated firewall at {ENFORCE_PATH} with {len(BANNED_IPS)} IPs.", flush=True)
        else:
            print(f"Failed to fetch ban list: Status code {response.status_code}")
    except Exception as e: 
        print(f"Failed to update firewall: {e}")

def monitor_logs():
    if not os.path.exists(LOG_PATH):
        print(f"[-] {AGENT_TYPE} Error: Log not found at {LOG_PATH}")
        return

    print(f"[*] {AGENT_TYPE} activated. Protecting: {LOG_PATH}")
    
    with open(LOG_PATH, "r") as f:
        if f.seekable():
            try:
                f.seek(0, 2) 
                print(f"[*] Seek successful. Watching for new entries on {AGENT_TYPE}.")
            except io.UnsupportedOperation:
                print(f"[*] {AGENT_TYPE} log is a stream. Reading from current position.")
        else:
            print(f"[*] {AGENT_TYPE} log is not seekable. Starting from beginning.")

        last_firewall_update = 0
        update_interval = 30
        
        while True:
            current_time = time.time()
            if current_time - last_firewall_update > update_interval:
                update_firewall()
                last_firewall_update = current_time
            
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            
            for signature, attack_type in SIGNATURES.items():
                if signature in line:
                    parts = line.split()
                    if not parts:
                        continue
                    ip = parts[0] if "WEB" in AGENT_TYPE else parts[-1]
                    report_attack(ip, f"{AGENT_TYPE}:{attack_type}")
                    break

if __name__ == "__main__":
    monitor_logs()
