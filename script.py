####################################
# Author: MohammadReza Rasi
# Created: 2024-03-07
# Last Modified: 2024-03-07
# Description: The Python script monitors various system aspects such as CPU usage, server load, IP blocking, disk I/O consumption, and RAM usage.
# Usage: python script.py
####################################

import os
import pwd
import psutil
import requests
import subprocess
from datetime import datetime

################################

cpu_usage_file_path = "./cpu_usage_log.log"

def get_username(pid):
    try:
        with open(f"/proc/{pid}/status", 'r') as status_file:
            for line in status_file:
                if line.startswith("Uid:"):
                    uid = int(line.split()[1])  # Index 1: The effective UID & Index 2: Real UID & Index 3: Saved UID & Index 4: Filesystem UID
                    # Get the username from the UID using pwd.getpwuid
                    username = pwd.getpwuid(uid).pw_name
                    return username
    except (FileNotFoundError, PermissionError, KeyError):
        return None

def get_process_cpu_cores(pid):
    try:
        # Get the number of CPU cores used by the process
        process_affinity = os.sched_getaffinity(pid)
        return len(process_affinity)
    except (AttributeError, OSError):
        return 0

def log_users_with_high_cores(threshold_cores=5, log_file_path="./cpu_usage_log.log"):
    with open(log_file_path, 'a') as log_file:
        log_file.write(f"Processes using more than {threshold_cores} cores:\n")
        log_file.write("{:<8} {:<16} {:<32} {:<10} {:<32}\n".format("PID", "USERNAME", "Process Name", "Core Count", "Command Line"))
        
        for pid in [pid for pid in os.listdir('/proc') if pid.isdigit()]:
            try:
                pid = int(pid)
                username = get_username(pid)
                process_name = open(f"/proc/{pid}/comm").read().strip()
                cpu_cores = get_process_cpu_cores(pid)
                cmd_line = open(f"/proc/{pid}/cmdline").read().replace('\0', ' ').strip()

                if cpu_cores > threshold_cores:
                    log_file.write("{:<8} {:<16} {:<32} {:<10} {:<32}\n".format(pid, username, process_name, cpu_cores, cmd_line))
            except (ValueError, FileNotFoundError, PermissionError):
                pass

        log_file.write("---------------------\n")
        log_file.write(f"Log created at {datetime.now().strftime('%a %d %b %Y %I:%M:%S %p %z')}\n")
        log_file.write("---------------------\n")

log_users_with_high_cores(threshold_cores=5, log_file_path=cpu_usage_file_path)

################################  

API_KEY = "your_cloudflare_api_key"
EMAIL = "your_cloudflare_email"
ZONE_ID = "your_cloudflare_zone_id"
SERVER_LOAD_THRESHOLD = 30

def get_server_load():
    try:
        # Execute the 'uptime' command and capture its output
        uptime_output = os.popen('uptime').read()
        
        # Extract the CPU load from the output
        load_str = uptime_output.split('load average:')[1].split(',')[0].strip()
        
        return float(load_str)

    except Exception as e:
        print(f"Error getting CPU load: {e}")
        return 0  # Return 0 in case of an error

def activate_under_attack_mode(api_key, email, zone_id):
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/settings/security_level"
    headers = {
        "Content-Type": "application/json",
        "X-Auth-Key": api_key,
        "X-Auth-Email": email,
    }
    payload = {
        "value": "under_attack"
    }

    response = requests.patch(url, headers=headers, json=payload)

    if response.status_code == 200:
        print("Under Attack mode activated successfully.")
        print(200)
    else:
        print(f"Error activating Under Attack mode. Status code: {response.status_code}")
        print(response.text)

if get_server_load() > SERVER_LOAD_THRESHOLD:
    activate_under_attack_mode(API_KEY, EMAIL, ZONE_ID)
else:
    print("Server load is below the threshold. Under Attack mode not activated.")

################################ 
    
THRESHOLD = 50
blocked_ips_file_path = "./blocked_ips.log"

def get_ip_counts():
    # Get the count of requests for each IP address
    ip_counts = {}
    with open('/var/log/apache2/access.log', 'r') as log_file:
        for line in log_file:
            parts = line.split()
            if len(parts) >= 4:
                ip_address = parts[0]
                if ip_address in ip_counts:
                    ip_counts[ip_address] += 1
                else:
                    ip_counts[ip_address] = 1
    return ip_counts

def block_ip(ip):
    subprocess.run(['sudo', 'nft' , 'add', 'rule', 'ip', 'filter', 'input', 'ip', 'saddr', ip, 'drop'])

def log_blocked_ip(ip_address, log_file_path="./blocked_ips.log"):
    with open(log_file_path, 'a') as log_file:
        log_file.write(f"Blocked IP: {ip_address}")

def check_blocking_ip(THRESHOLD=50):
    ip_counts = get_ip_counts()

    for ip_address, count in ip_counts.items():
        if count > THRESHOLD:
            block_ip(ip_address)
            log_blocked_ip(ip_address, blocked_ips_file_path)

    with open(blocked_ips_file_path, 'a') as log_file:
        log_file.write("---------------------\n")
        log_file.write(f"Log created at {datetime.now().strftime('%a %d %b %Y %I:%M:%S %p %z')}\n")
        log_file.write("---------------------\n")

check_blocking_ip(THRESHOLD=THRESHOLD)

################################ 

disk_IO_consumption_file_path = "./disk_IO_consumption.log"

def bytes_to_MB_or_KB(bytes_value, convert_to="MB"):
    if convert_to == "MB":
        return round(float(bytes_value) / (1024 ** 2), 2)
    elif convert_to == "KB":
        return round(float(bytes_value) / 1024, 2)

def get_process_disk_io(pid):
    try:
        with open(f"/proc/{pid}/io", 'r') as status_file:
            read_bytes_output, write_bytes_output = [], []
            for line in status_file:
                if line.startswith("read_bytes:"):
                    read_bytes = int(line.split(":")[1].strip())
                    read_bytes_output.append((pid, "read_bytes:", bytes_to_MB_or_KB(read_bytes, "MB"), bytes_to_MB_or_KB(read_bytes, "KB")))
                elif line.startswith("write_bytes:"):
                    write_bytes = int(line.split(":")[1].strip())
                    write_bytes_output.append((pid, "write_bytes:", bytes_to_MB_or_KB(write_bytes, "MB"), bytes_to_MB_or_KB(write_bytes, "KB")))
            return read_bytes_output, write_bytes_output
    except subprocess.CalledProcessError as e:
        # print(f"Error retrieving disk I/O for Process {pid}: {e}")
        return None, None
    except FileNotFoundError as e:
        # print(f"Error: {e}. Ensure that the process with ID {pid} exists.")
        return None, None
    except PermissionError as e:
        # print(f"Permission denied: '/proc/{pid}/io'")
        return None, None

def get_max_IO():
    all_entries = os.listdir('/proc')
    pids = [entry for entry in all_entries if entry.isdigit()]

    inf_r, inf_w = [], []
    for pid in pids:
        detail1, detail2 = get_process_disk_io(pid)
        if detail1 is not None:
            inf_r.extend(detail1)
            inf_w.extend(detail2)

    return inf_r, inf_w

def pids_with_high_cores_disk_IO_consumption(num=4, log_file_path="./disk_IO_consumption.log"):
    r_consumption, w_consumption = get_max_IO()
    sorted_r_consumption = sorted(r_consumption, key=lambda x: x[3], reverse=True)
    sorted_w_consumption = sorted(w_consumption, key=lambda x: x[3], reverse=True)

    with open(log_file_path, 'a') as log_file:
        log_file.write(f"Disk I/O\n")
        for r in sorted_r_consumption[:num]:
            log_file.write(f"{r[0]}, {r[1]}, {r[2]}, {r[3]}\n")
        log_file.write("---------------------\n")
        for w in sorted_w_consumption[:num]:
            log_file.write(f"{w[0]}, {w[1]}, {w[2]}, {w[3]}\n")
        
        log_file.write("---------------------\n")
        log_file.write(f"Log created at {datetime.now().strftime('%a %d %b %Y %I:%M:%S %p %z')}\n")
        log_file.write("---------------------\n")

pids_with_high_cores_disk_IO_consumption(num=6, log_file_path=disk_IO_consumption_file_path)

################################

ram_consumption_file_path = "./ram_consumption.log"

def get_users_over_limit(memory_limit_mb=100, log_file_path="./ram_consumption.log"):
    with open(log_file_path, 'a') as log_file:
        log_file.write(f"RAM Consumption:\n")
        log_file.write("{:<8} {:<12} {:<24} {:<16} {:<32}\n".format("pid", "username", "name", "memory_usage_mb", "cmdline"))
        users_over_limit = []

        for process in psutil.process_iter(['pid', 'name', 'username', 'memory_info', 'cmdline']):
            try:
                username = process.info['username']
                memory_usage_mb = process.info['memory_info'].rss / (1024 ** 2)  # convert to MB

                if memory_usage_mb > memory_limit_mb:
                    if username not in users_over_limit:
                        users_over_limit.append(username)
                    log_file.write("{:<8} {:<12} {:<24} {:<16} {:<32}\n".format(process.info['pid'], username, process.info['name'], memory_usage_mb, ' '.join(process.info['cmdline'])))

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        
        log_file.write("---------------------\n")
        log_file.write(f"Log created at {datetime.now().strftime('%a %d %b %Y %I:%M:%S %p %z')}\n")
        log_file.write("---------------------\n")

memory_limit = 150  # limit in MB
get_users_over_limit(memory_limit)

# todo: send email
