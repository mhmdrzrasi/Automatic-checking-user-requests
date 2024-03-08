# System Monitoring and Security Automation
The Python script monitors various system aspects such as CPU usage, server load, IP blocking, disk I/O consumption, and RAM usage

## Concepts and features
### 1. CPU Usage Monitoring
The script identifies processes utilizing more than a specified number of CPU cores and logs relevant information such as PID, username, process name, core count, and command line. The results are stored in a log file (cpu_usage_log.log).
### 2. Server Load Monitoring and Under Attack Mode Activation
The script checks the server load using the uptime command and activates Cloudflare's "Under Attack" mode if the load exceeds a predefined threshold. Ensure to set your Cloudflare API key, email, and zone ID in the script.
### 3. IP Blocking Based on Access Logs
The script analyzes Apache access logs to identify IPs with a high request count. IPs exceeding a specified threshold are blocked using nft rules. Blocked IP information is logged in blocked_ips.log.
### 4. Disk I/O Consumption Monitoring
The script identifies processes with the highest disk I/O consumption in terms of read and write bytes. The results are logged in disk_IO_consumption.log.
### 5. RAM Consumption Monitoring
Processes exceeding a specified RAM limit are logged with details such as PID, username, process name, memory usage, and command line. The results are stored in ram_consumption.log.
### 6. TODO
Implement email notification functionality.

## Usage
### 1- Clone the repository:
```
git clone https://github.com/mhmdrzrasi/Automatic-checking-user-requests.git
```
### 2- Install the required dependencies using:
```
pip install -r requirements.txt
```
### 3- Run the script using the following command:
```python
python g_w_script.py
```

## Author
MohammadReza Rasi
