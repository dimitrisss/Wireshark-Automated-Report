import os
import time
import re
from scapy.all import rdpcap, IP, TCP, ARP, Raw
from tkinter import Tk, filedialog

# Define suspicious port details
port_details = {
    20: ("FTP Data", "File Transfer Protocol (Data)", False, ""),
    21: ("FTP", "File Transfer Protocol", False, ""),
    22: ("SSH", "Secure Shell", False, ""),
    23: ("Telnet", "Unencrypted text communications", True, "Unencrypted protocol; potential for interception of credentials."),
    25: ("SMTP", "Simple Mail Transfer Protocol", True, "Can be exploited for spamming."),
    53: ("DNS", "Domain Name System", True, "Can be exploited for DNS amplification attacks."),
    67: ("DHCP Server", "Dynamic Host Configuration Protocol", False, ""),
    68: ("DHCP Client", "Dynamic Host Configuration Protocol", False, ""),
    69: ("TFTP", "Trivial File Transfer Protocol", True, "Lacks authentication; vulnerable to attacks."),
    80: ("HTTP", "Hypertext Transfer Protocol", False, ""),
    81: ("HTTP Alternate", "Alternative HTTP port", True, "Often used for less secure applications."),
    110: ("POP3", "Post Office Protocol", True, "Exposes credentials if not secured."),
    143: ("IMAP", "Internet Message Access Protocol", True, "Can expose credentials if not secured."),
    161: ("SNMP", "Simple Network Management Protocol", True, "Vulnerable to unauthorized access."),
    443: ("HTTPS", "Hypertext Transfer Protocol Secure", False, ""),
    465: ("SMTPS", "Secure SMTP", False, ""),
    514: ("Syslog", "System Logging Protocol", True, "Can be exploited for log injection attacks."),
    587: ("SMTP (Submission)", "Email Submission", False, ""),
    631: ("IPP", "Internet Printing Protocol", True, "Potential for unauthorized printing."),
    873: ("rsync", "Remote file synchronization", True, "Can be exploited if not secured."),
    993: ("IMAPS", "Secure IMAP", False, ""),
    995: ("POP3S", "Secure POP3", False, ""),
    1080: ("SOCKS", "Socket Secure", True, "Can be exploited if misconfigured."),
    1433: ("MSSQL", "Microsoft SQL Server", True, "Common target for database attacks."),
    1521: ("Oracle DB", "Oracle Database", True, "Commonly targeted for database exploitation."),
    2049: ("NFS", "Network File System", True, "Can expose sensitive data if not secured."),
    3306: ("MySQL", "MySQL Database Server", True, "Commonly targeted for database attacks."),
    3389: ("RDP", "Remote Desktop Protocol", True, "Targeted for unauthorized access."),
    5432: ("PostgreSQL", "PostgreSQL Database", True, "Commonly targeted for database attacks."),
    5900: ("VNC", "Virtual Network Computing", True, "Can be exploited for unauthorized access."),
    6379: ("Redis", "In-memory Data Structure Store", True, "Can be exposed to attacks if not secured."),
    8080: ("HTTP (Alternative)", "Alternative HTTP port", True, "Can be misconfigured and vulnerable."),
    8443: ("HTTPS (Alternative)", "Alternative HTTPS port", True, "Similar to port 443; can be less secure."),
    9000: ("Various", "Various services", True, "Depends on running services; can be exploited."),
    9200: ("Elasticsearch", "Elasticsearch API", True, "Can allow unauthorized access to data."),
    9300: ("Elasticsearch Cluster", "Elasticsearch Cluster", True, "Should be secured properly."),
    10000: ("Webmin", "Web-based system administration", True, "Exposed to unauthorized access risk."),
    27017: ("MongoDB", "MongoDB Database", True, "Commonly targeted for database attacks."),
    50000: ("Various", "Various applications and services", True, "Depends on applications; can be exploited."),
}

# Define common credential error patterns
credential_error_patterns = {
    'HTTP': [r'401 Unauthorized', r'login failed', r'Forbidden', r'Credentials invalid'],
    'SMTP': [r'530 Authentication required', r'Invalid user', r'Login failed'],
}

# Function to analyze the PCAP file
def analyze_pcap(file_path):
    packets = rdpcap(file_path)
    suspicious_traffic = {}
    ip_count = {}
    connection_times = {}
    attackers_info = {}  # To store attackers' and destination IPs and open ports
    credential_errors = {}  # To store credential errors
    mac_addresses = {}   # To store MAC addresses
    machine_info = {}    # To store each machine's info (IP, MAC, ports)

    for packet in packets:
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            
            # Count source IP occurrences
            ip_count[ip_src] = ip_count.get(ip_src, 0) + 1
            
            # Record MAC addresses from ARP packets
            if ARP in packet and packet[ARP].op == 2:  # ARP reply
                mac_addresses[packet[ARP].psrc] = packet[ARP].hwsrc

            # Check for unusual TCP destination ports
            if TCP in packet:
                dport = packet[TCP].dport
                
                # Check for unusual destination ports
                if dport not in {80, 443, 22}:  # Common ports
                    key = f"Unusual TCP port {dport} from {ip_src} to {ip_dst}"
                    if key not in suspicious_traffic:
                        suspicious_traffic[key] = 0
                    suspicious_traffic[key] += 1

                # Check for SSH traffic
                if dport == 22:
                    ssh_key = f"SSH Traffic from {ip_src} to {ip_dst}"
                    if ssh_key not in suspicious_traffic:
                        suspicious_traffic[ssh_key] = 0
                    suspicious_traffic[ssh_key] += 1

                # Check for suspicious port usage
                if dport in port_details and port_details[dport][3]:  # If the port is suspicious
                    port_name, description, is_suspicious, reason = port_details[dport]
                    suspicious_key = f"Suspicious traffic on {port_name} ({dport}) from {ip_src} to {ip_dst}: {reason}"
                    if suspicious_key not in suspicious_traffic:
                        suspicious_traffic[suspicious_key] = 0
                    suspicious_traffic[suspicious_key] += 1
                
                # Track attackers and their destination IPs and open ports
                if ip_src not in attackers_info:
                    attackers_info[ip_src] = {
                        'destinations': set(),
                        'open_ports': set()
                    }
                attackers_info[ip_src]['destinations'].add(ip_dst)
                attackers_info[ip_src]['open_ports'].add(dport)

                # Gather machine info (IP, MAC, ports)
                if ip_src not in machine_info:
                    machine_info[ip_src] = {
                        'mac_address': mac_addresses.get(ip_src, 'N/A'),
                        'open_ports': set()
                    }
                machine_info[ip_src]['open_ports'].add(dport)

                # Check for credential errors in HTTP and SMTP
                if Raw in packet:
                    payload = str(packet[Raw].load)
                    for protocol, patterns in credential_error_patterns.items():
                        for pattern in patterns:
                            if re.search(pattern, payload, re.IGNORECASE):
                                error_key = f"{protocol} credential error from {ip_src} to {ip_dst}: {pattern}"
                                if error_key not in credential_errors:
                                    credential_errors[error_key] = 0
                                credential_errors[error_key] += 1

            # Check for excessive connections to the same destination
            connection_key = (ip_src, ip_dst)
            timestamp = time.time()
            if connection_key not in connection_times:
                connection_times[connection_key] = []
            connection_times[connection_key].append(timestamp)

    # Analyze connection spikes
    for (src, dst), timestamps in connection_times.items():
        if len(timestamps) > 10:  # Arbitrary threshold for spike detection
            timestamps.sort()
            for i in range(1, len(timestamps)):
                if timestamps[i] - timestamps[i-1] < 1:  # Connections within 1 second
                    spike_key = f"Rapid connections from {src} to {dst}"
                    if spike_key not in suspicious_traffic:
                        suspicious_traffic[spike_key] = 0
                    suspicious_traffic[spike_key] += 1
                    break

    return suspicious_traffic, attackers_info, mac_addresses, machine_info, credential_errors

# Function to generate the report
def generate_report(suspicious_traffic, attackers_info, mac_addresses, machine_info, credential_errors, output_file):
    with open(output_file, 'w') as f:
        f.write("Suspicious Traffic Report\n")
        f.write("=" * 30 + "\n")
        
        # Write suspicious traffic details
        for key, count in suspicious_traffic.items():
            f.write(f"{key}: {count}\n")
        f.write("\n")

        # Write credential error details
        f.write("Credential Errors Detected:\n")
        f.write("=" * 30 + "\n")
        for error_key, count in credential_errors.items():
            f.write(f"{error_key}: {count}\n")
        f.write("\n")

        # Write attackers information
        f.write("Attackers Information:\n")
        f.write("=" * 30 + "\n")
        for ip, info in attackers_info.items():
            f.write(f"IP Address: {ip}\n")
            f.write(f"  - Destinations: {', '.join(info['destinations'])}\n")
            f.write(f"  - Open Ports: {', '.join(map(str, info['open_ports']))}\n")
            f.write("\n")

        # Write MAC addresses
        f.write("MAC Addresses:\n")
        f.write("=" * 30 + "\n")
        for ip, mac in mac_addresses.items():
            f.write(f"IP Address: {ip} - MAC Address: {mac}\n")
        f.write("\n")

        # Write machine information
        f.write("Machine Information:\n")
        f.write("=" * 30 + "\n")
        for ip, info in machine_info.items():
            f.write(f"IP Address: {ip}\n")
            f.write(f"  - MAC Address: {info['mac_address']}\n")
            f.write(f"  - Open Ports: {', '.join(map(str, info['open_ports']))}\n")
            f.write("\n")

# Function to select a PCAP file
def select_file():
    root = Tk()
    root.withdraw()
    file_path = filedialog.askopenfilename(
        title="Select a PCAP file",
        filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")]
    )
    return file_path

# Main function to run the analysis and generate the report
def main():
    pcap_file = select_file()
    if not pcap_file:
        print("No file selected. Exiting.")
        return

    suspicious_traffic, attackers_info, mac_addresses, machine_info, credential_errors = analyze_pcap(pcap_file)
    output_report_file = os.path.splitext(pcap_file)[0] + "_suspicious_traffic_report.txt"
    generate_report(suspicious_traffic, attackers_info, mac_addresses, machine_info, credential_errors, output_report_file)

    print(f"Report generated: {output_report_file}")

if __name__ == "__main__":
    main()
