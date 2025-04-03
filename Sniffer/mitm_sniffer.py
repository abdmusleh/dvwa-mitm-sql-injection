from scapy.all import rdpcap, IP, TCP, Raw

DVWA_IP_RANGE = ['172.18.0.' + str(i) for i in range(2, 10)]
SQL_INJECTION_PATTERNS = [
    "UNION SELECT", "ORDER BY", "SELECT UserId, Name, Password FROM Users WHERE UserId",
    "SELECT * FROM users WHERE userid", "1=1", "admin --", "select*from users"
]

SENSITIVE_PATTERNS = ["Set-Cookie", "password=", "Authorization:", "session="]

def contains_sql_injection(packet):
    if Raw in packet:
        payload = packet[Raw].load.decode(errors='ignore')
        for pattern in SQL_INJECTION_PATTERNS:
            if pattern in payload:
                return True
    return False

def contains_sensitive_data(packet):
    if Raw in packet:
        payload = packet[Raw].load.decode(errors='ignore')
        for pattern in SENSITIVE_PATTERNS:
            if pattern in payload:
                return True
    return False

def packet_filter(packet):
    if IP in packet and TCP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        
        if ip_src in DVWA_IP_RANGE or ip_dst in DVWA_IP_RANGE:
            if packet.haslayer(Raw):
                if contains_sql_injection(packet):
                    return 'SQL Injection'
                elif contains_sensitive_data(packet):
                    return 'MITM Captured Traffic'
                return 'Normal HTTP'
    return None

normal_traffic_file = '/home/kali/Desktop/capture in normal state/afterDVWA.pcapng'
sql_injection_file = '/home/kali/Desktop/capture in normal state/sqlDVWAinjection.pcapng'
mitm_traffic_file = '/home/kali/Desktop/capture in normal state/mitmDVWA.pcapng'

packets_normal = rdpcap(normal_traffic_file)
packets_sql_injection = rdpcap(sql_injection_file)
packets_mitm = rdpcap(mitm_traffic_file)

all_packets = packets_normal + packets_sql_injection + packets_mitm
categorized_packets = {'Normal HTTP': [], 'SQL Injection': [], 'MITM Captured Traffic': []}

for pkt in all_packets:
    result = packet_filter(pkt)
    if result:
        categorized_packets[result].append(pkt)

print(f"Total Normal HTTP packets: {len(categorized_packets['Normal HTTP'])}")
print(f"Total SQL Injection packets: {len(categorized_packets['SQL Injection'])}")
print(f"Total MITM Captured Traffic packets: {len(categorized_packets['MITM Captured Traffic'])}")

for category, packets in categorized_packets.items():
    print(f"\nCategory: {category}")
    for pkt in packets:
        print(pkt.summary())
        if pkt.haslayer(Raw):
            print(pkt[Raw].load)
            print("-" * 50)
