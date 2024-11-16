from scapy.all import sniff


IP_MAC_MAP={}
def processPacket (packet):
    src_IP = packet['ARP'].psrc
    src_MAC = packet ['Ether'].src
    print("Sniffing network for ARP Packets...")
    
    if src_MAC in IP_MAC_MAP.keys():
        if IP_MAC_MAP[src_MAC] != src_IP:
            try:
                old_IP = IP_MAC_MAP[src_MAC]
            except KeyError:
                old_IP = "Unknown"
            message = ("\n ARP ATTACK DETECTED** \n"+ "POSSIBLY ATTACKER SPOOFED THE MACHINES \n"+ str(old_IP) + " AND " + str(src_IP)+ "\n")
            return message

    else:
        IP_MAC_MAP[src_MAC] = src_IP

sniff (count = 0, filter="arp", store=0, prn=processPacket, iface="Wi-Fi")
