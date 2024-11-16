# packet_sniffer.py
import scapy.all as scapy
from scapy.layers.http import HTTPRequest
from flask_socketio import SocketIO

# SocketIO instance
socketio = None  # We'll set this in app.py to link with Flask-SocketIO

def start_sniffing(target_ip):
    # Sniff packets and call process_packet for each captured packet
    scapy.sniff(filter=f"tcp and host {target_ip}", prn=process_packet, store=False)

def process_packet(packet):
    if packet.haslayer(HTTPRequest):
        method = packet[HTTPRequest].Method.decode()
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        
        # Extract form data from POST requests if present
        if method == "POST" and packet.haslayer(scapy.Raw):
            form_data = packet[scapy.Raw].load.decode(errors='ignore')
        else:
            form_data = "No form data"

        # Emit the data to the frontend
        if socketio:
            socketio.emit('packet_data', {'url': url, 'method': method, 'form_data': form_data})
