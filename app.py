from flask import Flask, render_template, request
from detector import SQLShield
from datetime import datetime

app = Flask(__name__)
guard = SQLShield()

def log_incident(ip_address, payload, threats):
    with open("security_logs.txt", "a", encoding="utf-8") as f:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        details = [f"{t['type']}: {t['attack_type']}" for t in threats]
        f.write(f"[{timestamp}] [IP: {ip_address}] [ALARM] Threats: {details} | Payload: {payload}\n")

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    attacker_ip = request.headers.get('X-Forwarded-For', request.remote_addr)

    if request.method == 'POST':
        payload = request.form.get('payload')
        threats = guard.scan(payload)
        
        if threats:
            log_incident(attacker_ip, payload, threats)
            result = {"status": "danger", "data": threats}
        else:
            result = {"status": "success", "data": "No threats detected."}
            
    return render_template('index.html', result=result)

@app.route('/logs')
def view_logs():
    logs = []
    try:
        with open("security_logs.txt", "r", encoding="utf-8") as f:
            lines = f.readlines()[::-1]
            for line in lines:
                logs.append(line.strip())
    except FileNotFoundError:
        logs = ["No incidents logged yet."]
    return render_template('logs.html', logs=logs)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)