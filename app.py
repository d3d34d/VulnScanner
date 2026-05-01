from flask import Flask, render_template, request, jsonify
from scanner.main import VulnScanner
import threading
import uuid

app = Flask(__name__)

# Basic in-memory store for scan results
scan_results = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def run_scan():
    data = request.json
    target = data.get('target')
    if not target:
        return jsonify({"error": "Target is required"}), 400
        
    scan_id = str(uuid.uuid4())
    scan_results[scan_id] = {"status": "running", "results": None}
    
    # Vercel does not support background threads in Python Serverless functions.
    # We must run it synchronously before sending the response.
    try:
        # Limited ports for web interface to avoid Vercel 10s timeout
        ports = [80, 443]
        scanner = VulnScanner(target=target, ports=ports, crawl_depth=1, output_file=None)
        scanner.run()
        scan_results[scan_id]["status"] = "completed"
        scan_results[scan_id]["results"] = scanner.results
    except Exception as e:
        scan_results[scan_id]["status"] = "error"
        scan_results[scan_id]["error"] = str(e)
            
    return jsonify({"scan_id": scan_id})

@app.route('/api/scan/<scan_id>', methods=['GET'])
def get_scan_status(scan_id):
    if scan_id not in scan_results:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify(scan_results[scan_id])

if __name__ == '__main__':
    app.run(debug=True, port=5001)
