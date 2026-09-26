import httpx
import time
import subprocess
import os

print("Starting API Server...")
server_process = subprocess.Popen([
    ".venv\\Scripts\\python.exe", "-m", "uvicorn", "api.app:app", "--port", "8000"
], env=dict(os.environ, SIH_MODEL_DIR="models/baseline"))

try:
    # Give the server a moment to start
    time.sleep(3)
    
    # 1. Health
    print("\n--- 1. GET /health ---")
    resp = httpx.get("http://127.0.0.1:8000/health")
    print(resp.json())
    
    # 2. Model
    print("\n--- 2. GET /model ---")
    resp = httpx.get("http://127.0.0.1:8000/model")
    print(resp.json())
    
    # 3. Status (Initial)
    print("\n--- 3. GET /status (Initial) ---")
    resp = httpx.get("http://127.0.0.1:8000/status")
    print(resp.json())
    
    # 4. POST /detect (First Packet)
    print("\n--- 4. POST /detect (Packet 1) ---")
    resp = httpx.post("http://127.0.0.1:8000/detect", json={
        "timestamp": 1000.0,
        "length": 100,
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "src_port": 5000,
        "dst_port": 80,
        "protocol": "TCP"
    })
    print(resp.json())
    
    # 5. POST /detect (Second Packet, forces window elapsed if slide=1.0s window=10.0s? 
    # Actually slide is 1.0. Let's send a packet at 1001.1
    print("\n--- 5. POST /detect (Packet 2 - triggering window slide) ---")
    resp = httpx.post("http://127.0.0.1:8000/detect", json={
        "timestamp": 1011.1,
        "length": 200,
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "src_port": 5000,
        "dst_port": 80,
        "protocol": "TCP"
    })
    print(resp.json())
    
    # 6. Status (Final)
    print("\n--- 6. GET /status (Final) ---")
    resp = httpx.get("http://127.0.0.1:8000/status")
    print(resp.json())

finally:
    print("\nShutting down API Server...")
    server_process.terminate()
    server_process.wait()
    print("Done.")
