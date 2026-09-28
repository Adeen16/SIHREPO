import asyncio
import websockets
import json
import subprocess
import time
import pathlib
import sys

async def listen_ws(url: str, outfile: str):
    print(f"Listener connecting to {url}")
    events = []
    try:
        async with websockets.connect(url) as ws:
            while len(events) < 10:
                msg = await asyncio.wait_for(ws.recv(), timeout=5.0)
                events.append(json.loads(msg))
    except Exception as e:
        print(f"Listener error/timeout: {e}")
        
    print(f"Listener got {len(events)} events")

async def main():
    print("Starting uvicorn server...")
    server = subprocess.Popen([sys.executable, "-m", "uvicorn", "fastapi_app.main:app", "--port", "8000"])
    time.sleep(2) # wait for server to start
    
    url = "ws://localhost:8000/ws/telemetry"
    outfile = "reports/websocket_stream_log.json"
    
    # Start the listener
    listener_task = asyncio.create_task(listen_ws(url, outfile))
    
    # Let listener connect
    await asyncio.sleep(1)
    
    # Run the streamer
    pcap = "NTRO-Datasets/PCAPS/01_benign/2013-12-17_capture1.pcap"
    print(f"Starting stream of {pcap}")
    subprocess.run([sys.executable, "scripts/stream_pcap.py", "--pcap", pcap, "--url", url])
    
    await listener_task
    
    print("Terminating server...")
    server.terminate()
    server.wait()
    print("Done validation.")

if __name__ == "__main__":
    asyncio.run(main())
