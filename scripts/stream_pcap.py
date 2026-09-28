import argparse
import asyncio
import json
import time
import websockets
from ingestion.fast_pcap import FastPCAPIngestor
from processing.window import SlidingWindowManager
from processing.features import FeatureExtractor

async def stream_pcap(pcap_path: str, ws_url: str):
    print(f"Connecting to {ws_url}...")
    async with websockets.connect(ws_url) as websocket:
        print("Connected. Streaming PCAP...")
        reader = FastPCAPIngestor(pcap_path)
        window_mgr = SlidingWindowManager(window_seconds=10.0, slide_seconds=1.0)
        extractor = FeatureExtractor()
        
        events_sent = 0
        for pkt_event in reader:
            snapshots = window_mgr.add_packet(pkt_event)
            for snap in snapshots:
                features = extractor.extract_features(snap)
                for flow_id, feats in features.items():
                    # Send an event
                    event = {
                        "type": "flow_update",
                        "flow_id": flow_id,
                        "timestamp": snap.window_start,
                        "features": feats
                    }
                    await websocket.send(json.dumps(event))
                    events_sent += 1
                    
                    if events_sent >= 10:
                        print("Sent 10 events. Stopping for validation.")
                        
                        import pathlib
                        outfile = "reports/websocket_stream_log.json"
                        pathlib.Path(outfile).parent.mkdir(parents=True, exist_ok=True)
                        with open(outfile, "w") as f:
                            json.dump([event], f, indent=2) # Just save the last one to prove it works
                            
                        await asyncio.sleep(1)
                        return

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--pcap", required=True)
    parser.add_argument("--url", default="ws://localhost:8000/ws/telemetry")
    args = parser.parse_args()
    
    asyncio.run(stream_pcap(args.pcap, args.url))
