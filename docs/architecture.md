# Project Architecture

## Ingestion Layer (Phase 3)

The first stage of the ECDAT detection pipeline is the passive PCAP ingestion layer. It is designed to read captured network traffic from files (PCAP/PCAPNG) and emit a stream of packet events.

### Workflow
```
Controlled PCAP
      ↓
Passive PCAP Ingestion (ingestion/pcap_reader.py)
      ↓
Timestamped Packet Events (ingestion/packet_event.py)
      ↓
Future Flow Processing
```

### Details
- **Supported Formats**: PCAP and PCAPNG (handled via Scapy's PcapReader).
- **Packet Event Fields**: 
  - `timestamp`: Original capture time (preserved for precise flow timing).
  - `length`: Raw packet size.
  - `raw_packet`: Underlying Scapy object.
  - Basic IP/Transport metadata (`src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`) extracted cleanly.
- **Limitations**:
  - The ingestion layer is purely read-only and will never transmit packets.
  - It does not extract complex ML features or threat intelligence, only raw network observations.
- **Connecting to Flow Processing**:
  The `PCAPIngestor` implements an iterator that yields `PacketEvent` instances. The future flow processing layer can consume this transparently:
  ```python
  for event in ingestor:
      flow_processor.add(event)
  ```
