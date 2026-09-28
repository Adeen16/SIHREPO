# FlowRecord Feature Specification

The `FlowRecord` is the canonical boundary between data ingestion (from raw PCAPs or CSVs) and feature extraction.

## Canonical Features
| Feature Name | Type | Description | Known Differences (CICFlowMeter/Argus) |
| --- | --- | --- | --- |
| `flow_id` | str | String identifier (`srcIP:srcPort-dstIP:dstPort-Protocol`) | CICFlowMeter might order IP/ports differently. |
| `src_ip` | str | Source IP address (initiator) | |
| `dst_ip` | str | Destination IP address | |
| `src_port` | int | Source Port | |
| `dst_port` | int | Destination Port | |
| `protocol` | str | Protocol (TCP/UDP/etc) | CICFlowMeter outputs protocol number instead of name. |
| `first_seen` | float | Timestamp of first packet (epoch seconds) | CICFlowMeter outputs string dates. |
| `last_seen` | float | Timestamp of last packet (epoch seconds) | |
| `packet_count` | int | Total packets | |
| `byte_count` | int | Total bytes (payload + headers) | CICFlowMeter may exclude L2 headers. |
| `fwd_packet_count`| int | Packets sent from src to dst | |
| `rev_packet_count`| int | Packets sent from dst to src | |
| `fwd_byte_count` | int | Bytes sent from src to dst | |
| `rev_byte_count` | int | Bytes sent from dst to src | |
| `syn_count` | int | Count of SYN flags | |
| `fin_count` | int | Count of FIN flags | |
| `rst_count` | int | Count of RST flags | |
| `ack_count` | int | Count of ACK flags | |
| `psh_count` | int | Count of PSH flags | |
| `fwd_iat_mean` | float | Mean inter-arrival time of forward packets | Argus/CICFlowMeter calculate timeouts and split flows, we use pure windowed state. |
| `fwd_iat_std` | float | Stddev of forward IAT | |
| `rev_iat_mean` | float | Mean inter-arrival time of reverse packets | |
| `rev_iat_std` | float | Stddev of reverse IAT | |
