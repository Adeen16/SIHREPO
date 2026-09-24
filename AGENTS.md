============================================================
PROJECT IDENTITY
============================================================

Project:

AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

SIH Problem Statement:

26145

Organization:

National Technical Research Organisation (NTRO)

Theme:

Blockchain & Cybersecurity

Category:

Software

============================================================
1. CORE OBJECTIVE
============================================================

Build an AI/ML-based cyber-threat detection pipeline capable of monitoring a one-directional stream of IP traffic in near real time.

The system receives traffic or traffic-derived metadata from a monitoring enclave.

The system must detect, classify, and score cybersecurity threats using ONLY passively collected information.

The monitoring system must assume that it cannot communicate back with the observed traffic source or destination.

The system must therefore operate without:

- active probing
- packet injection
- handshake completion initiated by the detector
- response packets
- mitigation commands
- direct interaction with the production network

The detector is a READ-ONLY intelligence layer.

============================================================
2. FUNDAMENTAL ARCHITECTURE
============================================================

The intended logical pipeline is:

ONE-WAY TRAFFIC
        ↓
PASSIVE INGESTION
        ↓
PACKET / FLOW PROCESSING
        ↓
SLIDING-WINDOW STREAM PROCESSING
        ↓
FEATURE EXTRACTION
        ↓
AI/ML DETECTION
        ↓
THREAT CLASSIFICATION
        ↓
CONFIDENCE SCORING
        ↓
SEVERITY ASSESSMENT
        ↓
SUPPORTING EVIDENCE
        ↓
ALERT GENERATION
        ↓
VISUALIZATION DASHBOARD

All new code must fit into this architecture unless there is a documented technical reason to change it.

============================================================
3. PASSIVE / UNIDIRECTIONAL REQUIREMENT
============================================================

This is a NON-NEGOTIABLE requirement.

The monitoring system must behave as though it is connected to a unidirectional data feed or monitoring enclave.

The detection system may:

- receive packets
- receive PCAP data
- receive exported flow records
- receive derived metadata
- process observed traffic
- calculate features
- perform ML inference
- generate alerts
- display information

The detection system must NOT:

- send packets to monitored hosts
- ping hosts
- perform port scans
- initiate TCP connections to monitored hosts
- initiate DNS queries to investigate traffic
- perform active reconnaissance
- inject packets
- modify packets in transit
- send mitigation commands
- block hosts through the monitored network
- perform automated remediation
- contact the original traffic source for additional information

Any future mitigation functionality must remain outside the base passive detector.

============================================================
4. ENCRYPTED TRAFFIC REQUIREMENT
============================================================

The system must NOT depend on decrypting TLS or QUIC payloads.

TLS/QUIC traffic must be analysed using observable metadata.

Possible metadata/features include:

- connection timing
- packet sizes
- packet-size sequences
- flow duration
- directionality
- packet counts
- byte counts
- TLS/QUIC metadata
- JA3/JA3S/JA4 where available
- statistical characteristics

Never design the base system around decrypting protected payloads.

============================================================
5. STREAMING REQUIREMENT
============================================================

The system must be designed as a streaming detection pipeline.

Do NOT design the primary architecture as:

UPLOAD CSV
    ↓
LOAD ENTIRE DATASET
    ↓
RUN MODEL ONCE
    ↓
DISPLAY RESULTS

The intended model is:

TRAFFIC EVENT
    ↓
FLOW STATE
    ↓
SLIDING TIME WINDOW
    ↓
FEATURE UPDATE
    ↓
MODEL INFERENCE
    ↓
ALERT / NO ALERT
    ↓
NEXT WINDOW

PCAP files and datasets may be used as controlled replay sources for development and demonstration.

A PCAP replay must conceptually behave as a traffic stream.

============================================================
6. REQUIRED THREAT CATEGORIES
============================================================

The base system must support detection of these six required threat categories:

1. VOLUMETRIC / PROTOCOL DDoS
2. BOTNET C2 BEACONING
3. DGA / DNS TUNNELLING
4. MALWARE IN ENCRYPTED SESSIONS
5. RECONNAISSANCE / PORT SCANNING
6. DATA EXFILTRATION

BENIGN traffic must also be represented.

The initial conceptual labels should therefore be:

BENIGN
DDoS
C2_BEACONING
DNS_DGA_TUNNEL
ENCRYPTED_MALWARE
RECON_PORT_SCAN
DATA_EXFILTRATION

Do not invent unrelated threat categories unless explicitly required later.

============================================================
7. THREAT-SPECIFIC DETECTION FEATURES
============================================================

The feature-engineering layer should be designed to support the following.

------------------------------------------------------------
DDoS
------------------------------------------------------------

Potential features:

- packets per second
- bytes per second
- flow count
- packet count
- source IP count
- source IP entropy
- destination concentration
- SYN rate
- UDP rate
- burst characteristics
- protocol distribution

------------------------------------------------------------
C2 BEACONING
------------------------------------------------------------

Potential features:

- inter-arrival time
- mean inter-arrival time
- standard deviation of inter-arrival time
- periodicity
- connection frequency
- destination repetition
- flow duration
- timing regularity

------------------------------------------------------------
DGA / DNS TUNNELLING
------------------------------------------------------------

Potential features:

- domain length
- character distribution
- domain entropy
- digit/letter ratio
- n-gram characteristics
- query frequency
- query length
- unusual DNS record behaviour
- encoded-looking subdomains

------------------------------------------------------------
ENCRYPTED MALWARE
------------------------------------------------------------

Potential features:

- TLS/QUIC metadata
- JA3/JA3S/JA4 where available
- packet-size patterns
- packet timing
- flow duration
- packet count
- byte count
- directionality
- session characteristics

Do NOT require payload decryption.

------------------------------------------------------------
RECONNAISSANCE / PORT SCANNING
------------------------------------------------------------

Potential features:

- unique destination ports
- unique destination IPs
- connection attempts
- fan-out
- port diversity
- connection frequency
- time-window concentration
- source-to-destination relationship

------------------------------------------------------------
DATA EXFILTRATION
------------------------------------------------------------

Potential features:

- outbound bytes
- inbound bytes
- outbound/inbound ratio
- flow duration
- sustained outbound volume
- destination frequency
- packet count
- unusual transfer patterns

============================================================
8. FEATURE ENGINEERING
============================================================

Prefer flow/window-level behavioural features over simplistic packet-level classification.

Features must be:

- numerically valid
- reproducible
- explainable
- available from passive observation
- appropriate to the relevant traffic protocol
- documented

Do not create features that require information unavailable to a passive monitoring system.

Every feature used by the ML model must be documented.

============================================================
9. ML ARCHITECTURE
============================================================

The system must contain a real ML inference component.

The initial architecture may use:

- supervised classification
- anomaly detection
- hybrid classification + anomaly detection

Suitable initial models may include:

- Random Forest
- XGBoost
- Isolation Forest
- other lightweight models if justified

Do NOT select a complex deep-learning architecture merely for presentation value.

Model selection must be based on:

- accuracy
- precision
- recall
- F1
- inference latency
- robustness
- interpretability
- suitability for streaming inference

Do not fabricate model performance.

============================================================
10. CONFIDENCE AND SEVERITY
============================================================

Every generated alert must contain at minimum:

- timestamp
- flow identity
- source information available from observed traffic
- destination information available from observed traffic
- threat class
- confidence
- severity
- supporting evidence

Example conceptual alert:

{
    "timestamp": "...",
    "flow_id": "...",
    "threat_class": "RECON_PORT_SCAN",
    "confidence": 0.94,
    "severity": "HIGH",
    "evidence": {
        "unique_destination_ports": 47,
        "connection_attempts": 182,
        "window_seconds": 5
    }
}

This is an example schema, not fabricated output.

============================================================
11. EVIDENCE / EXPLAINABILITY
============================================================

The system must not merely output:

"Attack detected."

It should provide evidence describing why the alert was generated.

For example:

Threat:
RECON_PORT_SCAN

Confidence:
94%

Evidence:

- 47 unique destination ports
- 182 connection attempts
- 5-second observation window
- abnormal port distribution

Evidence must come from actual observed/calculated features.

Never fabricate evidence.

============================================================
12. DASHBOARD REQUIREMENTS
============================================================

The dashboard must visualize the streaming detection process.

At minimum it should eventually show:

- current traffic rate
- packets/sec
- flows/sec
- total alerts
- active threat count
- threat category distribution
- severity
- confidence
- timestamp
- source/destination information where available
- supporting evidence
- recent alerts
- traffic trends

The dashboard must make it obvious that the detector is operating passively.

Suggested high-level sections:

TRAFFIC OVERVIEW

THREAT DISTRIBUTION

LIVE ALERTS

THREAT TIMELINE

ALERT DETAILS

SYSTEM PERFORMANCE

============================================================
13. THROUGHPUT / PERFORMANCE
============================================================

The system must measure its actual processing capability.

Possible measurements:

- packets/sec
- flows/sec
- Mbps
- feature extraction latency
- inference latency
- end-to-end detection latency

Never hard-code impressive-looking performance numbers.

Performance values shown in the dashboard must come from actual measurements.

============================================================
14. DATA
============================================================

The problem statement references synthetic/lab-generated traffic including:

BENIGN:

- iperf3
- Ostinato
- TRex

ATTACK / LAB TRAFFIC:

- hping3
- Slowloris
- DNS tunnelling / iodine-style traffic
- DGA samples/algorithms
- other controlled datasets where appropriate

The development system may also use PCAP datasets and exported flow records.

All attack traffic must be generated or replayed only in controlled environments.

Never target external systems.

============================================================
15. DATA PIPELINE
============================================================

The intended data pipeline is:

RAW TRAFFIC / PCAP
        ↓
PACKET PARSER
        ↓
FLOW IDENTIFICATION
        ↓
FLOW STATE
        ↓
SLIDING WINDOW
        ↓
FEATURE EXTRACTION
        ↓
FEATURE NORMALIZATION / PREPROCESSING
        ↓
ML MODEL
        ↓
PREDICTION
        ↓
CONFIDENCE
        ↓
SEVERITY
        ↓
EVIDENCE
        ↓
ALERT

Each stage must remain modular.

============================================================
16. PROJECT STRUCTURE
============================================================

Preferred structure:

ingestion/
    packet_reader.py
    pcap_reader.py
    stream.py

processing/
    flow.py
    window.py
    features.py

detection/
    classifier.py
    anomaly.py
    inference.py
    preprocessing.py

alerts/
    schema.py
    engine.py

api/
    main.py
    websocket.py

dashboard/
    ...

datasets/
    README.md

models/
    README.md

scripts/
    ...

tests/
    ...

docs/
    architecture.md
    features.md
    model.md
    testing.md

============================================================
17. TECHNOLOGY STACK
============================================================

Initial backend:

Python

Network processing:

Scapy
PyShark where required

Data:

NumPy
Pandas

Machine learning:

scikit-learn
XGBoost where justified

Model persistence:

joblib or appropriate format

API:

FastAPI
Uvicorn

Real-time communication:

WebSockets

Frontend:

React
Vite

Styling:

Tailwind CSS if useful

Version control:

Git

============================================================
18. CODING RULES
============================================================

All code must be:

- modular
- typed where practical
- testable
- documented
- readable
- deterministic where possible
- easy to debug

Avoid:

- giant files
- giant functions
- duplicated logic
- hard-coded paths
- hard-coded model outputs
- fake metrics
- fake traffic
- fake confidence scores
- placeholder detections presented as real detections

Temporary mocks are allowed during early development, but they must be clearly marked as MOCK/SIMULATION and must later be replaceable with real components.

============================================================
19. DEVELOPMENT ORDER
============================================================

Do NOT attempt to build everything simultaneously.

Build in this order:

PHASE 1:
Environment

PHASE 2:
Project structure

PHASE 3:
PCAP/traffic ingestion

PHASE 4:
Flow construction

PHASE 5:
Sliding-window streaming engine

PHASE 6:
Feature extraction

PHASE 7:
Baseline detection pipeline

PHASE 8:
Dataset preprocessing

PHASE 9:
ML training

PHASE 10:
ML inference

PHASE 11:
Confidence/severity/evidence

PHASE 12:
FastAPI backend

PHASE 13:
WebSocket streaming

PHASE 14:
React dashboard

PHASE 15:
Performance measurement

PHASE 16:
End-to-end testing

Do not skip directly from Phase 2 to a polished dashboard.

============================================================
20. TESTING RULES
============================================================

Every major component must eventually have tests.

At minimum test:

- packet parsing
- flow identification
- window aggregation
- feature extraction
- preprocessing
- model inference
- alert generation
- API endpoints
- WebSocket events

Include benign and malicious controlled traffic cases.

============================================================
21. SECURITY BOUNDARIES
============================================================

The project is intended for authorized cybersecurity research and controlled demonstrations.

Never:

- attack external systems
- scan public IP addresses
- deploy persistence
- steal credentials
- capture unrelated users' traffic
- perform unauthorized reconnaissance
- send attack traffic outside a controlled lab
- disable host security controls
- implement autonomous destructive actions

The detector itself must remain passive.

============================================================
22. AI AGENT BEHAVIOUR
============================================================

Any AI coding agent working on this repository must:

1. Read AGENTS.md before making architectural changes.
2. Preserve the passive/unidirectional design.
3. Preserve the six required threat categories.
4. Never silently change the technology architecture.
5. Never fabricate datasets, model accuracy, confidence, evidence, or throughput.
6. Clearly mark mocks and simulations.
7. Explain major architectural changes in code comments or documentation.
8. Prefer the simplest technically valid implementation.
9. Test code after significant changes.
10. Avoid unnecessary dependencies.
11. Never add active network behaviour to the detector.
12. Never assume encrypted payloads can be inspected.
13. Never claim SIH/NTRO compliance without verifying the relevant requirement.
14. Keep the system demonstrable on controlled PCAP/synthetic traffic.
15. Maintain a clear separation between ingestion, processing, detection, alerting, API, and presentation.

============================================================
23. DEFINITION OF DONE FOR THE BASE PROTOTYPE
============================================================

The base prototype is NOT considered complete merely because the dashboard works.

The minimum functional chain must be:

CONTROLLED TRAFFIC / PCAP
        ↓
PASSIVE INGESTION
        ↓
STREAMING FLOW PROCESSING
        ↓
FEATURE EXTRACTION
        ↓
ML INFERENCE
        ↓
THREAT CLASSIFICATION
        ↓
CONFIDENCE
        ↓
SEVERITY
        ↓
SUPPORTING EVIDENCE
        ↓
REAL-TIME ALERT
        ↓
DASHBOARD

The system must demonstrate the six required threat categories plus benign traffic.

The system must operate without communicating back with the monitored traffic source/destination.

The system must report measured processing performance.

============================================================
24. IMPORTANT PRIORITY
============================================================

When forced to choose between:

A. a visually impressive feature

and

B. satisfying an actual NTRO requirement,

ALWAYS prioritize B.

When forced to choose between:

A. a complex AI architecture

and

B. a reliable, explainable, testable detection pipeline,

prioritize B.

The objective is to build a technically credible implementation of the actual problem statement before adding differentiating features.

============================================================
END OF AGENTS.MD SPECIFICATION
