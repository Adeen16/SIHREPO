# Class Coverage

Based on the `dataset_inventory.json`, the coverage for each PS145 Threat Class is as follows:

| PS145 Class | Status | Dataset & Labels |
| --- | --- | --- |
| **BENIGN** | TRAINABLE | CSE-CIC-IDS2018 (`Benign`), CTU-13 (various `Background`/`Normal` labels), CIC-Darknet2020 (`Non-Tor`, `NonVPN`) |
| **DDOS** | TRAINABLE | CSE-CIC-IDS2018 (`DoS attacks-SlowHTTPTest`, `DoS attacks-Hulk`) |
| **C2_BEACONING** | TRAINABLE | CSE-CIC-IDS2018 (`Bot`), CTU-13 (various `Botnet` labels) |
| **DNS_DGA_TUNNEL** | BLOCKED (DGA) / TRAINABLE (Tunnelling/Exfil) | CIC-Bell-DNS-EXF-2021 provides file-level labels via directory structure (Attacks/ vs Benign) for DNS Tunnelling/Exfiltration. DGA is BLOCKED. |
| **ENCRYPTED_MALWARE** | BLOCKED (test-only) | Darknet2020 only has Tor/VPN types, which are not malware. No training data available. |
| **RECON_PORT_SCAN** | BLOCKED | No explicit port scan labels identified in the current inventory. |
| **DATA_EXFILTRATION** | TRAINABLE | CSE-CIC-IDS2018 (`Infilteration`), CIC-Bell-DNS-EXF-2021 (implicitly via Attacks) |

**Note**: All classes that were previously evaluated against NTRO PCAPs are now TEST-ONLY for those specific PCAPs, as NTRO PCAPs are designated as a blind test set.
