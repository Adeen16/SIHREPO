# Class Coverage

Based on the `dataset_inventory.json`, the coverage for each PS145 Threat Class is as follows:

| PS145 Class | Status | Dataset & Labels |
| --- | --- | --- |
| **BENIGN** | TRAINABLE | CSE-CIC-IDS2018 (`Benign`), CTU-13 (various `Background`/`Normal` labels), CIC-Darknet2020 (`Non-Tor`, `NonVPN`) |
| **DDOS** | ACTIVE (ML) | CSE-CIC-IDS2018 (`DoS attacks-SlowHTTPTest`, `DoS attacks-Hulk`) |
| **C2_BEACONING** | ACTIVE (Behavioral) | CSE-CIC-IDS2018 (`Bot`), CTU-13 (various `Botnet` labels) |
| **DNS_DGA_TUNNEL** | ACTIVE (Behavioral) | CIC-Bell-DNS-EXF-2021 provides file-level labels via directory structure (Attacks/ vs Benign) for DNS Tunnelling/Exfiltration. |
| **ENCRYPTED_MALWARE** | ACTIVE (Behavioral) | Darknet2020 only has Tor/VPN types, which are not malware. Handled via behavioral TLS metadata analysis. |
| **RECON_PORT_SCAN** | ACTIVE (Behavioral) | Handled via behavioral connection fan-out analysis. |
| **DATA_EXFILTRATION** | ACTIVE (Behavioral) | CSE-CIC-IDS2018 (`Infilteration`), CIC-Bell-DNS-EXF-2021 (implicitly via Attacks). Handled via behavioral volume analysis. |

**Note**: All classes that were previously evaluated against NTRO PCAPs are now TEST-ONLY for those specific PCAPs, as NTRO PCAPs are designated as a blind test set.
