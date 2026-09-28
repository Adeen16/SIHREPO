# Class Coverage

Based on the `dataset_inventory.json`, the coverage for each PS145 Threat Class is as follows:

| PS145 Class | Status | Dataset & Labels |
| --- | --- | --- |
| **BENIGN** | TRAINABLE | CSE-CIC-IDS2018 (`Benign`), CTU-13 (various `Background`/`Normal` labels), CIC-Darknet2020 (`Non-Tor`, `NonVPN`) |
| **DDOS** | TRAINABLE | CSE-CIC-IDS2018 (`DoS attacks-SlowHTTPTest`, `DoS attacks-Hulk`) |
| **C2_BEACONING** | TRAINABLE | CSE-CIC-IDS2018 (`Bot`), CTU-13 (various `Botnet` labels) |
| **DNS_DGA_TUNNEL** | BLOCKED | CIC-Bell-DNS-EXF-2021 has features but no label column in the CSVs. Requires directory-based labelling. |
| **ENCRYPTED_MALWARE** | TRAINABLE | CIC-Darknet2020 (`Tor`, `VPN`) |
| **RECON_PORT_SCAN** | BLOCKED | No explicit port scan labels identified in the current inventory. |
| **DATA_EXFILTRATION** | TRAINABLE | CSE-CIC-IDS2018 (`Infilteration`), CIC-Bell-DNS-EXF-2021 (implicitly via Attacks) |

**Note**: All classes that were previously evaluated against NTRO PCAPs are now TEST-ONLY for those specific PCAPs, as NTRO PCAPs are designated as a blind test set.
