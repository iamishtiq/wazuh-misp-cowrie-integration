# SOC Lab: Wazuh SIEM Integration with MISP Threat Intelligence & Cowrie Honeypot


## Project Overview
This project demonstrates a real-world **Security Operations Center (SOC)** workflow by integrating:

- **Wazuh SIEM** for log collection, correlation, and alerting  
- **MISP (Malware Information Sharing Platform)** for external threat intelligence  
- **Cowrie SSH Honeypot** for deception-based attack detection  

The objective is to detect live attacks, enrich alerts with threat intelligence, and analyze attacker behavior in a controlled lab environment, similar to enterprise SOC operations.

---

## 🎯 Objectives
- Integrate MISP threat intelligence with Wazuh SIEM  
- Deploy a Cowrie SSH honeypot to capture real attack activity  
- Correlate honeypot events with MISP Indicators of Compromise (IOCs)  
- Analyze enriched alerts in the Wazuh Dashboard  
- Understand how threat intelligence and deception improve SOC detection and response  

---
## 🛠️ Skills Demonstrated
- SIEM deployment and log correlation (Wazuh)
- Threat intelligence ingestion and IOC enrichment (MISP)
- Honeypot deployment and deception-based detection
- Custom decoder and rule creation
- Attack simulation and adversary behavior analysis
- SOC alert triage and severity classification
- Linux system administration (Ubuntu Server)
- Incident detection lifecycle (Detect → Enrich → Analyze)


## 🏗️ Architecture Overview
This lab simulates an enterprise SOC architecture where external intelligence and live attack data are combined to improve detection accuracy.

### 🔹 Architecture Flow
- Attacks are launched from a Kali Linux attacker machine  
- The Cowrie SSH honeypot captures malicious activity (brute-force attempts, login behavior)  
- Logs are forwarded via Wazuh Agent  
- Wazuh Manager analyzes logs and applies detection rules  
- MISP enriches alerts with threat intelligence (malicious IPs, domains)  
- Correlated alerts are visualized in the Wazuh Dashboard  

📸 Architecture Diagrams:
- [Detailed SOC Architecture Diagram](screenshots/architecture/01-daigram.png)
- [Simplified SOC Architecture Diagram](screenshots/architecture/02-simple-daigram.png)


---

## 🧱 Components Used

| Component | Purpose |
|--------|--------|
| Wazuh SIEM | Central log collection, correlation, and alerting |
| MISP (Docker-based) | Threat intelligence sharing platform |
| Cowrie SSH Honeypot | Deception technology to attract attackers |
| Kali Linux | Attack simulation (SSH brute-force) |
| Oracle VirtualBox | Lab virtualization environment |

---

## 🖥️ Lab Environment

| System | Role |
|------|------|
| Ubuntu Server | Wazuh Manager |
| Ubuntu Server | Cowrie Honeypot + Wazuh Agent |
| Ubuntu Server | MISP (Docker) |
| Kali Linux | Attacker Machine |

📸 Lab Environment:
- [VirtualBox Lab Environment Setup](screenshots/environment/03-enviremantal-setup.png)


---

## 🔗 MISP Setup & Threat Intelligence

### 🔹 MISP Deployment
- MISP deployed on Ubuntu Server using Docker  
- Docker used for isolation, stability, and easy maintenance  
- Web interface accessed via local lab IP  

📸 MISP Installation & Setup:
- [Update Ubuntu Server](screenshots/misp/04-update-ubuntu-server.png)
- [Install Docker](screenshots/misp/05-install-docker.png)
- [Install Docker & Docker Compose](screenshots/misp/06-install-docker-and-docker-compose.png)
- [Check Docker Service Status](screenshots/misp/07-check-docker-status.png)
- [Run Docker Test Image](screenshots/misp/08-run-docker-image.png)
- [Docker Version Verification](screenshots/misp/09-docker-version.png)
- [Install MISP (Docker)](screenshots/misp/10-install-misp.png)
- [Configure .env File](screenshots/misp/11-configure-envfile.png)
- [.env File Configuration](screenshots/misp/12-env-file.png)
- [Pull MISP Docker Images](screenshots/misp/13-pull-docker.png)
- [Start MISP Containers](screenshots/misp/14-up-docker.png)
- [Verify Running Containers (docker ps)](screenshots/misp/15-docker-ps.png)
- [Access MISP Web Interface](screenshots/misp/16-misp-access.png)


---

### 🔹 Enabled Threat Feeds
The following feeds were enabled to ingest high-quality threat intelligence:

- **Botvrij.eu** – Botnet and C2 infrastructure  
- **Feodo Tracker** – Banking trojans (Dridex / Feodo)  
- **URLhaus** – Malicious URLs and malware distribution  

📸 MISP Threat Feeds:
- [Enable Threat Feed – Botvrij / Feodo / URLhaus](screenshots/misp/17-enable-feed.png)
- [Threat Feed Enabled (Additional View)](screenshots/misp/18-enable-feed-2.png)


---

### 🔹 MISP API Integration with Wazuh
- A dedicated MISP API key was generated for the Wazuh server  
- Wazuh uses this key to fetch IOCs securely  
- Indicators include malicious IP addresses, domains, and URLs  

📸 MISP API & Wazuh Integration:
- [Generate MISP API Key](screenshots/misp/19-get-api-key.png)



---

## ⚙️ Wazuh Integration with MISP
- Custom MISP integration script created in `/var/ossec/integrations.`  
- Wazuh is configured to query MISP during event analysis  
- Custom rules added to generate alerts on IOC matches  
- Wazuh Manager restarted to apply changes  

📸 MISP API & Wazuh Integration:
- [Custom MISP Integration create](screenshots/misp/20-create-custom-misp.png)
- [Custom MISP Integration Script Content](screenshots/misp/21-content-of-custom-misp.png)
- [Add Integration Block in ossec.conf](screenshots/misp/22-add-integration-block-in-ossec.conf.png)
- [Restart Wazuh Manager & Check Status](screenshots/misp/23-restart-manager-and-status.png)
- [Create Custom MISP Rules in Wazuh](screenshots/misp/24-create-rules.png)

---

## 🐝 Cowrie Honeypot Setup

### 🔹 Honeypot Deployment
- Cowrie SSH honeypot deployed on Ubuntu Server  
- SSH service enabled on port `2222.`  
- Python virtual environment used for dependency isolation  

📸 Cowrie Installation & Setup:
- [Update Ubuntu Server for Cowrie](screenshots/cowrie/25-update-ubuntu-server-for-cowrie.png)
- [Install Python Requirements](screenshots/cowrie/26-install-python-requriements.png)
- [Clone Cowrie Repository](screenshots/cowrie/27-clone-cowrie.png)
- [Create & Activate Virtual Environment](screenshots/cowrie/28-create-env-and-activite.png)
- [Install Cowrie Dependencies](screenshots/cowrie/29-install-requreiments.txt.png)
- [Edit Cowrie Configuration File](screenshots/cowrie/30-edit-cowrie.cfg.png)
- [Start Cowrie Honeypot](screenshots/cowrie/31-start-cowrie.png)


---

### 🔹 Log Collection with Wazuh Agent
- Wazuh Agent installed on Cowrie server  
- Cowrie log file (`cowrie.json`) added to `ossec.conf.`  
- Agent forwards honeypot logs in real time  

📸 Cowrie Log Collection:
- [Add cowrie.json in ossec.conf](screenshots/cowrie/32-add-cowrie.json-in-ossec.conf.png)
- [Restart Wazuh Agent](screenshots/cowrie/33-restart-agent.png)
- [Create Custom Decoder for Cowrie](screenshots/cowrie/34-create-decoder-for-cowrie.png)
- [Create Custom Rules for Cowrie](screenshots/cowrie/35-create-rules.png)
- [Wazuh Agent Monitoring cowrie.json](screenshots/cowrie/36-show-agent-monitoring-cowrie.json.png)


---

## ⚔️ Attack Simulation
- SSH brute-force attack simulated from Kali Linux  
- Hydra tool used with `rockyou.txt` wordlist  
- Attack traffic targeted Cowrie on port `2222`  
- Generated high-volume malicious authentication attempts  

📸 Attack Simulation:
- [SSH Brute-force Attack from Kali Linux](screenshots/attacks/37-attack-from-kali.png)


---

## 🚨 Detection & Alerting in Wazuh
This section demonstrates how raw honeypot logs were transformed into actionable SOC alerts through decoding, rule logic, and threat intelligence correlation.


### 🔹 Honeypot Detection
- Cowrie logs decoded using custom decoders  
- Custom rules detect:
  - SSH brute-force attempts  
  - Repeated authentication failures  
  - Suspicious login behavior  

- [Raw Cowrie JSON Logs](screenshots/correlation/38-cowrie.json-logs.png)
- [Cowrie Logs in Wazuh Dashboard](screenshots/correlation/39-cowrie-logs-in-wazuh-dashboard.png)
- [Detailed Cowrie Event View](screenshots/correlation/40-cowrie-logs-details.png)


---

### 🔹 MISP Correlation
- Attacker IPs matched against MISP IOCs  
- Alerts enriched with:
  - Threat status  
  - IOC category  
  - Severity level  
- Both malicious and non-malicious IPs observed  

- [MISP Logs in Wazuh](screenshots/correlation/41-misp-logs-wazuh.png)
- [Cowrie + MISP Correlated Logs](screenshots/correlation/42-cowrie-and-misp-logs.png)
- [Malicious IP Detected via MISP](screenshots/correlation/43-ip-malicous-log-in-wazuh-by-misp.png)
- [IOC Match Alert in Wazuh](screenshots/correlation/44-IOC-match-logs-in-wazuh-by-misp.png)
- [Normal Private IP (No IOC Match)](screenshots/correlation/45-normal-private-ip-logs-in-wazuh-by-misp.png)


  ---

## 🧩 MITRE ATT&CK Mapping

The detected attack activity and alerts in this lab were mapped to the MITRE ATT&CK framework to align with standard SOC threat classification.

| Tactic | Technique ID | Technique Name | Evidence |
|------|------------|---------------|---------|
| Credential Access | T1110 | Brute Force | SSH brute-force attempts captured by Cowrie |
| Lateral Movement | T1021 | Remote Services (SSH) | Unauthorized SSH access attempts |
| Initial Access | T1078 | Valid Accounts (Simulated) | Repeated credential guessing behavior |

This mapping helps us understand attacker intent, improve detection coverage, and standardize incident reporting.

---


## 📊 Analysis & Findings

### 🔍 Observed Attacks
- SSH brute-force attacks  
- Automated credential guessing  
- Repeated authentication failures  

### 🔍 Indicators Detected
- Known malicious IPs from MISP feeds  
- Network-based IOCs  
- Suspicious login behavior  

### 🔍 Alert Severity
- **High severity:** Cowrie activity + MISP IOC match  
- **Medium severity:** Brute-force activity without IOC match  
- **Low severity:** Benign or internal IP activity  

---

## 🧠 SOC Relevance
This integration demonstrates how:
- Threat intelligence improves detection accuracy  
- Honeypots provide high-fidelity attack data  
- Correlation reduces false positives  
- SOC analysts gain context-rich alerts for faster response  

---

## 📚 Key Learnings
- Practical use of MISP in SOC workflows  
- Deception-based security using honeypots  
- IOC enrichment for alert prioritization  
- End-to-end SOC detection and analysis process  

---

## 📄 Full Documentation
A detailed step-by-step implementation report, configurations, and explanations are available in:

📄 **Full Documentation Report**  
(See `Complete Documentation lab by ishtiaq.pdf` in this repository)



---

## Created by:
**Ishtiaq Rashid**  
Cybersecurity | SOC Analyst Aspirant 

