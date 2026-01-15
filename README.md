# 🔐 Wazuh + MISP + Cowrie Honeypot Integration (SOC Lab)

## 📌 Project Overview
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

## 🏗️ Architecture Overview
This lab simulates an enterprise SOC architecture where external intelligence and live attack data are combined to improve detection accuracy.

### 🔹 Architecture Flow
- Attacks are launched from a Kali Linux attacker machine  
- The Cowrie SSH honeypot captures malicious activity (brute-force attempts, login behavior)  
- Logs are forwarded via Wazuh Agent  
- Wazuh Manager analyzes logs and applies detection rules  
- MISP enriches alerts with threat intelligence (malicious IPs, domains)  
- Correlated alerts are visualized in the Wazuh Dashboard  

📸 **Screenshot:**  
`Architecture Diagram – Add Link Here`

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

📸 **Screenshot:**  
`VirtualBox Running Machines – Add Link Here`

---

## 🔗 MISP Setup & Threat Intelligence

### 🔹 MISP Deployment
- MISP deployed on Ubuntu Server using Docker  
- Docker used for isolation, stability, and easy maintenance  
- Web interface accessed via local lab IP  

📸 **Screenshot:**  
`MISP Web Interface – Add Link Here`

---

### 🔹 Enabled Threat Feeds
The following feeds were enabled to ingest high-quality threat intelligence:

- **Botvrij.eu** – Botnet and C2 infrastructure  
- **Feodo Tracker** – Banking trojans (Dridex / Feodo)  
- **URLhaus** – Malicious URLs and malware distribution  

📸 **Screenshot:**  
`MISP Feeds Enabled – Add Link Here`

---

### 🔹 MISP API Integration with Wazuh
- A dedicated MISP API key was generated for the Wazuh server  
- Wazuh uses this key to fetch IOCs securely  
- Indicators include malicious IP addresses, domains, and URLs  

📸 **Screenshot:**  
`MISP API Key Configuration – Add Link Here`

---

## ⚙️ Wazuh Integration with MISP
- Custom MISP integration script created in `/var/ossec/integrations`  
- Wazuh configured to query MISP during event analysis  
- Custom rules added to generate alerts on IOC matches  
- Wazuh Manager restarted to apply changes  

📸 **Screenshot:**  
`Wazuh MISP Integration Config – Add Link Here`

---

## 🐝 Cowrie Honeypot Setup

### 🔹 Honeypot Deployment
- Cowrie SSH honeypot deployed on Ubuntu Server  
- SSH service enabled on port `2222`  
- Python virtual environment used for dependency isolation  

📸 **Screenshot:**  
`Cowrie Running Status – Add Link Here`

---

### 🔹 Log Collection with Wazuh Agent
- Wazuh Agent installed on Cowrie server  
- Cowrie log file (`cowrie.json`) added to `ossec.conf`  
- Agent forwards honeypot logs in real time  

📸 **Screenshot:**  
`Wazuh Agent Monitoring Cowrie Logs – Add Link Here`

---

## ⚔️ Attack Simulation
- SSH brute-force attack simulated from Kali Linux  
- Hydra tool used with `rockyou.txt` wordlist  
- Attack traffic targeted Cowrie on port `2222`  
- Generated high-volume malicious authentication attempts  

📸 **Screenshot:**  
`Hydra SSH Brute-force – Add Link Here`

---

## 🚨 Detection & Alerting in Wazuh

### 🔹 Honeypot Detection
- Cowrie logs decoded using custom decoders  
- Custom rules detect:
  - SSH brute-force attempts  
  - Repeated authentication failures  
  - Suspicious login behavior  

📸 **Screenshot:**  
`Cowrie Alerts in Wazuh – Add Link Here`

---

### 🔹 MISP Correlation
- Attacker IPs matched against MISP IOCs  
- Alerts enriched with:
  - Threat status  
  - IOC category  
  - Severity level  
- Both malicious and non-malicious IPs observed  

📸 **Screenshot:**  
`MISP IOC Match Alert – Add Link Here`  

📸 **Screenshot:**  
`Non-Matching IP Alert – Add Link Here`

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
Full internship report available in:


---

## 👨‍💻 Author
**Ishtiaq “Wolf” Rashid**  
Cybersecurity | SOC Analyst (Entry-Level)  
📍 Pakistan

