# SOC Detection Lab - Wazuh SIEM

![Lab Status](https://img.shields.io/badge/Status-Completed-success)
![Platform](https://img.shields.io/badge/Platform-Wazuh-blue)
![OS](https://img.shields.io/badge/OS-Ubuntu-orange)

A hands-on Security Operations Center (SOC) lab demonstrating real-world threat detection and incident response using Wazuh SIEM. This project validates detection capabilities for SSH brute force attacks, privilege escalation, and file integrity monitoring.

## 📋 Table of Contents
- [Overview](#overview)
- [Lab Architecture](#lab-architecture)
- [Attack Scenarios Tested](#attack-scenarios-tested)
- [Key Findings](#key-findings)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Skills Demonstrated](#skills-demonstrated)
- [Setup Instructions](#setup-instructions)
- [Screenshots](#screenshots)
- [Lessons Learned](#lessons-learned)
- [Future Enhancements](#future-enhancements)
- [Resources](#resources)

## 🎯 Overview

This project simulates a production SOC environment where security analysts monitor, detect, and respond to security incidents. The lab focuses on validating Wazuh's detection capabilities across multiple attack vectors commonly seen in real-world breaches.

**Lab Objectives:**
- ✅ Validate SIEM alert generation and correlation
- ✅ Practice incident detection and documentation
- ✅ Map detections to MITRE ATT&CK framework
- ✅ Develop security hardening recommendations
- ✅ Build practical SOC analyst skills

**Date Completed:** January 18, 2026  
**Platform:** Wazuh v4.x (Docker deployment)  
**Monitored Endpoint:** Ubuntu Server (Agent ID: 005)

## 🏗️ Lab Architecture

```
┌─────────────────────────────────────────────┐
│           Wazuh Manager (Docker)            │
│  - Event Processing & Correlation           │
│  - Rule Engine                              │
│  - Dashboard & Alerting                     │
└──────────────────┬──────────────────────────┘
                   │
                   │ Agent Communication
                   │
┌──────────────────▼──────────────────────────┐
│      Monitored Endpoint (soc-server)        │
│  - OS: Ubuntu Server                        │
│  - Agent ID: 005                            │
│  - Log Sources: /var/log/auth.log           │
│  - FIM: /etc directory monitoring           │
└─────────────────────────────────────────────┘
```

**Components:**
- **Wazuh Manager:** Centralized log collection, analysis, and alerting
- **Wazuh Agent:** Installed on Ubuntu endpoint for log forwarding
- **Dashboard:** Web UI for alert visualization and investigation
- **Monitored Services:** SSH, sudo, file integrity monitoring (FIM)

## 🎭 Attack Scenarios Tested

### 1️⃣ SSH Authentication Abuse (Brute Force)
**Objective:** Simulate credential access attempts  
**Technique:** Multiple failed login attempts with invalid usernames  
**Detection Rule:** 5710 (SSH invalid user attempt)  
**MITRE ATT&CK:** T1110.001 (Password Guessing)

### 2️⃣ Privilege Escalation via Sudo
**Objective:** Simulate privilege escalation to root  
**Technique:** Successful sudo execution gaining root access  
**Detection Rule:** 5402 (Successful sudo to ROOT)  
**MITRE ATT&CK:** T1548.003 (Sudo and Sudo Caching)

### 3️⃣ File Integrity Monitoring (FIM)
**Objective:** Detect unauthorized file modifications  
**Technique:** Modified monitored file in /etc directory  
**Detection Rule:** 550 (Integrity checksum changed)  
**MITRE ATT&CK:** T1565.001 (Stored Data Manipulation)

## 🔍 Key Findings

### Detection Success ✅
- **SSH Abuse:** Successfully detected invalid user login attempts and failed authentications
- **Privilege Escalation:** Captured full context including user, command, and session details
- **File Tampering:** FIM detected integrity checksum changes with before/after hash values

### Attack Chain Correlation
The simulation demonstrated a realistic intrusion pattern:
```
1. Initial Access Attempt → SSH brute force (invalid users)
2. Privilege Escalation   → Successful sudo to root
3. Impact/Persistence     → File modification detected
```

### Important Note on Production Deployment
- **Rule 5710** (single invalid user attempt) triggered in this lab
- **Rule 5712** (SSHD brute force aggregation) is the primary production trigger
- Production environments should tune thresholds to distinguish attacks from typos

## 🗺️ MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Wazuh Detection |
|--------|--------------|----------------|-----------------|
| Credential Access | T1110.001 | Password Guessing | SSH failed login attempts |
| Privilege Escalation | T1548.003 | Sudo and Sudo Caching | Successful sudo to root |
| Impact | T1565.001 | Stored Data Manipulation | FIM checksum change |
| Initial Access | T1078 | Valid Accounts | SSH authentication success |

## 💪 Skills Demonstrated

**Technical Skills:**
- SIEM deployment and configuration (Docker-based Wazuh)
- Log analysis and correlation
- Security event investigation
- Rule-based detection engineering
- File integrity monitoring setup

**SOC Analyst Skills:**
- Incident detection and triage
- Evidence collection and documentation
- MITRE ATT&CK framework mapping
- Security hardening recommendations
- Technical report writing

**Tools & Technologies:**
- Wazuh SIEM platform
- Linux system administration (Ubuntu)
- Docker containerization
- Authentication log analysis (/var/log/auth.log)
- Syscheck/FIM configuration

## 🚀 Setup Instructions

### Prerequisites
```bash
# System Requirements
- Ubuntu Server 20.04+ or similar Linux distribution
- Docker & Docker Compose installed
- Minimum 4GB RAM, 2 CPU cores
- 20GB free disk space
```

### Step 1: Deploy Wazuh Manager (Docker)
```bash
# Clone Wazuh Docker repository
git clone https://github.com/wazuh/wazuh-docker.git
cd wazuh-docker/single-node

# Start Wazuh stack
docker-compose up -d

# Verify deployment
docker-compose ps
```

### Step 2: Install Wazuh Agent on Endpoint
```bash
# Download and install agent
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
chmod 644 /usr/share/keyrings/wazuh.gpg

# Add repository
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list

# Install agent
apt-get update
WAZUH_MANAGER="MANAGER_IP" apt-get install wazuh-agent

# Start agent
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent
```

### Step 3: Configure FIM (File Integrity Monitoring)
```bash
# Edit agent configuration
nano /var/ossec/etc/ossec.conf

# Add FIM monitoring for /etc
<syscheck>
  <directories realtime="yes" report_changes="yes">/etc</directories>
</syscheck>

# Restart agent
systemctl restart wazuh-agent
```

### Step 4: Access Wazuh Dashboard
```
URL: https://MANAGER_IP:443
Default credentials: admin / admin (change immediately)
```

## 📸 Screenshots

### Alert Dashboard
![Security Events Timeline](screenshots/dashboard_timeline.png)
*Overview of correlated security events showing the attack chain*

### SSH Brute Force Detection
![SSH Invalid User Alert](screenshots/ssh_invalid_user.png)
*Wazuh detecting SSH authentication abuse with invalid usernames*

### Privilege Escalation Alert
![Sudo to Root](screenshots/sudo_escalation.png)
*Successful privilege escalation event with command context*

### File Integrity Monitoring
![FIM Alert](screenshots/fim_checksum_change.png)
*File modification detected with before/after hash comparison*

## 📚 Lessons Learned

### What Worked Well ✅
- **Real-time Detection:** Wazuh successfully detected all simulated attacks within seconds
- **Rich Context:** Alerts included full event details needed for investigation
- **Integration:** Docker deployment made setup quick and portable
- **Visibility:** Dashboard provided clear timeline and correlation views

### Challenges Faced 🔧
- **Initial Setup:** Required understanding of Docker networking and Wazuh architecture
- **Rule Tuning:** Needed to understand difference between single-event rules and aggregation rules
- **FIM Configuration:** Required proper permission settings for monitored directories

### Key Takeaways 💡
1. **Detection != Prevention:** Monitoring is essential but should be paired with hardening
2. **Context Matters:** Good alerts include who, what, when, where - not just "something happened"
3. **Correlation is Key:** Individual alerts are less valuable than understanding the attack chain
4. **Documentation is Critical:** Without proper documentation, detections lose their value

## 🔮 Future Enhancements

### Planned Improvements
- [ ] Add Windows endpoint for cross-platform detection testing
- [ ] Implement automated response actions (IP blocking, account lockout)
- [ ] Integrate threat intelligence feeds (AbuseIPDB, VirusTotal)
- [ ] Set up correlation rules for automatic incident grouping
- [ ] Add email/Slack alerting for critical events
- [ ] Deploy TheHive for case management integration
- [ ] Create custom detection rules for specific use cases
- [ ] Test evasion techniques and detection bypass scenarios

### Next Lab Scenarios
- Web application attack detection (SQL injection, XSS)
- Malware execution simulation with AMSI/Sysmon
- Lateral movement detection (PsExec, WMI, RDP)
- Data exfiltration monitoring
- Persistence mechanism detection

## 📖 Resources

### Official Documentation
- [Wazuh Documentation](https://documentation.wazuh.com/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Wazuh Rule Reference](https://documentation.wazuh.com/current/user-manual/ruleset/index.html)

### Learning Resources
- [Wazuh GitHub Repository](https://github.com/wazuh/wazuh)
- [Blue Team Labs Online](https://blueteamlabs.online/)
- [SANS Blue Team Reading Room](https://www.sans.org/reading-room/whitepapers/blueteam/)

### Related Projects
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) - Attack simulation
- [Security Onion](https://securityonionsolutions.com/) - Alternative SIEM platform
- [Velociraptor](https://docs.velociraptor.app/) - Endpoint visibility

## 🤝 Contributing

Found an issue or have suggestions? Feel free to:
- Open an issue
- Submit a pull request
- Share your own detection scenarios

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👤 Author

**Karan Singh Samant**
- LinkedIn: www.linkedin.com/in/karan-singh-samant
- GitHub: karansamant821
- Email: karansamant821@gmail.com

---

### ⭐ If you found this project helpful, please consider giving it a star!

*Built with 🛡️ by a cybersecurity enthusiast committed to making the digital world safer*
