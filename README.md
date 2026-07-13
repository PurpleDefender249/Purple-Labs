# SOC & Threat Hunting Lab Course
### From Attack Simulation to Detection Engineering — A 9-Lab Hands-On Series

![Status](https://img.shields.io/badge/status-in%20progress-yellow)
![Labs](https://img.shields.io/badge/labs-9-blue)
![Stack](https://img.shields.io/badge/SIEM-ELK%20Stack-005571)
![Platform](https://img.shields.io/badge/attacker-Kali%20Linux-557C94)

## About This Course

This is a self-paced, hands-on course for anyone who wants to move from "I know what Nmap and Metasploit do" to **"I can generate an attack, see it land in a SIEM, write the detection rule, and explain the evidence like an analyst."**

Every lab follows the same loop:

**Attack → Log → Detect → Document.**

You will run real attack techniques from Kali Linux against real targets (a dedicated victim VM), watch the resulting evidence arrive in an ELK Stack SIEM, build a detection (query, alert, or dashboard) for it, and write up the finding the way a SOC analyst would.

Each lab also opens with a **"Why this matters in real SOC work"** note tying the exercise to the actual detection-engineering or incident-response problem it mirrors — this course is built to feel like early-career SOC work.

Every lab is fully documented in text, with exact commands, expected output, and example screenshots to offer visual support - but should not always match your output.

## Lab Environment Architecture

Three virtual machines, one isolated internal network:

```mermaid
flowchart LR
    subgraph VMware Host-Only Network 192.168.56.0/24
        K["🐉 Kali Linux<br/>Attacker<br/>192.168.56.101"]
        U["📊 Ubuntu Server<br/>ELK Stack (SIEM)<br/>192.168.56.102"]
        M["🎯 Metasploitable2<br/>Victim<br/>192.168.56.103"]
    end
    K -- "attacks / scans" --> M
    M -- "syslog / auth.log" --> U
    K -- "views dashboards :5601" --> U
    K -. "some labs: attacker log source too" .-> U
```

| Machine | Role | OS | IP (this course) |
|---|---|---|---|
| Kali Linux | Attacker / red team box | Kali Rolling 2025.3 | `192.168.56.101` |
| ELK-SIEM | Log aggregation, detection, dashboards | Ubuntu Server 22.04 LTS | `192.168.56.102` |
| Metasploitable2 | Intentionally vulnerable victim | Ubuntu 8.04 (custom) | `192.168.56.103` |

> Environment build instructions (Phase 0) live in [`00-Environment-Setup/`](./00-Environment-Setup/README.md). **Do this before starting Lab 1.**
>
> **Log shipping note:** Metasploitable2 runs a 2008-era Ubuntu base too old for modern log-shipping agents (Filebeat, etc.) to run on. Labs that need its logs use its built-in classic syslog daemon (`sysklogd`, via `/etc/syslog.conf`) to forward events over UDP to port 514 on the ELK-SIEM VM, where an `iptables` rule redirects that traffic to a **Logstash** listener on port 5514 (Logstash can't bind port 514 directly without breaking Java's library loading — see Lab 1's troubleshooting section). Logstash then parses and forwards events to Elasticsearch. This is introduced in Lab 1 and reused in later labs.

## Repository Structure

```
soc-threat-hunting-course/
├── README.md                              ← you are here
├── 00-Environment-Setup/
│   ├── README.md                          ← setup environment and build the 3-VM lab network
│   └── media/                             ← A storage folder for supporting screenshots (Ignore)
├── Lab-01-SSH-Bruteforce-Detection/
│   ├── README.md                          ← walkthrough guides from this file in each lab
│   └── media/
├── Lab-02-Port-Scan-Detection-Engineering/
├── Lab-03-Reverse-Shell-Network-Detection/
├── Lab-04-SOC-Investigation-Simulation/
├── Lab-05-Custom-Log-Based-IDS-Script/
├── Lab-06-Beaconing-Traffic-Detection/
├── Lab-07-Exploitation-Visibility-Analysis/
├── Lab-08-Web-Attack-Detection-SIEM/
└── Lab-09-Baseline-vs-Attack-Deviation/
```

Each lab folder is self-contained: its `README.md` is the full manual, `media/` holds only that lab's screenshots, and two files support the final deliverable,`LabN-Investigation-Writeup-Template.docx` to actually fill in, and a `WRITEUP-TEMPLATE.md` guide explaining exactly where in that lab to find the information each field needs.

## Course Index

| # | Lab Title | Core Skill | Primary Tools |
|---|---|---|---|
| 1 | [SSH Brute-Force Detection in ELK](./Lab-01-SSH-Bruteforce-Detection/README.md) | Threshold-based alerting on auth logs | Hydra, Nmap, ELK |
| 2 | [Port Scan Detection Engineering Lab](./Lab-02-Port-Scan-Detection-Engineering/README.md) | Recon detection, false-positive tuning | Nmap, ELK |
| 3 | [Reverse Shell Network Detection Study](./Lab-03-Reverse-Shell-Network-Detection/README.md) | Packet-level C2 identification | Netcat, Metasploit, Wireshark |
| 4 | [End-to-End SOC Investigation Simulation](./Lab-04-SOC-Investigation-Simulation/README.md) | Full attack chain + incident timeline | Nmap, Metasploit, Wireshark, ELK |
| 5 | [Custom Log-Based Intrusion Detection Script](./Lab-05-Custom-Log-Based-IDS-Script/README.md) | Custom detection engineering | Python, ELK (via Filebeat/HTTP) |
| 6 | [Beaconing Traffic Detection Lab](./Lab-06-Beaconing-Traffic-Detection/README.md) | Time-series / periodicity detection | Netcat, Wireshark, ELK |
| 7 | [Exploitation Visibility Analysis](./Lab-07-Exploitation-Visibility-Analysis/README.md) | Log coverage gap analysis | Metasploit, ELK |
| 8 | [Web Attack Detection in SIEM](./Lab-08-Web-Attack-Detection-SIEM/README.md) | Web log detection engineering | Metasploit (DVWA/Mutillidae), ELK |
| 9 | [Network Baseline vs Attack Deviation Report](./Lab-09-Baseline-vs-Attack-Deviation/README.md) | Baselining & anomaly documentation | Wireshark, Nmap, ELK |

### Lab Introductions

**Lab 1 — SSH Brute-Force Detection in ELK**
Simulate a real SSH credential-stuffing attack against the victim VM using Hydra, ingest `auth.log` into ELK via Filebeat, and build a Kibana visualization plus a threshold alert that fires when failed-login velocity crosses a baseline. Goal: understand how volumetric authentication abuse looks in raw logs vs. in a SIEM, and how to tune a threshold so it catches the attack without false-alarming on normal typos.

**Lab 2 — Port Scan Detection Engineering Lab**
Run multiple Nmap scan types (`-sS`, `-sT`, `-sA`, `-sU`, `-Pn`, timing templates) against the victim and capture them on the wire and in logs. Build ELK detection logic that flags reconnaissance based on unique-port-count-per-source-per-time-window, and deliberately tune it against a "noisy but benign" traffic sample to reduce false positives. Goal: learn the tradeoff between detection sensitivity and analyst alert fatigue.

**Lab 3 — Reverse Shell Network Detection Study**
Generate multiple reverse shells (Netcat and Metasploit/`msfvenom` payloads) from the victim back to Kali, capture the traffic in Wireshark, and identify the network fingerprints of shell activity — long-lived low-volume connections, unusual destination ports, interactive-shell packet timing. Goal: learn to spot C2 channels from packet behavior alone, without relying on payload signatures.

**Lab 4 — End-to-End SOC Investigation Simulation**
Chain everything together: scan → exploit → shell → post-exploitation, captured simultaneously in Wireshark and ELK. Then produce a structured incident report with a timeline correlating each attack stage to its detection evidence (or lack of it). Goal: practice the actual SOC/IR deliverable — a timeline a Tier-2 analyst or incident commander could read cold.

**Lab 5 — Custom Log-Based Intrusion Detection Script**
Write a Python script that tails `auth.log` in real time, detects brute-force patterns using your own logic (not a SIEM query), and forwards structured JSON alerts into ELK over HTTP/Filebeat. Goal: understand detection engineering from first principles — what a SIEM's built-in correlation is actually doing under the hood — and produce a small reusable tool for your portfolio.

**Lab 6 — Beaconing Traffic Detection Lab**
Simulate periodic C2-style check-in traffic (a scripted Netcat loop) and use Wireshark statistics plus an ELK time-bucket query to detect the beacon interval, jitter, and regularity. Goal: learn interval-based/statistical detection, which catches C2 that no signature ever will.

**Lab 7 — Exploitation Visibility Analysis**
Exploit a vulnerable service on the victim (e.g. via Metasploit) and deliberately compare three views of the same event: the raw application/system log, the default ELK ingestion, and a purpose-built detection. Goal: learn to identify and articulate **monitoring gaps** — a core SOC-maturity skill that's rarely taught directly.

**Lab 8 — Web Attack Detection in SIEM**
Simulate common web attacks (SQLi, XSS, directory traversal, encoded payloads) against a vulnerable web app on the victim VM, ingest web server logs into ELK, and build detection queries for suspicious parameters, HTTP error-code spikes, and encoding anomalies (e.g. `%27`, `<script`, `../../`). Goal: extend detection engineering skills from network/auth logs into the web layer.

**Lab 9 — Network Baseline vs Attack Deviation Report**
Capture a clean traffic baseline on the lab network, then run a mix of attacks from earlier labs, and produce a before/after report documenting exactly how port usage, packet timing, and flow volume deviated from baseline. Goal: this is the "capstone" lab — it demonstrates the foundational SOC skill of knowing what *normal* looks like before you can recognize *abnormal*.

---

**Note:** The level of knowledge required to get advantage of this course is not limitted to people with cyber security background. The explaination is detailed and instructive, and friendly absulte novices. However, A baseline background will ensure much greater benefit.

---

## Legal Disclaimer & Usage Terms

1. The information, scripts, and attack simulations contained in this repository are provided strictly for educational, research, and defensive security training purposes. This course is designed to teach defensive professionals how to recognize malicious activity and build robust monitoring rules. It does not encourage, facilitate, or promote unauthorized computer access or malicious hacking.

2. All practical demonstrations, exploits, and network traffic analyses in this course are strictly restricted to a private virtual laboratory environment. The target system used (Metasploitable2) is a legacy, intentionally vulnerable machine that lacks modern security controls and is completely unsuited for deployment on a live network.

3. **Do not attempt** any of the offensive techniques described in this repository against networks, systems, or infrastructure that you do not own or do not have formal authorization to test. Executing these tools against unauthorized targets is illegal and can lead to severe criminal penalties.

4. This course is the original work of Elmutaz Hussain. The author assumes absolute no liability and is not responsible for any misuse, damage, data loss, legal consequences, or administrative actions resulting from the implementation or adaptation of the concepts, scripts, or tools presented herein. You engage with these practical materials entirely at your own risk.

5. **Permitted Usage:**
**For Learners:** You are fully encouraged to clone this repository, follow the guides, and practice the labs for personal growth and educational portfolio building.

**For Reviewers:** Peer reviews, feedback, and constructive critiques are highly welcome!

**Restrictions:** You may not copy, redistribute, republish, or host this material on other platforms, websites, or commercial courses without explicit written permission from the author. If you reference this work in blogs or portfolios, please provide a direct link back to this GitHub repository.

---