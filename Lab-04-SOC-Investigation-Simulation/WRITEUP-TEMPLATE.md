# Lab 4 — Investigation Write-Up Template

> Copy this file's contents into your own findings, or duplicate this file (e.g. `WRITEUP.md`) and fill it in.

## Investigation Write-Up

**Date/Time:** [fill in from your Part 2.2 recon timestamp]
**Source (attacker):** 192.168.56.101 (Kali)
**Target (victim):** 192.168.56.103 (Metasploitable2)
**Attack Chain:** Nmap full port/version reconnaissance → Metasploit `vsftpd_234_backdoor` exploitation → root shell → post-exploitation commands

### Incident Timeline

| Stage | Event | Timestamp | Evidence Source | Caught by SIEM? |
|---|---|---|---|---|
| 1 | Reconnaissance (full port/version scan) | [ts] | `portscan-logs-*` | Yes |
| 2 | Exploitation attempt (vsftpd backdoor trigger) | [ts] | Wireshark only | No |
| 3 | Root shell established (port 6200) | [ts] | Wireshark only | No |
| 4 | Post-exploitation commands executed | [ts] | Wireshark only | No |

### Detection Coverage Summary

Reconnaissance was fully visible via the port-scan detection pipeline built in Lab 2.
Everything from the moment of exploitation onward — the backdoor trigger, the resulting
root shell, and all post-exploitation activity — was completely invisible to both SIEM
indices in use (`ssh-auth-logs-*` and `portscan-logs-*`). Only the Wireshark packet
capture recorded these later stages.

### Root Cause of the Detection Gap

Neither existing pipeline was built to monitor FTP-layer exploitation or arbitrary
shell traffic on non-standard ports (6200, in this case). This mirrors a common
real-world gap: detections are often built reactively, around techniques already
understood, leaving genuinely novel or less-common attack paths uncovered until
an incident forces the gap into view.

### Evidence

(embed your screenshots here, e.g. `![Backdoor shell obtained](media/lab04-03-vsftpd-backdoor-shell.png)`)

### Recommendation

Extend log/detection coverage to include FTP service logs and unusual outbound/inbound
connections on non-standard ports (such as 6200) — the same "unexpected port" principle
established in Lab 3. More broadly, this incident is a case for periodic purple-team
exercises that specifically test attack paths outside the SOC's current detection
coverage, rather than only validating detections that are already known to work.
