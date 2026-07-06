# Lab 1 — Investigation Write-Up Template

> Copy this file's contents into your own findings, or duplicate this file (e.g. `WRITEUP.md`) and fill it in. This is the deliverable a real SOC analyst would produce after this investigation — fill in every bracketed field with your actual lab data and timestamps.

## Investigation Write-Up

**Date/Time of Attack:** [fill in from your Hydra run timestamp]
**Source:** 192.168.56.101 (Kali — simulated attacker)
**Target:** 192.168.56.103 (Metasploitable2)
**Technique:** SSH dictionary brute-force (Hydra, 7-entry wordlist, 4 threads)

### Timeline

| Time | Event |
|---|---|
| [ts] | First failed login attempt observed |
| [ts] | Failed-login count crosses threshold (5/min) |
| [ts] | Alert rule shows "Active" status |
| [ts] | Successful login recorded (`msfadmin` password matched) |

### Detection Logic

Elasticsearch query rule on index `ssh-auth-logs-*`, counting documents matching
`message: "Failed password"`, threshold >5 events per 1-minute window.

### False Positive Considerations

A legitimate user mistyping their password 2–3 times would not cross this threshold.
Environments with many simultaneous legitimate users may need a per-source-IP
threshold instead of a global one — worth calling out as a tuning consideration
rather than something this lab solves outright.

### Evidence

(embed your screenshots here, e.g. `![Hydra attack](media/lab01-07-hydra-attack-success.png)`)

### Recommendation

Rate-limit or temporarily lock accounts after repeated failures (e.g. `fail2ban`),
and consider disabling direct password auth on SSH in favor of key-based auth.
