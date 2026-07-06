# Lab 2 — Investigation Write-Up Template

> Copy this file's contents into your own findings, or duplicate this file (e.g. `WRITEUP.md`) and fill it in.

## Investigation Write-Up

**Date/Time of Scans:** [fill in from your first Nmap scan timestamp]
**Source:** 192.168.56.101 (Kali — simulated attacker)
**Target:** 192.168.56.103 (Metasploitable2)
**Techniques Observed:** SYN scan, TCP connect scan, ACK scan, UDP scan, host-discovery-skip, slow-timing stealth scan

### Timeline

| Time | Event |
|---|---|
| [ts] | Benign baseline traffic recorded (2–3 ports touched) |
| [ts] | First scan (`-sS`) launched |
| [ts] | Unique-port-count threshold crossed |
| [ts] | Alert rule shows "Active" status |
| [ts] | Remaining scan types (`-sT`, `-sA`, `-sU`, `-Pn`, `-T0`) completed |

### Detection Logic

Elasticsearch query rule on index `portscan-logs-*`, using a `cardinality` aggregation on
`dst_port` grouped by `src_ip`, threshold >10 unique ports touched per 1-minute window.

### False Positive Considerations

Benign traffic (a single web request plus one SSH check) touched only 2 distinct ports in
the same window — well under the threshold. In a production network with more diverse
legitimate multi-port clients (health checks, load balancers), a longer baseline period
would be needed before finalizing this threshold.

### Evidence

(embed your screenshots here, e.g. `![Nmap SYN scan](media/lab02-05-nmap-syn-scan.png)`)

### Recommendation

Alert on unique-destination-port cardinality per source rather than raw packet/connection
counts, since scan techniques (SYN vs. connect vs. ACK) vary widely in packet volume but
consistently touch many distinct ports in a short window. Consider a secondary, lower
threshold as a "low and slow" tier to catch stealth-timed scans that spread probes out
over longer windows than this lab's 1-minute bucket would catch.
