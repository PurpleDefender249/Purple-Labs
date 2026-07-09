# Lab 4 — Write-Up Guide

> This file does **not** contain the write-up template itself — that lives in [`Lab4-Investigation-Writeup-Template.docx`](./Lab4-Investigation-Writeup-Template.docx), left clean and instruction-free. This guide explains **where to find** the information each field in that document is asking for. This lab's timeline pulls from multiple sources at once — that's the point of the exercise.

## Date/Time

From your Part 2.2 recon check — the earliest `@timestamp` returned by:
```bash
curl "http://192.168.56.102:9200/portscan-logs-*/_search?pretty&q=src_ip:192.168.56.101"
```

## Source / Target / Attack Chain

Static for this lab — copy as-is from what's already in the document.

## Incident Timeline Rows

1. **Reconnaissance (full port/version scan)** — same timestamp as "Date/Time" above, from `portscan-logs-*`.
2. **Exploitation attempt (vsftpd backdoor trigger)** — in your saved `lab4-exploitation-capture.pcapng`, filter `tcp.port == 21 or tcp.port == 6200`, take the timestamp of the first port-21 packet (Part 5.2).
3. **Root shell established (port 6200)** — same filtered view, the timestamp of the first port-6200 packet.
4. **Post-exploitation commands executed** — the timestamp of the last relevant packet in that same stream, corresponding to your Part 4 command activity.

The "Evidence Source" and "Caught by SIEM?" columns are already filled in correctly in the template — reconnaissance is the only stage your SIEM caught; everything after it was Wireshark-only. You're only filling in the four timestamps.

## Detection Coverage Summary / Root Cause / Recommendation

These sections are already written as general findings — confirm they match your actual results (i.e., you genuinely found nothing exploitation-related in either Elasticsearch index per Part 5.1) rather than researching anything new.

## Evidence

Reference your existing screenshots by filename (e.g. `media/lab04-03-vsftpd-backdoor-shell.png`) — no new captures needed.
