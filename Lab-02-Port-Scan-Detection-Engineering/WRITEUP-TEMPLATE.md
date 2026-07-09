# Lab 2 — Write-Up Guide

> This file does **not** contain the write-up template itself — that lives in [`Lab2-Investigation-Writeup-Template.docx`](./Lab2-Investigation-Writeup-Template.docx), left clean and instruction-free. This guide explains **where to find** the information each field in that document is asking for.

## Date/Time of Scans

The timestamp printed at the top of your first Nmap scan's output (the `-sS` scan from Part 5):
```
Starting Nmap ... at [date/time]
```

## Source / Target / Techniques Observed

Static for this lab — copy as-is from what's already in the document.

## Timeline Rows

Kibana **Discover** (`Port Scan Logs` data view) is your source of truth for most of these:

1. **Benign baseline traffic recorded** — the timestamp of your Part 7.1 `curl`/`ssh` test. Filter `src_ip: "192.168.56.101"`, sort ascending — it's your earliest entry, showing only 2–3 distinct `dst_port` values in that minute.
2. **First scan (`-sS`) launched** — the `Starting Nmap ... at` line from that scan's terminal output (Part 5), or cross-check in Discover for the first minute where `dst_port` values jump from single digits to dozens.
3. **Unique-port-count threshold crossed** — scroll through the `-sS` scan's burst in Discover and find the timestamp of roughly the 10th–11th distinct port touched within that same minute. Manual counting, same as Lab 1's threshold point.
4. **Alert rule shows "Active" status** — **Stack Management → Rules → Port Scan Threshold Alert → Alerts** tab shows the exact time it transitioned to Active.
5. **Remaining scan types completed** — the final line of each scan's terminal output (Nmap prints `Nmap done: ... scanned in X.XX seconds`) — note the timestamp of your last one.

## Detection Logic / False Positive Considerations / Recommendation

Conceptual sections — restate the cardinality-based rule you built (Part 8) and the benign-vs-scan comparison from Part 7. No lookup needed, just confirm your write-up matches what you actually configured.

## Evidence

Reference your existing screenshots by filename (e.g. `media/lab02-05-nmap-syn-scan.png`) — no new captures needed.
