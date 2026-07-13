# Lab 9 — Write-Up Guide

## Date/Time

The start time of your baseline capture (Part 1.1) — check Wireshark's first packet timestamp, or your terminal scrollback for when you started the capture.

## Source / Target / Techniques Observed

Static for this lab — copy as-is from what's already in the document.

## Comparison Table (the main deliverable)

All values come directly from Wireshark's **Statistics** windows — no calculation needed, just transcribe what's shown:

1. **Total packets** — Statistics → Endpoints, total packet count, for each `.pcapng` file separately.
2. **Total distinct TCP conversations** — Statistics → Conversations → TCP tab, the row count.
3. **Distinct destination ports touched** — count the unique values in the "Port B" column of the same Conversations view.
4. **Dominant protocol (% of traffic)** — Statistics → Protocol Hierarchy, the top-line percentage.
5. **SYN-only connections** — in Conversations → TCP tab, look for streams with very few packets (2–3) and no data transfer — these are typically incomplete/scan-only connections. A rough count is fine; exact precision isn't the point.
6. **Capture duration** — Wireshark's status bar shows this while a capture is running, or check the timestamp of the first and last packet.

The "Deviation" column is your own written comparison (e.g. "6x more ports touched," "SYN-only connections went from 0 to 47") — not a lookup, just describe what changed.

## Timeline Rows

1. **Baseline capture started** — Part 1.1.
2. **Baseline capture completed** — Part 1.3.
3. **Attack window started** — Part 3.1.
4. **Nmap scan completed** — from your terminal output in Part 3.2.
5. **Hydra attack completed** — from Hydra's own "finished at" timestamp line.
6. **Reverse shell established** — from your Netcat listener's connection announcement.
7. **Attack window capture completed** — Part 3.3.

## SIEM Cross-Reference / Visibility Asymmetry / Recommendation

These sections are conceptual — restate what Part 6 actually showed (recon and brute-force visible in the SIEM, reverse shell not) and confirm it matches your own count query results rather than the example numbers in the manual.

## Evidence

Reference your screenshots (e.g. `media/lab09-02-baseline-protocol-hierarchy.png`)
