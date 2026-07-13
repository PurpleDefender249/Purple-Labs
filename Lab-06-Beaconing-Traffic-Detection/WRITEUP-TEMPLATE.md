# Lab 6 — Write-Up Guide

## Date/Time

The timestamp of your first beacon check-in arriving in Kali's `ncat` listener (Part 2.2), or the first event's `@timestamp` in Elasticsearch:
```bash
curl "http://192.168.56.102:9200/beacon-logs-*/_search?pretty&size=1&sort=@timestamp:asc"
```

## Source / Destination / Technique

Static for this lab — copy as-is from what's already in the document.

## Timeline Rows

1. **Beacon script started** — when you ran `./beacon.sh` in Part 2.2.
2. **Wireshark capture started** — when you clicked Start in Part 3.1.
3. **iptables OUTPUT logging added** — when you ran the `iptables -A OUTPUT ...` command in Part 4.1.
4. **First beacon analysis run (regular verdict)** — the timestamp shown in your Part 5 terminal output when you ran `analyze_beaconing.py` the first time.
5. **Irregular comparison traffic generated** — when you started the `for i in 1 2 3 4 5 6; do ...` loop in Part 6.2.
6. **Second beacon analysis run (comparison verdict)** — the timestamp from your Part 6.3 terminal output.

## Timing Statistics (Mean Gap, Std Dev, Coefficient of Variation)

Copy these directly from your two `analyze_beaconing.py` runs' printed output (Parts 5 and 6.3) — no calculation needed, the script computes and prints them for you.

## Detection Logic / Comparison / Recommendation

Conceptual sections — restate the coefficient-of-variation approach from Part 5 and what your two runs actually showed. Confirm your write-up matches your real script output rather than the example numbers in the manual.

## Evidence

Reference your screenshots (e.g. `media/lab06-06-beacon-analysis-verdict.png`)