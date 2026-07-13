# Lab 5 — Write-Up Guide

## Date/Time

The timestamp of your first `[ALERT SENT]` line from Part 5 — visible directly in your ELK-SIEM terminal, or in the alert document's own `@timestamp` field:
```bash
curl "http://192.168.56.102:9200/custom-ids-alerts-*/_search?pretty"
```

## Source / Target / Detector

Static for this lab — copy as-is from what's already in the document.

## Timeline Rows

1. **Detector script started** — when you ran `python3 ~/detect_bruteforce.py` in Part 4, or when the systemd service started (Part 7), whichever you used. Check your terminal scrollback or `sudo systemctl status bruteforce-detector` for the service start time.
2. **Hydra attack launched** — from Kali's Hydra output header (same as Lab 1: `Hydra ... starting at [date/time]`).
3. **Alert fired (`[ALERT SENT]`)** — the exact line in your Part 5 terminal output, or the `@timestamp` field of the alert document in Elasticsearch (most precise source).
4. **Second attack correctly suppressed** — the timestamp of your `[SUPPRESSED]` line from Part 5.

## Detection Logic / Design Decisions / Recommendation

These sections are conceptual — restate the algorithm you actually implemented (polling interval, window, threshold, cooldown) as documented in Part 2/3 of the lab. Note the threshold is `3`, not the more intuitive `5` — this was deliberately lowered after confirming this legacy target's `sshd`/PAM logging doesn't produce one discrete log line per attempt (see Part 5's note on this). Worth mentioning in your write-up as a real finding, not just a script detail.

## Evidence

Reference your  screenshots  (e.g. `media/lab05-03-alert-sent.png`)
