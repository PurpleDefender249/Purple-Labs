# Lab 1 — Write-Up Guide

> This file does **not** contain the write-up template itself — that lives in [`Lab1-Investigation-Writeup-Template.docx`](./Lab1-Investigation-Writeup-Template.docx), which is intentionally left as a clean, instruction-free document you can fill in directly or hand off as-is. This guide explains **where to find** the information each field in that document is asking for.

## Date/Time of Attack

Look at the top of your Hydra output from Part 6.3 — the line that says:
```
Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at [date/time]
```
That's your attack start time.

## Source / Target / Technique

These are static for this lab — just use `192.168.56.101` (Kali), `192.168.56.103` (Metasploitable2), and "SSH dictionary brute-force" as already noted in the document.

## Timeline Rows

Kibana **Discover** (`SSH Auth Logs` data view) is your source of truth for all of these:

1. **First failed login attempt observed** — filter `message: "Failed password"`, sort by `@timestamp` **ascending**. The first row is your answer.
2. **Failed-login count crosses threshold (5/min)** — scroll through the sorted results and find the timestamp of the 5th failed-login event within any rolling 1-minute window. This is manual counting — normal for tuning work.
3. **Alert rule shows "Active" status** — **Stack Management → Rules → SSH Brute-Force Threshold Alert → Alerts** (or **Execution history**) tab shows the exact time it transitioned to Active.
4. **Successful login recorded** — run this on ELK-SIEM for the precise timestamp:
   ```bash
   curl "http://192.168.56.102:9200/ssh-auth-logs-*/_search?pretty&q=message:Accepted"
   ```
   The `@timestamp` field in the result is your answer.

## Detection Logic / False Positive Considerations / Recommendation

These sections are largely conceptual — restate the rule you actually built (index, query, threshold, window) and the reasoning already covered in Lab 1 Part 8. You don't need to look anything up; just confirm what you configured matches what you write.

## Evidence

Reference your existing screenshots by filename (e.g. `media/lab01-07-hydra-attack-success.png`) — no new captures needed.
