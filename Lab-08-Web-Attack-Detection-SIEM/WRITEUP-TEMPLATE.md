# Lab 8 — Write-Up Guide

> This file does **not** contain the write-up template itself — that lives in [`Lab8-Investigation-Writeup-Template.docx`](./Lab8-Investigation-Writeup-Template.docx), left clean and instruction-free. This guide explains **where to find** the information each field in that document is asking for.

## Date/Time

The `@timestamp` of your Part 4.1 SQL injection request — check via:
```bash
curl "http://192.168.56.102:9200/web-access-logs-*/_search?pretty&q=url.original.keyword:*UNION*+OR+url.original.keyword:*1*3D*1*"
```
or simply note the time shown in your browser/terminal when you submitted the attack.

## Source / Target / Techniques Observed

Static for this lab — copy as-is from what's already in the document.

## Timeline Rows

1. **Apache log bridge started** — when you ran `./forward_apache_log.sh` in Part 2.1.
2. **SQL injection executed** — from Part 4.1, your DVWA submission time.
3. **XSS executed** — from Part 4.2.
4. **Directory traversal executed** — from Part 4.3.
5. **Encoded payload sent** — from Part 4.4's `curl` output timestamp.
6. **Detection queries confirmed matching** — whenever you completed Part 5's searches.

## Attack Payloads Table

Copy these directly from what you actually typed in Part 4 — the raw payload strings (`' OR '1'='1`, `<script>alert('xss')</script>`, `../../../../etc/passwd`, and the URL-encoded variant) — no lookup needed, just transcribe what you used.

## Detection Logic / Recommendation

Conceptual sections — restate the three query types from Part 5 (suspicious parameters, error-code spikes, encoded payloads) and why each catches something the others might miss. No lookup needed, just confirm your write-up matches what you actually built.

## Evidence

Reference your existing screenshots by filename (e.g. `media/lab08-04-sqli-attack.png`) — no new captures needed.
