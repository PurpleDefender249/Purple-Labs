# Lab 3 — Write-Up Guide

## Date/Time

The timestamp shown in Wireshark's status bar or packet list for the very first packet of your Netcat capture (Part 3.2–3.5) — that's your session start.

## Source / Destination / Techniques Observed

Static for this lab — copy as-is from what's already in the document.

## Timeline Rows

1. **Netcat listener started on Kali** — the moment you ran `nc -lvnp 4444` (Part 3.1). Check your terminal scrollback or the implied timing on your Part 3 screenshot.
2. **Netcat reverse shell connection established** — in Wireshark, filter `tcp.port == 4444`, sort by time, take the timestamp of the first `SYN` packet (source `192.168.56.103`).
3. **Shell commands executed and captured** — the timestamp of the last packet in that same filtered view, roughly when you finished running `whoami`/`id`/`ls`/`cat /etc/passwd`.
4. **msfvenom payload generated** — the terminal timestamp from Part 5.1 (if your terminal doesn't print one, note "recorded manually" — that's fine).
5. **Metasploit handler session established** — `msfconsole` prints a timestamp on its `[*] Sending stage...` / `[*] Command shell session ... opened` lines (Part 5.6).
6. **Second capture completed** — whenever you clicked Stop in Wireshark for the msfvenom capture.

## Network Indicators / Comparison / Detection Gap / Recommendation

These sections are already written as general findings in the document — confirm they match what you actually observed (e.g., did `auth.log` genuinely show nothing for both shells, per Part 6?) rather than researching anything new.

## Evidence

Reference your  screenshots  (e.g. `media/lab03-05-follow-tcp-stream.png`)
