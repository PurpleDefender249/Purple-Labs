# Lab 3 — Investigation Write-Up Template

> Copy this file's contents into your own findings, or duplicate this file (e.g. `WRITEUP.md`) and fill it in.

## Investigation Write-Up

**Date/Time:** [fill in from your first Wireshark capture timestamp]
**Source (victim, connecting out):** 192.168.56.103 (Metasploitable2)
**Destination (attacker, listening):** 192.168.56.101 (Kali)
**Techniques Observed:** Raw Netcat reverse shell (port 4444), Metasploit/msfvenom `linux/x86/shell_reverse_tcp` payload (port 4445)

### Timeline

| Time | Event |
|---|---|
| [ts] | Netcat listener started on Kali |
| [ts] | Netcat reverse shell connection established |
| [ts] | Shell commands executed and captured |
| [ts] | msfvenom payload generated |
| [ts] | Metasploit handler session established |
| [ts] | Second capture completed |

### Network Indicators Identified

- **Connection direction:** victim-to-attacker outbound connection, opposite of normal client-to-server traffic.
- **Port choice:** both shells used non-standard, unregistered high ports (4444, 4445).
- **Packet timing/size:** many small packets spread across the full session duration, consistent with interactive keystroke-by-keystroke shell activity — distinct from a file transfer (few large packets, front-loaded) or a typical web request (brief burst, done in under a second).
- **Plaintext reconstruction:** `Follow TCP Stream` fully reconstructed both shell sessions' commands and output with no encryption.

### Comparison: Netcat vs. Metasploit Payload

Both delivery methods produced functionally identical network fingerprints — direction anomaly, small interactive packets, and full plaintext reconstruction. The payload-generation tool changed how the shell was delivered, not how it behaved on the wire.

### Detection Gap Observed

Neither reverse shell produced any entry in `/var/log/auth.log` on the victim — this activity is invisible to host authentication log monitoring (the detection method built in Lab 1). Network-level visibility (packet capture) was the only source that caught it.

### Evidence

(embed your screenshots here, e.g. `![Follow TCP Stream](media/lab03-05-follow-tcp-stream.png)`)

### Recommendation

Network monitoring for unexpected outbound connections from servers (especially to non-standard ports) should be treated as a high-value detection independent of payload/malware signatures. Consider egress filtering (default-deny outbound on servers, allow only required destinations) as a preventive control, since detection alone — as shown here — happens only after the shell is already active.
