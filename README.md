# dnspoison

*A lightweight DNS cache poisoning tool built with Scapy*

---

## Overview

`dnspoison` captures DNS A record queries on a network interface and injects forged DNS responses to selected target hostnames, aiming to poison the victim's resolver cache.

---

## Features

- Captures and inspects live DNS traffic in promiscuous mode.
- Injects spoofed DNS responses based on a configurable list of domains.
- Forges valid and properly-formed DNS packets for successful cache poisoning.
- Allows filtering specific traffic using BPF (Berkeley Packet Filter) expressions.
- Automatically selects a default network interface if none is provided.

---

## Usage

```bash
sudo python3 dnspoison.py [-i interface] [-f hostnames_file] [expression]
```

### Arguments

- `-i interface` — Network interface to listen on (e.g., `eth0`, `en0`). If omitted, a default interface is selected.
- `-f hostnames_file` — File containing IP address and hostname pairs to spoof.
- `expression` — Optional BPF filter to monitor specific traffic (e.g., a single victim).

### Example

```bash
sudo python3 dnspoison.py -i en0 -f hostnames.txt
```

---

## Hostnames File Format

Each line in the `hostnames.txt` file should have:

```
<IP_ADDRESS> <HOSTNAME>
```

### Example:

```
165.22.4.26 www.testvictim.com
165.22.4.26 www.example.com
```

If `-f` is not specified, `dnspoison` will forge responses for all observed DNS queries using the default attacker IP (`165.22.4.26`).

---

## Capturing and Testing

### Test Setup

1. Start Wireshark with a capture filter:
   ```
   udp port 53
   ```
2. Launch `dnspoison.py`
3. Trigger DNS requests on a separate terminal (e.g., using `dig` or `nslookup`):

**Example:**

```bash
dig www.testvictim.com
```

### Wireshark Display Filter for Verification

```
dns.qry.name == "www.testvictim.com"
```

A successful poisoning shows:

- A forged DNS response with the spoofed IP (`165.22.4.26`) before any legitimate response.
- Matching transaction IDs and valid DNS fields.

---

## Example Output

```bash
[*] Listening on en0, filter='udp port 53'
[+] Spoofing response for www.testvictim.com -> 165.22.4.26
```

In Wireshark, you will see:

```
Standard query response 0x1234 A www.testvictim.com A 165.22.4.26
```

---

