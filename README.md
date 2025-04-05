# CTF Recon Toolkit 🛠️

A smart enumeration tool for CTFs and Active Directory labs.

## Features
- Smart Nmap scanning (TCP/UDP, NSE)
- Auto-detection of services (SMB, LDAP, Kerberos, RDP)
- Launches tools like enum4linux-ng, crackmapexec, ldapsearch, impacket
- Saves results per box in YAML and loot folders
- Hostname detection and /etc/hosts updating

## Usage

```bash
python3 ctf_scan.py --ip 10.10.10.134 --name bastion
```

---

### 📝 5. **LICENSE**

If you’re open to others using/contributing, MIT is ideal:

```text
MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy...

