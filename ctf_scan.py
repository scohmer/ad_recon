#!/usr/bin/env python3

import argparse
import yaml
import nmap
import subprocess
from pathlib import Path
from datetime import datetime

PORT_NSE_SCRIPTS = {
    53: ['dns-zone-transfer', 'dns-recursion'],
    80: ['http-enum', 'http-title', 'http-headers'],
    88: ['krb5-enum-users'],
    135: ['msrpc-enum'],
    139: ['smb-enum-shares', 'smb-enum-users', 'smb-os-discovery'],
    389: ['ldap-search', 'ldap-rootdse'],
    445: ['smb-enum-shares', 'smb-enum-users', 'smb-os-discovery'],
    464: ['kerberos'],
    593: ['msrpc-enum'],
    636: ['ldap-search', 'ldap-rootdse'],
    3268: ['ldap-search'],
    3389: ['rdp-enum-encryption'],
    5985: ['http-auth', 'http-ntlm-info'],
    9389: ['wcf-enum'],
}

def resolve_config_and_paths(machine_name, new_ip):
    base_path = Path.home() / "htb" / machine_name
    yaml_path = base_path / "yaml"
    loot_path = base_path / "loot"
    config_file = yaml_path / f"{machine_name}.yml"

    yaml_path.mkdir(parents=True, exist_ok=True)
    loot_path.mkdir(parents=True, exist_ok=True)

    if config_file.exists():
        with open(config_file, "r") as f:
            config = yaml.safe_load(f)
        config["ip"] = new_ip
    else:
        config = {
            "ip": new_ip,
            "machine_name": machine_name,
            "ports": [],
            "notes": "",
            "os_guess": ""
        }

    with open(config_file, "w") as f:
        yaml.dump(config, f)

    return config, str(config_file), str(base_path), str(yaml_path), str(loot_path)

def save_config(config, config_file):
    with open(config_file, "w") as f:
        yaml.dump(config, f)

def save_loot(machine_name, loot_path, filename, content):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    loot_file = Path(loot_path) / f"{timestamp}_{machine_name}_{filename}"
    with open(loot_file, "w") as f:
        f.write(content)
    print(f"[+] Loot saved: {loot_file}")
    return str(loot_file)

def prompt_hosts_entry(ip, hostname, skip=False):
    if skip or not hostname or "." not in hostname:
        return
    hosts_path = "/etc/hosts"
    try:
        with open(hosts_path, "r") as f:
            if any(hostname in line and ip in line for line in f.readlines()):
                print(f"[+] {hostname} already in /etc/hosts.")
                return
    except PermissionError:
        print("[!] Cannot read /etc/hosts. You may need sudo.")

    print(f"[!] Found hostname: {hostname}")
    choice = input(f"[?] Add '{ip} {hostname}' to /etc/hosts? [y/N]: ").strip().lower()
    if choice == "y":
        cmd = f"echo '{ip} {hostname}' | sudo tee -a /etc/hosts"
        try:
            subprocess.run(cmd, shell=True)
            print("[+] Entry added.")
        except Exception as e:
            print(f"[!] Failed to add hosts entry: {e}")

def run_command_capture(cmd, label, machine_name, loot_path):
    try:
        print(f"[*] Running {label}...")
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=180)
        output = result.stdout + "\n" + result.stderr
        save_loot(machine_name, loot_path, f"{label}.txt", output)
    except Exception as e:
        print(f"[!] {label} failed: {e}")

def run_nmap_full(ip, udp=False):
    print(f"[+] Running full {'UDP' if udp else 'TCP'} scan on {ip}...")
    scanner = nmap.PortScanner()
    if udp:
        scanner.scan(hosts=ip, arguments='-sU --top-ports 50 -T4 --min-rate 5000 -Pn --max-retries 1 --host-timeout 2m')
    else:
        scanner.scan(hosts=ip, arguments='-p- -sS -T4 --min-rate 5000 -Pn --max-retries 1 --host-timeout 2m')
    open_ports = []
    if ip in scanner.all_hosts():
        for proto in scanner[ip].all_protocols():
            open_ports.extend(scanner[ip][proto].keys())
    return sorted(set(open_ports))

def get_nse_scripts_for_ports(ports):
    scripts = set()
    for port in ports:
        scripts.update(PORT_NSE_SCRIPTS.get(port, []))
    return sorted(scripts)

def run_nmap_detailed(ip, ports, machine_name, loot_path, skip_hosts_prompt=False):
    scripts = get_nse_scripts_for_ports(ports)
    port_str = ",".join(str(p) for p in ports)
    script_str = f"--script={','.join(scripts)}" if scripts else ""
    args = f"-sS -sV -sC -T4 --min-rate 5000 --max-retries 1 -Pn {script_str}"

    print(f"[+] Running detailed scan on ports: {port_str}")
    scanner = nmap.PortScanner()

    try:
        scanner.scan(hosts=ip, ports=port_str, arguments=args)
    except Exception as e:
        print(f"[!] Nmap scan failed: {e}")
        return save_loot(machine_name, loot_path, "nmap_detailed.txt", f"[!] Nmap scan failed: {e}")

    if ip not in scanner.all_hosts():
        print(f"[!] No scan results returned for {ip}. The host might be up but all scanned ports are filtered or closed.")
        return save_loot(machine_name, loot_path, "nmap_detailed.txt",
                         f"[!] No scan data returned for {ip}.\nTry using a slower scan or verify port accessibility.")

    hostname = scanner[ip].hostname()
    if hostname:
        prompt_hosts_entry(ip, hostname, skip_hosts_prompt)

    output = []
    for host in scanner.all_hosts():
        output.append(f"Host: {host} ({scanner[host].hostname()})")
        output.append(f"State: {scanner[host].state()}")
        for proto in scanner[host].all_protocols():
            output.append(f"Protocol: {proto}")
            for port in sorted(scanner[host][proto].keys()):
                s = scanner[host][proto][port]
                output.append(
                    f"  Port {port}: {s['state']} {s['name']} {s.get('product', '')} {s.get('version', '')}"
                )

    return save_loot(machine_name, loot_path, "nmap_detailed.txt", "\n".join(output))

def auto_recon(ip, ports, machine_name, loot_path):
    if 445 in ports:
        run_command_capture(f"enum4linux-ng -A {ip}", "enum4linux-ng", machine_name, loot_path)
        run_command_capture(f"crackmapexec smb {ip}", "cme_smb", machine_name, loot_path)
    if any(p in ports for p in [389, 636, 3268]):
        run_command_capture(f"ldapsearch -x -H ldap://{ip} -s base", "ldapsearch", machine_name, loot_path)
        run_command_capture(f"crackmapexec ldap {ip}", "cme_ldap", machine_name, loot_path)
    if 88 in ports:
        run_command_capture(f"impacket-GetUserSPNs -request -dc-ip {ip} -no-pass EXAMPLE.COM/", "impacket_spns", machine_name, loot_path)
    if 3389 in ports:
        run_command_capture(f"crackmapexec rdp {ip}", "cme_rdp", machine_name, loot_path)
    if 5985 in ports:
        run_command_capture(f"crackmapexec winrm {ip}", "cme_winrm", machine_name, loot_path)

def main():
    parser = argparse.ArgumentParser(description="CTF Recon Toolkit")
    parser.add_argument("--ip", required=True, help="Target IP address")
    parser.add_argument("--name", required=True, help="Machine name")
    parser.add_argument("--refresh", action="store_true", help="Force TCP rescan")
    parser.add_argument("--udp", action="store_true", help="Include UDP scan")
    parser.add_argument("--no-hosts", action="store_true", help="Skip /etc/hosts prompt")
    args = parser.parse_args()

    config, config_file, base_path, yaml_path, loot_path = resolve_config_and_paths(args.name, args.ip)

    if args.refresh or not config.get("ports"):
        config["ports"] = run_nmap_full(config["ip"])
        save_config(config, config_file)
    else:
        print("[+] Using cached TCP ports.")

    run_nmap_detailed(config["ip"], config["ports"], config["machine_name"], loot_path, skip_hosts_prompt=args.no_hosts)

    if args.udp:
        udp_ports = run_nmap_full(config["ip"], udp=True)
        save_loot(config["machine_name"], loot_path, "udp_ports.txt", "\n".join(map(str, udp_ports)))

    auto_recon(config["ip"], config["ports"], config["machine_name"], loot_path)

if __name__ == "__main__":
    main()
