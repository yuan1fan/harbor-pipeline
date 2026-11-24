"""Trusted, one-shot network setup in a separate NET_ADMIN container.

The author itself never receives NET_ADMIN, even through sudo. Its namespace
allows public IPv4, Docker DNS, its host service port and its own debug targets.
"""
import ipaddress
import json
import subprocess
import sys

PRIVATE = (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
    "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
)


def run(*args, check=True):
    return subprocess.run(args, check=check, capture_output=True)


def configure(service_ip, port, targets):
    service_ip = str(ipaddress.IPv4Address(service_ip))
    targets = [str(ipaddress.IPv4Address(ip)) for ip in targets]
    port = int(port)
    if not 1 <= port <= 65535:
        raise ValueError("invalid service port")
    chain = "HARBOR_AUTHOR"
    # Fail closed while updating an already-running namespace.
    run("iptables", "-w", "-I", "OUTPUT", "1", "-j", "DROP")
    run("ip6tables", "-w", "-P", "OUTPUT", "DROP")
    run("iptables", "-w", "-N", chain, check=False)
    while run("iptables", "-w", "-C", "OUTPUT", "-j", chain, check=False).returncode == 0:
        run("iptables", "-w", "-D", "OUTPUT", "-j", chain)
    run("iptables", "-w", "-F", chain)
    run("iptables", "-w", "-A", chain, "-o", "lo", "-j", "ACCEPT")
    run("iptables", "-w", "-A", chain, "-d", service_ip, "-p", "tcp", "--dport", str(port), "-j", "ACCEPT")
    for ip in targets:
        run("iptables", "-w", "-A", chain, "-d", ip, "-j", "ACCEPT")
    for network in PRIVATE:
        run("iptables", "-w", "-A", chain, "-d", network, "-j", "REJECT")
    run("iptables", "-w", "-A", chain, "-j", "ACCEPT")
    run("iptables", "-w", "-I", "OUTPUT", "1", "-j", chain)
    run("iptables", "-w", "-D", "OUTPUT", "-j", "DROP")


if __name__ == "__main__":
    configure(**json.loads(sys.argv[1]))
