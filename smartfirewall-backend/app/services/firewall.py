"""
app/services/firewall.py

iptables management:
- pending devices block (approved=0)
- manual internet blocking (device internet_blocked)
- DNS redirect rules per device (dns_filtered)

Safer behavior:
- uses timeouts so requests do not hang forever
- uses -w on iptables so it waits briefly for xtables lock
- persist_rules() will not block forever
"""

import subprocess
from flask import current_app

DEFAULT_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


def _env():
    env = {}
    env.update({"PATH": DEFAULT_PATH})
    return env


def sh(cmd: list[str], timeout: int = 20) -> tuple[int, str, str]:
    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=_env(),
            timeout=timeout,
        )
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except subprocess.TimeoutExpired:
        return 124, "", f"Command timed out: {' '.join(cmd)}"


def run_cmd(args, timeout: int = 20):
    try:
        r = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=_env(),
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"Command timed out: {' '.join(args)}")

    if r.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(args)}\n{r.stderr.strip()}")
    return r.stdout.strip()


def _iptables_base(table=None):
    cmd = ["sudo", "iptables", "-w", "3"]
    if table:
        cmd += ["-t", table]
    return cmd


def iptables_rule_exists(table, chain, rule_parts):
    cmd = _iptables_base(table) + ["-C", chain] + rule_parts
    r = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=_env(),
        timeout=10,
    )
    return r.returncode == 0


def iptables_add_rule(table, chain, rule_parts, insert=False, position=1):
    cmd = _iptables_base(table)
    if insert:
        cmd += ["-I", chain, str(position)] + rule_parts
    else:
        cmd += ["-A", chain] + rule_parts
    run_cmd(cmd, timeout=15)


def iptables_delete_rule(table, chain, rule_parts):
    cmd = _iptables_base(table) + ["-D", chain] + rule_parts
    while True:
        try:
            r = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=_env(),
                timeout=10,
            )
        except subprocess.TimeoutExpired:
            break

        if r.returncode != 0:
            break


def ensure_chains_exist():
    sh(["sudo", "iptables", "-w", "3", "-N", "IOT_BLOCK"])
    sh(["sudo", "iptables", "-w", "3", "-N", "IOT_ALLOW"])
    sh(["sudo", "iptables", "-w", "3", "-t", "nat", "-N", "DNS_FILTER"])


def enforce_pending_block(mac: str, should_block: bool):
    """
    Approved=0 => always blocked regardless of groups.
    """
    ensure_chains_exist()
    mac = mac.lower().strip()
    ap = current_app.config["AP_IFACE"]
    wan = current_app.config["WAN_IFACE"]

    rule = ["-i", ap, "-o", wan, "-m", "mac", "--mac-source", mac, "-j", "DROP"]

    if should_block:
        if not iptables_rule_exists(None, "IOT_BLOCK", rule):
            iptables_add_rule(None, "IOT_BLOCK", rule, insert=True, position=1)
    else:
        iptables_delete_rule(None, "IOT_BLOCK", rule)


def set_internet_block(mac: str, blocked: bool):
    """
    Manual/group internet block: same rule format as pending.
    """
    ensure_chains_exist()
    mac = mac.lower().strip()
    ap = current_app.config["AP_IFACE"]
    wan = current_app.config["WAN_IFACE"]

    rule = ["-i", ap, "-o", wan, "-m", "mac", "--mac-source", mac, "-j", "DROP"]

    if blocked:
        if not iptables_rule_exists(None, "IOT_BLOCK", rule):
            iptables_add_rule(None, "IOT_BLOCK", rule, insert=True, position=1)
    else:
        iptables_delete_rule(None, "IOT_BLOCK", rule)


def set_dns_filter(mac: str, enabled: bool):
    """
    DNS filtering ON/OFF per device:
    Redirect device DNS to dnsmasq-filtered (port 5300).
    """
    ensure_chains_exist()
    mac = mac.lower().strip()

    rule_udp = [
        "-m", "mac", "--mac-source", mac,
        "-p", "udp", "--dport", "53",
        "-j", "REDIRECT", "--to-ports", "5300"
    ]
    rule_tcp = [
        "-m", "mac", "--mac-source", mac,
        "-p", "tcp", "--dport", "53",
        "-j", "REDIRECT", "--to-ports", "5300"
    ]

    if enabled:
        if not iptables_rule_exists("nat", "DNS_FILTER", rule_udp):
            iptables_add_rule("nat", "DNS_FILTER", rule_udp)
        if not iptables_rule_exists("nat", "DNS_FILTER", rule_tcp):
            iptables_add_rule("nat", "DNS_FILTER", rule_tcp)
    else:
        iptables_delete_rule("nat", "DNS_FILTER", rule_udp)
        iptables_delete_rule("nat", "DNS_FILTER", rule_tcp)


def persist_rules():
    """
    Only call on admin changes, not every minute.
    Do not allow this to hang forever.
    """
    rc, out, err = sh(["sudo", "netfilter-persistent", "save"], timeout=25)
    if rc != 0:
        raise RuntimeError(err or out or "netfilter-persistent save failed")
