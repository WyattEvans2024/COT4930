#!/usr/bin/env python3
"""Network discovery command-line tool.

Given a target network in CIDR notation, this tool discovers live hosts,
enriches each one, groups them into network segments, and can export a map.

Discovery uses two complementary probes per host:

1. A TCP connect probe against a small set of commonly open ports. Any port
   that accepts a connection within the timeout marks the host as live.
2. A single system ``ping`` per host, issued through :mod:`subprocess`. Besides
   confirming reachability, the echo request makes the operating system resolve
   the host at layer 2, which populates the local ARP / neighbor cache.

Each live host is then enriched with:

* its MAC address, read from the local neighbor table (``ip neigh`` on Linux,
  ``arp -a`` elsewhere),
* the hardware vendor, resolved from the MAC's OUI prefix against a small
  built-in table,
* its hostname, via reverse DNS,
* a best-guess device type, inferred from the open ports and the vendor.

Finally, hosts are grouped by subnet and default gateway into segments. The
result is printed as a table, printed again as an indented text tree, and can
be exported as a Graphviz DOT file (``--map FILE``) for rendering as a network
map.

Security and safety:

* The tool is strictly read-only. It performs only TCP connect probes (each
  socket is closed at once), one ICMP echo per host, and SNMP GET / GETNEXT
  reads. It issues no SNMP SET and writes nothing to any scanned device.
* ``--authorized`` is required; the tool refuses to run without that explicit
  confirmation that you are permitted to scan the target.
* Every input is validated (CIDR, ports, switch IPs) and nothing user-supplied
  reaches a shell (no ``shell=True``; all subprocess calls take argument lists).
* The SNMP community string is read only from the ``SNMP_COMMUNITY`` environment
  variable (or a no-echo prompt). It is never hardcoded, stored, or logged.
* All actions are logged to a timestamped file, and scan concurrency and rate
  are capped.

The core tool uses only the Python standard library; the optional SNMP module
uses pysnmp.
"""

from __future__ import annotations

import argparse
import asyncio
import datetime
import getpass
import ipaddress
import logging
import os
import platform
import re
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Optional, Sequence, Union

IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

# Ports probed by default: SSH, HTTP, HTTPS, SMB and RDP.
COMMON_PORTS: tuple[int, ...] = (22, 80, 443, 445, 3389)

# Upper bound on the number of hosts a single invocation may scan.
MAX_HOSTS: int = 1024

# Default per-connection TCP timeout, in seconds.
DEFAULT_TIMEOUT: float = 1.0

# Default size of the worker thread pool.
DEFAULT_WORKERS: int = 100

# Hard ceiling on concurrent probe threads, regardless of --workers.
MAX_WORKERS: int = 256

# Default probe start-rate cap, in hosts per second.
DEFAULT_RATE: float = 100.0

# Maximum switches queried concurrently over SNMP.
MAX_SNMP_CONCURRENCY: int = 8

# Module logger; handlers are attached by setup_logging().
log = logging.getLogger("netdiscover")


class RateLimiter:
    """Thread-safe cap on how often an action may start.

    Each :meth:`acquire` reserves the next evenly spaced time slot and sleeps
    until it arrives, so concurrent worker threads together begin at most
    ``rate`` actions per second. A non-positive rate disables throttling.
    """

    def __init__(self, rate_per_second: float) -> None:
        self._interval = 1.0 / rate_per_second if rate_per_second > 0 else 0.0
        self._lock = threading.Lock()
        self._next = 0.0

    def acquire(self) -> None:
        """Block until this caller's rate slot is due."""
        if self._interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            slot = max(now, self._next)
            self._next = slot + self._interval
        delay = slot - time.monotonic()
        if delay > 0:
            time.sleep(delay)


# OUI (Organizationally Unique Identifier) to vendor lookup.
#
# A MAC address is 48 bits. The first 24 bits (the first three octets) are the
# OUI, assigned by the IEEE to the hardware maker. Keys below are that OUI as
# six uppercase hex characters with no separators; values are the vendor.
#
# This is a deliberately small sample. To extend it, add more entries, or load
# the full public registry: download the CSV from
# https://standards-oui.ieee.org/oui/oui.csv and build a dict keyed by the
# "Assignment" column (uppercased, colons stripped) mapping to the
# "Organization Name" column. The lookup code needs no changes.
OUI_VENDORS: dict[str, str] = {
    # Apple
    "000393": "Apple", "001B63": "Apple", "002500": "Apple",
    "3C0754": "Apple", "ACBC32": "Apple", "F01898": "Apple",
    # Raspberry Pi
    "B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi", "E45F01": "Raspberry Pi",
    # Espressif (ESP8266 / ESP32 modules, common in DIY IoT)
    "240AC4": "Espressif", "30AEA4": "Espressif",
    "A4CF12": "Espressif", "7C9EBD": "Espressif",
    # Samsung
    "001632": "Samsung", "0012FB": "Samsung", "5C0A5B": "Samsung",
    # Google / Nest
    "001A11": "Google", "F4F5D8": "Google",
    "18B430": "Nest Labs", "641666": "Nest Labs",
    # Amazon (Echo, Fire TV)
    "44650D": "Amazon", "6837E9": "Amazon", "FCA183": "Amazon",
    # Roku
    "B0A737": "Roku",
    # Sony
    "0013A9": "Sony",
    # LG Electronics
    "001C62": "LG Electronics", "2C54CF": "LG Electronics",
    # HP (makes both computers and printers, so left out of printer typing)
    "001B78": "HP", "3CD92B": "HP",
    # Canon
    "000085": "Canon",
    # Brother
    "008077": "Brother",
    # Cisco
    "00000C": "Cisco", "001AA1": "Cisco",
    # VMware (virtual machine NICs)
    "005056": "VMware", "000C29": "VMware",
    "000569": "VMware", "001C14": "VMware",
    # Microsoft (Hyper-V virtual NICs, Xbox, Surface)
    "00155D": "Microsoft", "0050F2": "Microsoft",
    # Dell
    "001422": "Dell", "B82A72": "Dell", "180373": "Dell",
    # Intel
    "001B21": "Intel", "3CA9F4": "Intel", "A08869": "Intel",
    # Ubiquiti
    "00156D": "Ubiquiti", "24A43C": "Ubiquiti", "FCECDA": "Ubiquiti",
    # Netgear
    "00095B": "Netgear", "00146C": "Netgear",
    # TP-Link
    "50C7BF": "TP-Link", "EC086B": "TP-Link",
    # D-Link
    "00055D": "D-Link",
}

# Vendor groups used by device-type inference. A vendor may appear in the OUI
# table above without appearing here (and vice versa); extend both as needed.
_PRINTER_VENDORS = frozenset(
    {"canon", "brother", "epson", "lexmark", "xerox", "ricoh", "kyocera"}
)
_VM_VENDORS = frozenset({"vmware"})
_TV_IOT_VENDORS = frozenset(
    {
        "roku", "nest labs", "google", "amazon", "sony",
        "lg electronics", "samsung", "espressif", "sonos",
    }
)
_SBC_VENDORS = frozenset({"raspberry pi"})

# Matches a MAC address with ':' or '-' separators and 1-2 hex digits per octet.
_MAC_RE = re.compile(r"(?:[0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2}")
# Matches a dotted IPv4 address.
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass
class HostResult:
    """Outcome of probing and enriching a single host.

    Attributes:
        ip: The host address as a string.
        open_ports: The probed TCP ports that accepted a connection.
        pinged: ``True`` if the host answered a single ICMP echo request.
        mac: The host's MAC address from the neighbor table, or ``None``.
        vendor: The hardware vendor resolved from the MAC's OUI, or ``None``.
        hostname: The reverse-DNS name, or ``None`` if none resolved.
        device_type: A best-guess device category.
        switch: IP of the switch this device is attached to, from SNMP, or
            ``None`` if the optional SNMP module did not place it.
        port: The switch interface name the device sits on, or ``None``.
    """

    ip: str
    open_ports: list[int] = field(default_factory=list)
    pinged: bool = False
    mac: Optional[str] = None
    vendor: Optional[str] = None
    hostname: Optional[str] = None
    device_type: str = "unknown"
    switch: Optional[str] = None
    port: Optional[str] = None

    @property
    def is_live(self) -> bool:
        """Return whether either discovery probe found the host to be up."""
        return bool(self.open_ports) or self.pinged


@dataclass
class Segment:
    """A group of devices sharing a subnet and default gateway.

    Attributes:
        network: The subnet in CIDR notation, for example ``"192.168.1.0/24"``.
        gateway: The default-gateway IP within this subnet, or ``None`` if none
            is known (for example when scanning a remote subnet).
        devices: The discovered live hosts in this subnet, sorted by address.
        gateway_device: The gateway as a renderable node. It is the matching
            entry from ``devices`` when the gateway was discovered, a separate
            enriched node when the gateway was not discovered live, or ``None``
            when no gateway is known.
    """

    network: str
    gateway: Optional[str]
    devices: list[HostResult]
    gateway_device: Optional[HostResult] = None


def parse_cidr(value: str) -> IPNetwork:
    """Parse and validate a CIDR string, for use as an ``argparse`` type.

    Host bits are masked off, so ``192.168.1.37/24`` is accepted and treated as
    ``192.168.1.0/24``.

    Args:
        value: The raw CIDR string from the command line.

    Returns:
        The parsed network object.

    Raises:
        argparse.ArgumentTypeError: If the value is not valid CIDR notation, has
            no usable hosts, or exceeds :data:`MAX_HOSTS` usable hosts.
    """
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid CIDR {value!r}: {exc}") from exc

    # Guard before materializing the host list so an enormous network (for
    # example a bare IPv6 /64) is rejected without allocating anything.
    if network.num_addresses > MAX_HOSTS + 2:
        raise argparse.ArgumentTypeError(
            f"network {network} is too large: more than {MAX_HOSTS} hosts"
        )

    hosts = list(network.hosts())
    if not hosts:
        raise argparse.ArgumentTypeError(f"network {network} contains no usable hosts")
    if len(hosts) > MAX_HOSTS:
        raise argparse.ArgumentTypeError(
            f"network {network} has {len(hosts)} hosts, exceeding the cap "
            f"of {MAX_HOSTS}"
        )
    return network


def parse_ports(value: str) -> tuple[int, ...]:
    """Parse a comma-separated list of TCP ports, for use as an ``argparse`` type.

    Args:
        value: A string such as ``"22,80,443"``.

    Returns:
        A tuple of validated port numbers in the order given.

    Raises:
        argparse.ArgumentTypeError: If any entry is not an integer in 1-65535,
            or if no valid port is supplied.
    """
    ports: list[int] = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            port = int(part)
        except ValueError:
            raise argparse.ArgumentTypeError(f"invalid port {part!r}")
        if not 1 <= port <= 65535:
            raise argparse.ArgumentTypeError(f"port {port} is out of range 1-65535")
        ports.append(port)
    if not ports:
        raise argparse.ArgumentTypeError("no valid ports provided")
    return tuple(ports)


def parse_switch_list(value: str) -> tuple[str, ...]:
    """Parse a comma-separated list of switch IPs, for use as an ``argparse`` type.

    Args:
        value: A string such as ``"10.0.0.2,10.0.0.3"``.

    Returns:
        A tuple of validated IP-address strings in the order given.

    Raises:
        argparse.ArgumentTypeError: If any entry is not a valid IP address, or
            if no address is supplied.
    """
    switches: list[str] = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if not _is_ip_address(part):
            raise argparse.ArgumentTypeError(f"invalid switch IP {part!r}")
        switches.append(part)
    if not switches:
        raise argparse.ArgumentTypeError("no valid switch IPs provided")
    return tuple(switches)


def positive_float(value: str) -> float:
    """Parse a strictly positive float, for use as an ``argparse`` type.

    Args:
        value: The raw string from the command line.

    Returns:
        The parsed value.

    Raises:
        argparse.ArgumentTypeError: If the value is not a number or is not > 0.
    """
    try:
        parsed = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value!r} is not a number")
    if parsed <= 0:
        raise argparse.ArgumentTypeError(f"{value!r} must be greater than 0")
    return parsed


def positive_int(value: str) -> int:
    """Parse a strictly positive integer, for use as an ``argparse`` type.

    Args:
        value: The raw string from the command line.

    Returns:
        The parsed value.

    Raises:
        argparse.ArgumentTypeError: If the value is not an integer or is not > 0.
    """
    try:
        parsed = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value!r} is not an integer")
    if parsed <= 0:
        raise argparse.ArgumentTypeError(f"{value!r} must be greater than 0")
    return parsed


def tcp_probe(host: str, ports: Sequence[int], timeout: float) -> list[int]:
    """Try a TCP connect to each port and collect the ones that open.

    Args:
        host: The target address as a string.
        ports: The TCP ports to try, in order.
        timeout: Per-connection timeout in seconds.

    Returns:
        The ports that accepted a connection within the timeout, in the order
        they were tried. Empty if none did.
    """
    open_ports: list[int] = []
    for port in ports:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                open_ports.append(port)
        except OSError:
            # Refused, timed out, or unreachable: try the next port.
            continue
    return open_ports


def ping_host(host: str, timeout: float) -> bool:
    """Send one ICMP echo request to a host via the system ``ping`` utility.

    Running ``ping`` in a subprocess avoids the raw-socket privileges that a
    native ICMP implementation would need. The reply, if any, also leaves an
    entry in the local ARP / neighbor cache.

    Args:
        host: The target address as a string.
        timeout: How long to wait for a reply, in seconds.

    Returns:
        ``True`` if ``ping`` reported success (exit code 0), else ``False``.
    """
    # Defense in depth: never hand anything but a validated IP to the shell-less
    # subprocess call below. Callers already pass addresses from the scanned
    # network, so this only guards against future misuse.
    if not _is_ip_address(host):
        return False

    system = platform.system().lower()
    if system == "windows":
        # -n 1: one echo request. -w: per-reply timeout in milliseconds.
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), host]
    elif system == "darwin":
        # -c 1: one echo request. -W: per-reply timeout in milliseconds.
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout * 1000))), host]
    else:
        # Linux and most BSDs. -c 1: one echo. -W: per-reply timeout in seconds.
        cmd = ["ping", "-c", "1", "-W", str(max(1, round(timeout))), host]

    try:
        completed = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 2.0,
        )
    except (OSError, subprocess.SubprocessError):
        # ping missing, or it ran past the subprocess timeout.
        return False
    return completed.returncode == 0


def probe_host(host: str, ports: Sequence[int], timeout: float) -> HostResult:
    """Run the TCP and ping probes for one host and collect the result.

    Args:
        host: The target address as a string.
        ports: The TCP ports to probe.
        timeout: Timeout in seconds shared by both probes.

    Returns:
        A :class:`HostResult` with discovery fields set. Enrichment fields are
        filled in later by :func:`enrich_host`.
    """
    open_ports = tcp_probe(host, ports, timeout)
    pinged = ping_host(host, timeout)
    return HostResult(ip=host, open_ports=open_ports, pinged=pinged)


def discover(
    network: IPNetwork,
    ports: Sequence[int],
    timeout: float,
    workers: int,
    limiter: Optional[RateLimiter] = None,
) -> list[HostResult]:
    """Probe every usable host in a network concurrently.

    Concurrency is bounded by ``workers``, the host count, and the hard
    :data:`MAX_WORKERS` ceiling. When a limiter is given, probe starts are also
    rate-capped.

    Args:
        network: The validated target network.
        ports: The TCP ports to probe on each host.
        timeout: Per-probe timeout in seconds.
        workers: Requested worker-thread count (capped at :data:`MAX_WORKERS`).
        limiter: Optional per-host start-rate limiter.

    Returns:
        One :class:`HostResult` per host, sorted by ascending IP address.
    """
    hosts = [str(host) for host in network.hosts()]
    worker_count = max(1, min(workers, MAX_WORKERS, len(hosts)))

    def run_one(host: str) -> HostResult:
        if limiter is not None:
            limiter.acquire()
        return probe_host(host, ports, timeout)

    results: list[HostResult] = []
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = [executor.submit(run_one, host) for host in hosts]
        for future in as_completed(futures):
            results.append(future.result())
    results.sort(key=lambda result: ipaddress.ip_address(result.ip))
    return results


def _run_command(cmd: Sequence[str]) -> Optional[str]:
    """Run a short command and return its stdout, or ``None`` on failure.

    Args:
        cmd: The command and its arguments.

    Returns:
        Captured standard output if the command ran and produced any, else
        ``None`` (command missing, errored, or empty output).
    """
    try:
        completed = subprocess.run(
            cmd, capture_output=True, text=True, timeout=5.0
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return completed.stdout if completed.stdout.strip() else None


def _normalize_mac(raw: str) -> Optional[str]:
    """Normalize a MAC address to lowercase, colon-separated, zero-padded form.

    Accepts both ``00-11-22-...`` (Windows) and short ``0:11:22:...`` (BSD/macOS)
    spellings.

    Args:
        raw: A MAC address as printed by ``ip neigh`` or ``arp``.

    Returns:
        The normalized MAC (for example ``"00:11:22:33:44:55"``), or ``None`` if
        it does not have six valid octets.
    """
    parts = raw.replace("-", ":").lower().split(":")
    if len(parts) != 6:
        return None
    try:
        octets = [int(part, 16) for part in parts]
    except ValueError:
        return None
    if any(octet < 0 or octet > 255 for octet in octets):
        return None
    return ":".join(f"{octet:02x}" for octet in octets)


def _is_ip_address(value: str) -> bool:
    """Return whether a string is a valid IP address."""
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _ip_in_network(ip: str, network: IPNetwork) -> bool:
    """Return whether an IP string falls within a network."""
    try:
        return ipaddress.ip_address(ip) in network
    except ValueError:
        return False


def _parse_ip_neigh(output: str) -> dict[str, str]:
    """Parse ``ip neigh`` output into an IP-to-MAC mapping.

    Each line looks like ``192.168.1.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE``.
    Lines with no ``lladdr`` (for example ``FAILED`` entries) are skipped.

    Args:
        output: The raw text printed by ``ip neigh``.

    Returns:
        A mapping of IP address to normalized MAC address.
    """
    table: dict[str, str] = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 2 or "lladdr" not in parts:
            continue
        ip = parts[0]
        index = parts.index("lladdr")
        if index + 1 >= len(parts):
            continue
        mac = _normalize_mac(parts[index + 1])
        if mac and _is_ip_address(ip):
            table[ip] = mac
    return table


def _parse_arp(output: str) -> dict[str, str]:
    """Parse ``arp -a`` output into an IP-to-MAC mapping.

    Handles the Windows (``192.168.1.1  00-11-22-33-44-55  dynamic``),
    macOS/BSD (``? (192.168.1.1) at 0:11:22:... on en0``) and Linux net-tools
    (``host (192.168.1.1) at 00:11:22:... [ether] on eth0``) formats by pulling
    the first IPv4 address and the first MAC out of each line.

    Args:
        output: The raw text printed by ``arp -a``.

    Returns:
        A mapping of IP address to normalized MAC address.
    """
    table: dict[str, str] = {}
    for line in output.splitlines():
        mac_match = _MAC_RE.search(line)
        ip_match = _IPV4_RE.search(line)
        if not mac_match or not ip_match:
            continue
        mac = _normalize_mac(mac_match.group())
        ip = ip_match.group()
        if mac and _is_ip_address(ip):
            table[ip] = mac
    return table


def read_neighbor_table() -> dict[str, str]:
    """Read the local ARP / neighbor cache into an IP-to-MAC mapping.

    Tries ``ip neigh`` first (Linux), then falls back to ``arp -a`` (Windows,
    macOS, BSD, and Linux without iproute2). Only populated after traffic has
    been sent to a host, which the ping sweep in :func:`discover` arranges.

    Returns:
        A mapping of IP address to normalized MAC address. Empty if no neighbor
        command is available or the cache holds no usable entries.
    """
    output = _run_command(["ip", "neigh"])
    if output is not None:
        table = _parse_ip_neigh(output)
        if table:
            return table
    output = _run_command(["arp", "-a"])
    if output is not None:
        return _parse_arp(output)
    return {}


def _parse_gateway_ip_route(output: str) -> Optional[str]:
    """Pull the gateway IP from ``ip route`` output (Linux iproute2).

    Looks for a line like ``default via 192.168.1.1 dev eth0``.
    """
    for line in output.splitlines():
        tokens = line.split()
        if tokens and tokens[0] == "default" and "via" in tokens:
            candidate = tokens[tokens.index("via") + 1]
            if _is_ip_address(candidate):
                return candidate
    return None


def _parse_gateway_route_print(output: str) -> Optional[str]:
    """Pull the gateway IP from Windows ``route print`` output.

    Looks for an active-route line whose destination and mask are both
    ``0.0.0.0``; the third column is the gateway.
    """
    for line in output.splitlines():
        tokens = line.split()
        if (
            len(tokens) >= 3
            and tokens[0] == "0.0.0.0"
            and tokens[1] == "0.0.0.0"
            and _is_ip_address(tokens[2])
        ):
            return tokens[2]
    return None


def _parse_gateway_route_get(output: str) -> Optional[str]:
    """Pull the gateway IP from macOS ``route -n get default`` output.

    Looks for a line like ``    gateway: 192.168.1.1``.
    """
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("gateway:"):
            candidate = stripped.split(":", 1)[1].strip()
            if _is_ip_address(candidate):
                return candidate
    return None


def _parse_gateway_default_row(output: str) -> Optional[str]:
    """Pull the gateway IP from ``netstat -rn`` or ``route -n`` output.

    Looks for a line whose first column is ``default`` (BSD/macOS) or ``0.0.0.0``
    (Linux net-tools); the second column is the gateway.
    """
    for line in output.splitlines():
        tokens = line.split()
        if (
            len(tokens) >= 2
            and tokens[0] in ("default", "0.0.0.0")
            and _is_ip_address(tokens[1])
        ):
            return tokens[1]
    return None


def detect_default_gateway() -> Optional[str]:
    """Detect this machine's IPv4 default gateway from the routing table.

    Tries platform-appropriate commands in turn and returns the first gateway
    IP found. This is the local machine's gateway; it identifies a segment's
    router only when the scanned subnet is the local subnet.

    Returns:
        The gateway IP as a string, or ``None`` if it could not be determined.
    """
    system = platform.system().lower()
    attempts: list[tuple[list[str], Callable[[str], Optional[str]]]]
    if system == "windows":
        attempts = [(["route", "print"], _parse_gateway_route_print)]
    elif system == "darwin":
        attempts = [
            (["route", "-n", "get", "default"], _parse_gateway_route_get),
            (["netstat", "-rn"], _parse_gateway_default_row),
        ]
    else:
        attempts = [
            (["ip", "route"], _parse_gateway_ip_route),
            (["route", "-n"], _parse_gateway_default_row),
        ]

    for cmd, parser in attempts:
        output = _run_command(cmd)
        if output:
            gateway = parser(output)
            if gateway:
                return gateway
    return None


def lookup_vendor(mac: Optional[str]) -> Optional[str]:
    """Resolve a MAC address to a hardware vendor via its OUI prefix.

    Args:
        mac: A normalized MAC address, or ``None``.

    Returns:
        The vendor name, or ``None`` if the MAC is missing or its OUI is not in
        :data:`OUI_VENDORS`.
    """
    if not mac:
        return None
    prefix = mac.replace(":", "")[:6].upper()
    return OUI_VENDORS.get(prefix)


def reverse_dns(host: str) -> Optional[str]:
    """Look up the reverse-DNS (PTR) hostname for an address.

    Args:
        host: The IP address as a string.

    Returns:
        The resolved hostname, or ``None`` if no PTR record exists or the
        lookup fails.
    """
    try:
        hostname, _aliases, _addresses = socket.gethostbyaddr(host)
    except OSError:
        return None
    return hostname


def guess_device_type(open_ports: Sequence[int], vendor: Optional[str]) -> str:
    """Infer a coarse device category from open ports and vendor.

    This is a heuristic best guess, not a fingerprint. The signals are weak:
    a five-port scan and a 24-bit vendor prefix cannot distinguish, say, an
    iPhone from an iPad. Treat the result as a hint.

    Priority, strongest signal first:

    1. Single-purpose vendors (printer makers, virtualization NICs).
    2. Windows sharing or remote desktop (SMB / RDP) -> computer.
    3. SSH without Windows services -> server.
    4. Consumer media and smart-home brands -> TV/IoT.
    5. Single-board computers -> server.
    6. A lone web interface -> embedded appliance (TV/IoT).
    7. Reachable with no open ports, from a handset vendor -> phone.

    Args:
        open_ports: The probed ports found open on the host.
        vendor: The resolved hardware vendor, or ``None``.

    Returns:
        One of ``"computer"``, ``"phone"``, ``"printer"``, ``"TV/IoT"``,
        ``"server"``, or ``"unknown"``.
    """
    ports = set(open_ports)
    vendor_key = (vendor or "").lower()

    has_web = bool(ports & {80, 443})
    has_shell = 22 in ports
    has_smb = 445 in ports
    has_rdp = 3389 in ports

    if vendor_key in _PRINTER_VENDORS:
        return "printer"
    if vendor_key in _VM_VENDORS:
        return "server"
    if has_rdp or has_smb:
        return "computer"
    if has_shell:
        return "server"
    if vendor_key in _TV_IOT_VENDORS:
        return "TV/IoT"
    if vendor_key in _SBC_VENDORS:
        return "server"
    if has_web:
        return "TV/IoT"
    if not ports and vendor_key == "apple":
        return "phone"
    return "unknown"


def enrich_host(result: HostResult, neighbors: dict[str, str]) -> None:
    """Fill in the MAC, vendor, hostname, and device-type fields of a result.

    Args:
        result: A :class:`HostResult` to enrich in place.
        neighbors: The IP-to-MAC mapping from :func:`read_neighbor_table`.
    """
    result.mac = neighbors.get(result.ip)
    result.vendor = lookup_vendor(result.mac)
    result.hostname = reverse_dns(result.ip)
    result.device_type = guess_device_type(result.open_ports, result.vendor)


def enrich_hosts(
    results: Sequence[HostResult], neighbors: dict[str, str], workers: int
) -> None:
    """Enrich every live host in place, concurrently.

    Runs per-host enrichment across a thread pool, mainly to overlap the
    reverse-DNS lookups.

    Args:
        results: All host results from :func:`discover`.
        neighbors: The IP-to-MAC mapping from :func:`read_neighbor_table`.
        workers: Maximum number of worker threads.
    """
    live = [result for result in results if result.is_live]
    if not live:
        return
    with ThreadPoolExecutor(max_workers=min(workers, len(live))) as executor:
        futures = [
            executor.submit(enrich_host, result, neighbors) for result in live
        ]
        for future in as_completed(futures):
            future.result()


# ---------------------------------------------------------------------------
# Optional SNMP switch-port mapping module.
#
# This block queries managed switches over SNMP (pysnmp) to learn which
# physical port each MAC address lives on, correlates that with the discovered
# devices, and reads LLDP to find switch-to-switch uplinks. pysnmp is imported
# lazily, so the rest of the tool runs without it. The whole block is skipped
# unless --switches is given. Targets pysnmp 7.x (install: pip install pysnmp).
# ---------------------------------------------------------------------------

# Bridge-MIB and related OIDs (as dotted strings).
OID_DOT1D_TPFDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"        # MAC -> bridge port
OID_DOT1Q_TPFDB_PORT = "1.3.6.1.2.1.17.7.1.2.2.1.2"    # Q-BRIDGE: vlan+MAC -> port
OID_DOT1D_BASEPORT_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"  # bridge port -> ifIndex
OID_IFNAME = "1.3.6.1.2.1.31.1.1.1.1"                  # ifIndex -> ifName
OID_IFDESCR = "1.3.6.1.2.1.2.2.1.2"                    # ifIndex -> ifDescr
OID_SYSNAME = "1.3.6.1.2.1.1.5.0"                      # scalar sysName.0
OID_LLDP_REM_CHASSIS = "1.0.8802.1.1.2.1.4.1.1.5"      # LLDP remote chassis id
OID_LLDP_REM_PORTID = "1.0.8802.1.1.2.1.4.1.1.7"       # LLDP remote port id
OID_LLDP_REM_SYSNAME = "1.0.8802.1.1.2.1.4.1.1.9"      # LLDP remote system name

# Default SNMP timing.
SNMP_TIMEOUT: float = 2.0
SNMP_RETRIES: int = 1

# Lazily imported pysnmp async hlapi module, cached after first load.
_PYSNMP = None


class SnmpUnavailable(Exception):
    """Raised when the pysnmp library cannot be imported."""


class SnmpError(Exception):
    """Raised when an SNMP exchange with a switch fails."""


@dataclass
class LldpNeighbor:
    """One LLDP neighbor seen by a switch.

    Attributes:
        local_port: The local LLDP port number the neighbor is seen on.
        remote_sysname: The neighbor's advertised system name.
        remote_port: The neighbor's advertised port id.
        remote_chassis: The neighbor's advertised chassis id.
    """

    local_port: str
    remote_sysname: str
    remote_port: str
    remote_chassis: str


@dataclass
class Switch:
    """Result of querying one managed switch over SNMP.

    Attributes:
        ip: The switch management IP.
        reachable: ``True`` if the switch answered SNMP.
        sysname: The switch's SNMP sysName, if read.
        mac_ports: Mapping of MAC address to the local interface name it is
            learned on.
        neighbors: LLDP neighbors the switch reports.
        error: A short failure description when ``reachable`` is ``False``.
    """

    ip: str
    reachable: bool = False
    sysname: Optional[str] = None
    mac_ports: dict[str, str] = field(default_factory=dict)
    neighbors: list[LldpNeighbor] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class UplinkLink:
    """An LLDP link from one switch to a neighbor.

    Attributes:
        local_ip: The reporting switch's IP.
        local_label: The reporting switch's name or IP.
        local_port: The local port the neighbor is on.
        remote_label: The neighbor's name or chassis id.
        remote_port: The neighbor's port id.
        is_switch: ``True`` if the neighbor is one of the queried switches.
    """

    local_ip: str
    local_label: str
    local_port: str
    remote_label: str
    remote_port: str
    is_switch: bool


def _load_pysnmp():
    """Import and cache the pysnmp async hlapi module.

    Returns:
        The imported module.

    Raises:
        SnmpUnavailable: If pysnmp is not installed.
    """
    global _PYSNMP
    if _PYSNMP is None:
        try:
            import pysnmp.hlapi.v3arch.asyncio as module
        except Exception as exc:  # ImportError and any transitive failure.
            raise SnmpUnavailable(str(exc) or exc.__class__.__name__) from exc
        _PYSNMP = module
    return _PYSNMP


def resolve_snmp_community() -> Optional[str]:
    """Obtain the SNMP community string without ever hardcoding it.

    Reads the ``SNMP_COMMUNITY`` environment variable first; if unset and the
    session is interactive, prompts for it without echo. Returns ``None`` when
    no value is available, so the caller can skip SNMP gracefully.

    Returns:
        The community string, or ``None``.
    """
    community = os.environ.get("SNMP_COMMUNITY")
    if community:
        return community
    if sys.stdin is not None and sys.stdin.isatty():
        try:
            entered = getpass.getpass("SNMP community string: ")
        except (EOFError, KeyboardInterrupt):
            return None
        return entered or None
    return None


def _oid_ints(name: object) -> tuple[int, ...]:
    """Return an SNMP object name as a tuple of integer sub-identifiers."""
    as_tuple = getattr(name, "asTuple", None)
    if callable(as_tuple):
        try:
            return tuple(int(part) for part in as_tuple())
        except (TypeError, ValueError):
            pass
    return tuple(int(part) for part in str(name).strip(".").split(".") if part)


def _mac_from_oid_tail(oid_tuple: Sequence[int]) -> Optional[str]:
    """Build a MAC string from the last six sub-identifiers of a table index."""
    if len(oid_tuple) < 6:
        return None
    tail = oid_tuple[-6:]
    if any(octet < 0 or octet > 255 for octet in tail):
        return None
    return ":".join(f"{octet:02x}" for octet in tail)


def _parse_fdb_port(varbinds: Sequence[tuple[Sequence[int], object]]) -> dict[str, int]:
    """Parse a forwarding-table walk into a MAC-to-bridge-port mapping.

    Args:
        varbinds: ``(oid_tuple, value)`` pairs from a dot1dTpFdbPort or
            dot1qTpFdbPort walk. The MAC is the last six sub-identifiers of the
            index and the value is the bridge port number.

    Returns:
        A mapping of MAC address to bridge port number.
    """
    table: dict[str, int] = {}
    for oid_tuple, value in varbinds:
        mac = _mac_from_oid_tail(oid_tuple)
        if mac is None:
            continue
        try:
            table[mac] = int(value)
        except (TypeError, ValueError):
            continue
    return table


def _parse_indexed_int(
    varbinds: Sequence[tuple[Sequence[int], object]]
) -> dict[int, int]:
    """Parse a walk whose index's last sub-id is an int key and value is an int."""
    table: dict[int, int] = {}
    for oid_tuple, value in varbinds:
        if not oid_tuple:
            continue
        try:
            table[oid_tuple[-1]] = int(value)
        except (TypeError, ValueError):
            continue
    return table


def _parse_indexed_str(
    varbinds: Sequence[tuple[Sequence[int], object]]
) -> dict[int, str]:
    """Parse a walk whose index's last sub-id is an int key and value is a str."""
    table: dict[int, str] = {}
    for oid_tuple, value in varbinds:
        if not oid_tuple:
            continue
        table[oid_tuple[-1]] = str(value)
    return table


def _compose_mac_ports(
    fdb_port: dict[str, int],
    base_port_ifindex: dict[int, int],
    if_names: dict[int, str],
) -> dict[str, str]:
    """Resolve MAC-to-bridge-port into MAC-to-interface-name.

    The forwarding table gives bridge port numbers, which map through
    dot1dBasePortIfIndex to ifIndex, which map through ifName/ifDescr to a
    human name. When a step is missing, falls back to the numeric port.

    Args:
        fdb_port: MAC to bridge port number.
        base_port_ifindex: Bridge port number to ifIndex.
        if_names: ifIndex to interface name.

    Returns:
        A mapping of MAC address to interface name.
    """
    mac_ports: dict[str, str] = {}
    for mac, bridge_port in fdb_port.items():
        if_index = base_port_ifindex.get(bridge_port, bridge_port)
        mac_ports[mac] = if_names.get(if_index) or f"port {bridge_port}"
    return mac_ports


def _parse_lldp(
    sysname_vbs: Sequence[tuple[Sequence[int], object]],
    portid_vbs: Sequence[tuple[Sequence[int], object]],
    chassis_vbs: Sequence[tuple[Sequence[int], object]],
) -> list[LldpNeighbor]:
    """Join the three LLDP remote-table walks into neighbor records.

    Each lldpRemTable row is indexed by ``timeMark.localPortNum.remIndex``
    appended to the column OID, so entries are joined on
    ``(localPortNum, remIndex)``.

    Args:
        sysname_vbs: lldpRemSysName walk.
        portid_vbs: lldpRemPortId walk.
        chassis_vbs: lldpRemChassisId walk.

    Returns:
        The LLDP neighbors, one per remote-table row.
    """

    def by_index(
        varbinds: Sequence[tuple[Sequence[int], object]], base_oid: str
    ) -> dict[tuple[int, int], str]:
        base_len = len([part for part in base_oid.split(".") if part])
        mapping: dict[tuple[int, int], str] = {}
        for oid_tuple, value in varbinds:
            suffix = tuple(oid_tuple[base_len:])
            if len(suffix) >= 3:
                mapping[(suffix[1], suffix[2])] = str(value)
        return mapping

    sysnames = by_index(sysname_vbs, OID_LLDP_REM_SYSNAME)
    ports = by_index(portid_vbs, OID_LLDP_REM_PORTID)
    chassis = by_index(chassis_vbs, OID_LLDP_REM_CHASSIS)

    neighbors: list[LldpNeighbor] = []
    for key in sorted(set(sysnames) | set(ports) | set(chassis)):
        neighbors.append(
            LldpNeighbor(
                local_port=str(key[0]),
                remote_sysname=sysnames.get(key, ""),
                remote_port=ports.get(key, ""),
                remote_chassis=chassis.get(key, ""),
            )
        )
    return neighbors


async def _snmp_get(engine, module, community: str, ip: str, oid: str,
                    timeout: float, retries: int) -> Optional[object]:
    """Perform an SNMP GET of a single scalar OID.

    Returns:
        The value, or ``None`` if the agent had no such object.

    Raises:
        SnmpError: If the exchange failed (for example a timeout).
    """
    target = await module.UdpTransportTarget.create(
        (ip, 161), timeout=timeout, retries=retries
    )
    error_indication, error_status, _error_index, var_binds = await module.get_cmd(
        engine,
        module.CommunityData(community, mpModel=1),
        target,
        module.ContextData(),
        module.ObjectType(module.ObjectIdentity(oid)),
    )
    if error_indication:
        raise SnmpError(str(error_indication))
    if error_status:
        raise SnmpError(error_status.prettyPrint())
    if not var_binds:
        return None
    value = var_binds[0][1]
    if isinstance(
        value,
        (module.NoSuchObject, module.NoSuchInstance, module.EndOfMibView, module.Null),
    ):
        return None
    return value


async def _snmp_walk(engine, module, community: str, ip: str, base_oid: str,
                     timeout: float, retries: int
                     ) -> list[tuple[tuple[int, ...], object]]:
    """Walk an SNMP subtree and return coerced ``(oid_tuple, value)`` pairs.

    Integer-typed values become ``int``; everything else becomes its pretty
    string. End-of-MIB sentinels are skipped.

    Raises:
        SnmpError: If the exchange failed.
    """
    int_types = (
        module.Integer32, module.Gauge32, module.Counter32,
        module.Counter64, module.Unsigned32, module.TimeTicks,
    )
    target = await module.UdpTransportTarget.create(
        (ip, 161), timeout=timeout, retries=retries
    )
    out: list[tuple[tuple[int, ...], object]] = []
    walk = module.walk_cmd(
        engine,
        module.CommunityData(community, mpModel=1),
        target,
        module.ContextData(),
        module.ObjectType(module.ObjectIdentity(base_oid)),
        lexicographicMode=False,
    )
    async for error_indication, error_status, error_index, var_binds in walk:
        if error_indication:
            raise SnmpError(str(error_indication))
        if error_status:
            raise SnmpError(f"{error_status.prettyPrint()} at {error_index}")
        for var_bind in var_binds:
            value = var_bind[1]
            if isinstance(
                value,
                (module.NoSuchObject, module.NoSuchInstance,
                 module.EndOfMibView, module.Null),
            ):
                continue
            coerced: object = int(value) if isinstance(value, int_types) else value.prettyPrint()
            out.append((_oid_ints(var_bind[0]), coerced))
    return out


async def _query_switch(engine, module, ip: str, community: str,
                        timeout: float, retries: int) -> Switch:
    """Query one switch for its forwarding table and LLDP neighbors.

    Any failure marks the switch unreachable rather than raising, so one dead
    switch never aborts the run.
    """
    switch = Switch(ip=ip)
    try:
        # sysName.0 is universal; failing it means the switch did not answer.
        sysname = await _snmp_get(
            engine, module, community, ip, OID_SYSNAME, timeout, retries
        )
        switch.sysname = str(sysname) if sysname is not None else None

        base_port_ifindex = _parse_indexed_int(
            await _snmp_walk(engine, module, community, ip,
                             OID_DOT1D_BASEPORT_IFINDEX, timeout, retries)
        )
        if_names = _parse_indexed_str(
            await _snmp_walk(engine, module, community, ip,
                             OID_IFNAME, timeout, retries)
        )
        if not if_names:
            if_names = _parse_indexed_str(
                await _snmp_walk(engine, module, community, ip,
                                 OID_IFDESCR, timeout, retries)
            )
        fdb = _parse_fdb_port(
            await _snmp_walk(engine, module, community, ip,
                             OID_DOT1D_TPFDB_PORT, timeout, retries)
        )
        if not fdb:
            # Many modern switches only populate the VLAN-aware Q-BRIDGE table.
            fdb = _parse_fdb_port(
                await _snmp_walk(engine, module, community, ip,
                                 OID_DOT1Q_TPFDB_PORT, timeout, retries)
            )
        switch.mac_ports = _compose_mac_ports(fdb, base_port_ifindex, if_names)

        try:
            switch.neighbors = _parse_lldp(
                await _snmp_walk(engine, module, community, ip,
                                 OID_LLDP_REM_SYSNAME, timeout, retries),
                await _snmp_walk(engine, module, community, ip,
                                 OID_LLDP_REM_PORTID, timeout, retries),
                await _snmp_walk(engine, module, community, ip,
                                 OID_LLDP_REM_CHASSIS, timeout, retries),
            )
        except SnmpError:
            switch.neighbors = []  # LLDP is optional; keep the FDB data.

        switch.reachable = True
    except Exception as exc:  # Degrade gracefully for this switch.
        switch.reachable = False
        switch.error = str(exc) or exc.__class__.__name__
    return switch


async def _query_all_switches(switch_ips: Sequence[str], community: str,
                              timeout: float, retries: int) -> list[Switch]:
    """Query switches concurrently, capped at :data:`MAX_SNMP_CONCURRENCY`."""
    module = _load_pysnmp()
    engine = module.SnmpEngine()
    semaphore = asyncio.Semaphore(MAX_SNMP_CONCURRENCY)

    async def guarded(ip: str) -> Switch:
        async with semaphore:
            return await _query_switch(engine, module, ip, community, timeout, retries)

    return list(await asyncio.gather(*(guarded(ip) for ip in switch_ips)))


def run_snmp_module(switch_ips: Sequence[str], community: str,
                    timeout: float = SNMP_TIMEOUT,
                    retries: int = SNMP_RETRIES) -> list[Switch]:
    """Synchronous entry point for the SNMP module.

    Args:
        switch_ips: The managed switch IPs to query.
        community: The SNMP community string.
        timeout: Per-request timeout in seconds.
        retries: Per-request retry count.

    Returns:
        One :class:`Switch` per IP.

    Raises:
        SnmpUnavailable: If pysnmp is not installed.
    """
    _load_pysnmp()  # Fail fast with a clear error if pysnmp is missing.
    return asyncio.run(
        _query_all_switches(switch_ips, community, timeout, retries)
    )


def build_mac_port_map(switches: Sequence[Switch]) -> dict[str, tuple[str, str]]:
    """Merge switch forwarding tables into a MAC-to-(switch, port) map.

    When a MAC is seen on several ports (its access port plus every uplink it
    is flooded across), the port carrying the fewest MACs wins. An access port
    typically shows a single MAC, while a trunk or uplink shows many, so this
    picks the edge port the device actually plugs into.

    Args:
        switches: The queried switches.

    Returns:
        A mapping of MAC address to ``(switch_ip, interface_name)``.
    """
    port_mac_counts: dict[tuple[str, str], int] = {}
    for switch in switches:
        if not switch.reachable:
            continue
        for port in switch.mac_ports.values():
            port_mac_counts[(switch.ip, port)] = (
                port_mac_counts.get((switch.ip, port), 0) + 1
            )

    best: dict[str, tuple[str, str, int]] = {}
    for switch in switches:
        if not switch.reachable:
            continue
        for mac, port in switch.mac_ports.items():
            count = port_mac_counts[(switch.ip, port)]
            current = best.get(mac)
            if current is None or count < current[2]:
                best[mac] = (switch.ip, port, count)
    return {mac: (ip, port) for mac, (ip, port, _count) in best.items()}


def correlate_devices(
    results: Sequence[HostResult], mac_port_map: dict[str, tuple[str, str]]
) -> None:
    """Annotate discovered devices with the switch and port they sit on.

    Args:
        results: The host results to annotate in place.
        mac_port_map: Output of :func:`build_mac_port_map`.
    """
    for host in results:
        if host.is_live and host.mac and host.mac in mac_port_map:
            host.switch, host.port = mac_port_map[host.mac]


def switch_uplinks(switches: Sequence[Switch]) -> list[UplinkLink]:
    """Derive LLDP links, flagging those that reach another queried switch.

    Args:
        switches: The queried switches.

    Returns:
        One :class:`UplinkLink` per LLDP neighbor seen on a reachable switch.
    """
    known_sysnames = {
        switch.sysname for switch in switches if switch.sysname
    }
    links: list[UplinkLink] = []
    for switch in switches:
        if not switch.reachable:
            continue
        for neighbor in switch.neighbors:
            remote_label = (
                neighbor.remote_sysname or neighbor.remote_chassis or "unknown"
            )
            links.append(
                UplinkLink(
                    local_ip=switch.ip,
                    local_label=switch.sysname or switch.ip,
                    local_port=neighbor.local_port,
                    remote_label=remote_label,
                    remote_port=neighbor.remote_port,
                    is_switch=bool(neighbor.remote_sysname)
                    and neighbor.remote_sysname in known_sysnames,
                )
            )
    return links


def print_snmp_summary(switches: Sequence[Switch]) -> None:
    """Print per-switch SNMP status and the discovered LLDP uplinks."""
    print("SNMP switch-port mapping")
    for switch in switches:
        if switch.reachable:
            label = switch.sysname or switch.ip
            print(
                f"  {switch.ip}  {label}  reachable  "
                f"({len(switch.mac_ports)} MAC entries, "
                f"{len(switch.neighbors)} LLDP neighbors)"
            )
        else:
            print(f"  {switch.ip}  unreachable ({switch.error or 'no response'})")

    links = switch_uplinks(switches)
    uplinks = [link for link in links if link.is_switch]
    if uplinks:
        print("  Switch-to-switch uplinks (LLDP):")
        seen: set[tuple[str, str]] = set()
        for link in uplinks:
            key = tuple(sorted((link.local_label, link.remote_label)))
            if key in seen:
                continue
            seen.add(key)
            print(
                f"    {link.local_label} {link.local_port}  <->  "
                f"{link.remote_label} {link.remote_port}"
            )
    others = [link for link in links if not link.is_switch]
    if others:
        print("  Other LLDP neighbors:")
        for link in others:
            print(
                f"    {link.local_label} {link.local_port}  ->  "
                f"{link.remote_label} {link.remote_port}"
            )


def group_into_segments(
    results: Sequence[HostResult],
    network: IPNetwork,
    gateway: Optional[str],
    neighbors: dict[str, str],
) -> list[Segment]:
    """Group live hosts into network segments by subnet and gateway.

    This tool scans a single CIDR, so it forms exactly one segment: the scanned
    subnet. The return type is a list so the renderers also support a future
    multi-subnet scan with no change. The default gateway is attached only when
    it falls inside the scanned subnet; when it was not itself discovered live,
    a separate enriched node is built for it so the map still shows the router.

    Args:
        results: All host results from :func:`discover`.
        network: The scanned network.
        gateway: The detected default gateway IP, or ``None``.
        neighbors: The IP-to-MAC mapping, used to enrich an undiscovered gateway.

    Returns:
        A list holding the single segment for the scanned subnet.
    """
    live = sorted(
        (result for result in results if result.is_live),
        key=lambda result: ipaddress.ip_address(result.ip),
    )

    gateway_ip = gateway if (gateway and _ip_in_network(gateway, network)) else None
    gateway_device: Optional[HostResult] = None
    if gateway_ip:
        match = next((host for host in live if host.ip == gateway_ip), None)
        if match is not None:
            gateway_device = match
        else:
            # The gateway ignored our probes but is still a real device.
            gateway_device = HostResult(ip=gateway_ip)
            enrich_host(gateway_device, neighbors)

    segment = Segment(
        network=str(network),
        gateway=gateway_ip,
        devices=live,
        gateway_device=gateway_device,
    )
    return [segment]


def format_tree(segments: Sequence[Segment]) -> str:
    """Render the segment grouping as an indented ASCII tree.

    Args:
        segments: The segments to render.

    Returns:
        The tree as a single string, without a trailing newline.
    """
    lines = ["network"]
    for seg_index, segment in enumerate(segments):
        seg_last = seg_index == len(segments) - 1
        seg_branch = "`-- " if seg_last else "|-- "
        gateway_text = (
            f"(gateway: {segment.gateway})" if segment.gateway else "(gateway: unknown)"
        )
        lines.append(f"{seg_branch}{segment.network}  {gateway_text}")
        child_prefix = "    " if seg_last else "|   "

        # List the gateway first when it was not among the discovered devices.
        members = list(segment.devices)
        if segment.gateway_device is not None and segment.gateway_device not in members:
            members = [segment.gateway_device] + members

        if not members:
            lines.append(f"{child_prefix}`-- (no live hosts)")
            continue

        ip_width = max(len(host.ip) for host in members)
        host_width = max(len(host.hostname or "-") for host in members)
        vendor_width = max(len(host.vendor or "-") for host in members)

        for dev_index, host in enumerate(members):
            dev_last = dev_index == len(members) - 1
            dev_branch = "`-- " if dev_last else "|-- "
            is_gateway = (
                segment.gateway_device is not None
                and host.ip == segment.gateway_device.ip
            )
            marker = "  [gateway]" if is_gateway else ""
            switch_text = f"  @ {host.switch}:{host.port}" if host.switch else ""
            line = (
                f"{child_prefix}{dev_branch}"
                f"{host.ip.ljust(ip_width)}  "
                f"{(host.hostname or '-').ljust(host_width)}  "
                f"{(host.vendor or '-').ljust(vendor_width)}  "
                f"{host.device_type}{switch_text}{marker}"
            )
            lines.append(line)
    return "\n".join(lines)


def _dot_escape(text: str) -> str:
    """Escape a string for use inside a double-quoted DOT label."""
    return text.replace("\\", "\\\\").replace('"', '\\"')


def _dot_node_id(ip: str) -> str:
    """Return a quoted DOT node id for an IP address."""
    return '"' + ip + '"'


def _dot_label(host: HostResult, is_gateway: bool) -> str:
    """Build a multi-line DOT node label for a host."""
    parts = [host.ip]
    if host.hostname:
        parts.append(host.hostname)
    if host.vendor:
        parts.append(host.vendor)
    parts.append(host.device_type)
    if is_gateway:
        parts.append("[gateway]")
    return "\\n".join(_dot_escape(part) for part in parts)


def _build_dot_logical(segments: Sequence[Segment]) -> str:
    """Build a Graphviz DOT document for the segment model.

    Each segment becomes a cluster. Within a segment, devices connect to a hub:
    the gateway node when one is known (which in turn connects to an "Internet"
    node), or a synthetic segment node otherwise. Render the output with, for
    example, ``dot -Tpng map.dot -o map.png``.

    Args:
        segments: The segments to render.

    Returns:
        The DOT document as a string, ending with a newline.
    """
    out: list[str] = []
    out.append("graph network_map {")
    out.append('  graph [rankdir=LR, fontname="Helvetica", fontsize=12];')
    out.append(
        '  node [fontname="Helvetica", fontsize=10, shape=box, '
        'style="rounded,filled", fillcolor="#f5f5f5"];'
    )
    out.append('  edge [color="#888888"];')
    out.append("")

    if any(segment.gateway_device for segment in segments):
        out.append(
            '  "internet" [label="Internet", shape=ellipse, '
            'style=filled, fillcolor="#dddddd"];'
        )
        out.append("")

    # Node declarations, grouped into one cluster per segment.
    for index, segment in enumerate(segments):
        out.append(f"  subgraph cluster_{index} {{")
        out.append(f'    label="{_dot_escape(segment.network)}";')
        out.append("    style=rounded;")
        out.append('    color="#4472c4";')
        out.append('    fontname="Helvetica";')

        members = list(segment.devices)
        if (
            segment.gateway_device is not None
            and segment.gateway_device not in members
        ):
            members = members + [segment.gateway_device]

        if not members:
            out.append(
                f'    "seg{index}_empty" '
                '[label="(no live hosts)", shape=plaintext, style=""];'
            )
        for host in members:
            is_gateway = (
                segment.gateway_device is not None
                and host.ip == segment.gateway_device.ip
            )
            shape = "box3d" if is_gateway else "box"
            out.append(
                f'    {_dot_node_id(host.ip)} '
                f'[label="{_dot_label(host, is_gateway)}", shape={shape}];'
            )

        if segment.gateway_device is None and segment.devices:
            out.append(
                f'    "seg{index}_hub" '
                f'[label="{_dot_escape(segment.network)}\\n(segment)", '
                'shape=ellipse, style=filled, fillcolor="#dddddd"];'
            )
        out.append("  }")
        out.append("")

    # Edges.
    for index, segment in enumerate(segments):
        if segment.gateway_device is not None:
            hub = _dot_node_id(segment.gateway_device.ip)
            out.append(f'  "internet" -- {hub};')
            for host in segment.devices:
                if host.ip == segment.gateway_device.ip:
                    continue
                out.append(f"  {hub} -- {_dot_node_id(host.ip)};")
        elif segment.devices:
            hub = f'"seg{index}_hub"'
            for host in segment.devices:
                out.append(f"  {hub} -- {_dot_node_id(host.ip)};")

    out.append("}")
    return "\n".join(out) + "\n"


def build_dot(
    segments: Sequence[Segment], switches: Optional[Sequence[Switch]] = None
) -> str:
    """Build a Graphviz DOT document for the network.

    With reachable SNMP switch data, devices attach to their switch by port and
    switch-to-switch LLDP uplinks are drawn (a physical map). Without it, the
    logical gateway-based map is produced. Render with, for example,
    ``dot -Tpng map.dot -o map.png``.

    Args:
        segments: The segments to render.
        switches: Optional SNMP switch results; triggers the physical map.

    Returns:
        The DOT document as a string, ending with a newline.
    """
    if switches and any(getattr(switch, "reachable", False) for switch in switches):
        return _build_dot_physical(segments, switches)
    return _build_dot_logical(segments)


def _build_dot_physical(
    segments: Sequence[Segment], switches: Sequence[Switch]
) -> str:
    """Build a physical DOT map: devices to switch ports, plus LLDP uplinks."""
    reachable = [switch for switch in switches if switch.reachable]
    sysname_to_ip = {sw.sysname: sw.ip for sw in reachable if sw.sysname}

    out: list[str] = []
    out.append("graph network_map {")
    out.append('  graph [rankdir=LR, fontname="Helvetica", fontsize=12];')
    out.append(
        '  node [fontname="Helvetica", fontsize=10, shape=box, '
        'style="rounded,filled", fillcolor="#f5f5f5"];'
    )
    out.append('  edge [color="#888888"];')
    out.append("")

    if any(segment.gateway_device for segment in segments):
        out.append(
            '  "internet" [label="Internet", shape=ellipse, '
            'style=filled, fillcolor="#dddddd"];'
        )
        out.append("")

    for switch in reachable:
        label = switch.ip
        if switch.sysname:
            label += "\\n" + switch.sysname
        label += "\\n[switch]"
        out.append(
            f'  "sw_{switch.ip}" [label="{_dot_escape(label)}", '
            'shape=box3d, style=filled, fillcolor="#ffe8b3"];'
        )
    out.append("")

    for index, segment in enumerate(segments):
        out.append(f"  subgraph cluster_{index} {{")
        out.append(f'    label="{_dot_escape(segment.network)}";')
        out.append("    style=rounded;")
        out.append('    color="#4472c4";')
        out.append('    fontname="Helvetica";')

        members = list(segment.devices)
        if (
            segment.gateway_device is not None
            and segment.gateway_device not in members
        ):
            members = members + [segment.gateway_device]

        if not members:
            out.append(
                f'    "seg{index}_empty" '
                '[label="(no live hosts)", shape=plaintext, style=""];'
            )
        for host in members:
            is_gateway = (
                segment.gateway_device is not None
                and host.ip == segment.gateway_device.ip
            )
            shape = "box3d" if is_gateway else "box"
            out.append(
                f'    {_dot_node_id(host.ip)} '
                f'[label="{_dot_label(host, is_gateway)}", shape={shape}];'
            )

        unmapped = [host for host in segment.devices if not host.switch]
        if segment.gateway_device is None and unmapped:
            out.append(
                f'    "seg{index}_hub" '
                f'[label="{_dot_escape(segment.network)}\\n(segment)", '
                'shape=ellipse, style=filled, fillcolor="#dddddd"];'
            )
        out.append("  }")
        out.append("")

    for index, segment in enumerate(segments):
        if segment.gateway_device is not None:
            out.append(
                f'  "internet" -- {_dot_node_id(segment.gateway_device.ip)};'
            )
            fallback: Optional[str] = _dot_node_id(segment.gateway_device.ip)
        elif any(not host.switch for host in segment.devices):
            fallback = f'"seg{index}_hub"'
        else:
            fallback = None

        for host in segment.devices:
            if host.switch:
                out.append(
                    "  "
                    + _dot_node_id(host.ip)
                    + ' -- "sw_'
                    + host.switch
                    + '" [label="'
                    + _dot_escape(host.port or "")
                    + '"];'
                )
            elif fallback is not None and not (
                segment.gateway_device is not None
                and host.ip == segment.gateway_device.ip
            ):
                out.append(f"  {fallback} -- {_dot_node_id(host.ip)};")

    seen: set[tuple[str, str]] = set()
    for switch in reachable:
        for neighbor in switch.neighbors:
            remote_ip = sysname_to_ip.get(neighbor.remote_sysname)
            if remote_ip and remote_ip != switch.ip:
                key = tuple(sorted((switch.ip, remote_ip)))
                if key in seen:
                    continue
                seen.add(key)
                edge_label = _dot_escape(
                    f"{neighbor.local_port}<->{neighbor.remote_port}"
                )
                out.append(
                    f'  "sw_{switch.ip}" -- "sw_{remote_ip}" '
                    f'[label="{edge_label}", style=bold, color="#d08400"];'
                )

    out.append("}")
    return "\n".join(out) + "\n"


def print_report(
    results: Sequence[HostResult], total: int, show_switch_port: bool = False
) -> None:
    """Print a table of the live hosts to standard output.

    Args:
        results: Every host result from the scan.
        total: How many hosts were scanned, for the summary line.
        show_switch_port: Add SWITCH and PORT columns (set when SNMP ran).
    """
    live = [result for result in results if result.is_live]
    if not live:
        print(f"No live hosts found ({total} scanned).")
        return

    headers = [
        "IP ADDRESS", "OPEN PORTS", "PING", "MAC ADDRESS",
        "VENDOR", "HOSTNAME", "DEVICE TYPE",
    ]
    if show_switch_port:
        headers += ["SWITCH", "PORT"]

    rows: list[tuple[str, ...]] = []
    for result in live:
        row = [
            result.ip,
            ",".join(str(port) for port in result.open_ports) or "-",
            "yes" if result.pinged else "no",
            result.mac or "-",
            result.vendor or "-",
            result.hostname or "-",
            result.device_type,
        ]
        if show_switch_port:
            row += [result.switch or "-", result.port or "-"]
        rows.append(tuple(row))

    widths = [
        max(len(headers[col]), *(len(row[col]) for row in rows))
        for col in range(len(headers))
    ]

    gap = "  "
    print(gap.join(headers[col].ljust(widths[col]) for col in range(len(headers))))
    print(gap.join("-" * widths[col] for col in range(len(headers))))
    for row in rows:
        print(gap.join(row[col].ljust(widths[col]) for col in range(len(headers))))
    print()
    print(f"{len(live)} live host(s) of {total} scanned.")


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser.

    Returns:
        A configured :class:`argparse.ArgumentParser`.
    """
    parser = argparse.ArgumentParser(
        description=(
            "Discover live hosts on a network with TCP connect probes and a "
            "single ICMP ping per host, enrich each with MAC, vendor, hostname "
            "and a device-type guess, then group them into segments."
        )
    )
    parser.add_argument(
        "cidr",
        type=parse_cidr,
        help=(
            "Target network in CIDR notation, for example 192.168.1.0/24 "
            f"(at most {MAX_HOSTS} hosts)."
        ),
    )
    parser.add_argument(
        "-p",
        "--ports",
        type=parse_ports,
        default=COMMON_PORTS,
        help=(
            "Comma-separated TCP ports to probe (default: "
            f"{','.join(str(port) for port in COMMON_PORTS)})."
        ),
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=positive_float,
        default=DEFAULT_TIMEOUT,
        help=f"Per-probe timeout in seconds (default: {DEFAULT_TIMEOUT}).",
    )
    parser.add_argument(
        "-w",
        "--workers",
        type=positive_int,
        default=DEFAULT_WORKERS,
        help=(
            f"Worker thread count (default: {DEFAULT_WORKERS}, hard-capped at "
            f"{MAX_WORKERS})."
        ),
    )
    parser.add_argument(
        "--map",
        dest="map_file",
        metavar="FILE",
        help="Write the network map as a Graphviz DOT file to FILE.",
    )
    parser.add_argument(
        "--switches",
        type=parse_switch_list,
        metavar="IP[,IP...]",
        help=(
            "Comma-separated managed switch IPs to query over SNMP for "
            "switch-port mapping. Reads the community string from the "
            "SNMP_COMMUNITY environment variable, or prompts for it. Requires "
            "the pysnmp library; skipped gracefully if it is missing."
        ),
    )
    parser.add_argument(
        "--authorized",
        action="store_true",
        help=(
            "Confirm you are authorized to scan the target. REQUIRED: the tool "
            "refuses to run without it. Only scan networks you own or have "
            "explicit written permission to test."
        ),
    )
    parser.add_argument(
        "--rate",
        type=positive_float,
        default=DEFAULT_RATE,
        metavar="N",
        help=(
            "Cap probe starts to N hosts per second "
            f"(default: {DEFAULT_RATE})."
        ),
    )
    parser.add_argument(
        "--log",
        dest="log_path",
        metavar="FILE",
        help=(
            "Log file path (default: a timestamped netdiscover-*.log in the "
            "current directory). The SNMP community string is never logged."
        ),
    )
    return parser


def setup_logging(log_path: Optional[str]) -> tuple[logging.Logger, Optional[str]]:
    """Attach a file handler to the module logger, using a timestamped file.

    Args:
        log_path: Explicit log path, or ``None`` for a timestamped default in
            the current directory.

    Returns:
        The configured logger and the path actually opened (``None`` if no file
        could be created, in which case logging is silently dropped and the
        scan still runs).
    """
    if not log_path:
        stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        log_path = f"netdiscover-{stamp}.log"

    log.setLevel(logging.INFO)
    for handler in list(log.handlers):
        log.removeHandler(handler)

    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s %(message)s", datefmt="%Y-%m-%dT%H:%M:%S%z"
    )
    try:
        handler: logging.Handler = logging.FileHandler(log_path, encoding="utf-8")
    except OSError as exc:
        print(f"warning: cannot open log file {log_path!r}: {exc}", file=sys.stderr)
        log.addHandler(logging.NullHandler())
        return log, None
    handler.setFormatter(formatter)
    log.addHandler(handler)
    return log, log_path


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the tool from command-line arguments.

    Args:
        argv: Argument list to parse. Defaults to ``sys.argv[1:]``.

    Returns:
        A process exit code: 0 on success, 1 on an error, 2 if the run is not
        authorized.
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    logger, log_path = setup_logging(args.log_path)

    # Authorization gate: refuse before any network activity happens.
    if not args.authorized:
        logger.warning("Refused: run attempted without --authorized (target=%s)", args.cidr)
        print(
            "Refusing to run without --authorized.\n"
            "Only scan networks you own or have explicit written permission to "
            "scan. Re-run with --authorized to confirm you are permitted.",
            file=sys.stderr,
        )
        return 2

    total = len(list(args.cidr.hosts()))
    ports_text = ",".join(str(port) for port in args.ports)
    workers = max(1, min(args.workers, MAX_WORKERS))

    logger.info(
        "Authorized scan start: target=%s ports=%s workers=%d rate=%.1f/s switches=%s",
        args.cidr, ports_text, workers, args.rate,
        ",".join(args.switches) if args.switches else "none",
    )
    if log_path:
        print(f"Logging actions to {log_path}", file=sys.stderr)
    print(
        f"Scanning {args.cidr} ({total} hosts) on ports {ports_text} ...",
        file=sys.stderr,
    )

    try:
        limiter = RateLimiter(args.rate)
        results = discover(args.cidr, args.ports, args.timeout, workers, limiter)
        live_count = sum(1 for result in results if result.is_live)
        logger.info("Discovery complete: %d live of %d scanned", live_count, total)

        neighbors = read_neighbor_table()
        enrich_hosts(results, neighbors, workers)
        gateway = detect_default_gateway()
        logger.info("Default gateway: %s", gateway or "unknown")
        segments = group_into_segments(results, args.cidr, gateway, neighbors)

        # Optional SNMP switch-port mapping module.
        switches: list[Switch] = []
        snmp_ran = False
        if args.switches:
            community = resolve_snmp_community()
            if community is None:
                logger.warning("SNMP skipped: no community string available")
                print(
                    "SNMP: no community string available (set SNMP_COMMUNITY or "
                    "run interactively); skipping switch-port mapping.",
                    file=sys.stderr,
                )
            else:
                # Log only the source of the community, never the value.
                source = (
                    "SNMP_COMMUNITY env var"
                    if os.environ.get("SNMP_COMMUNITY")
                    else "interactive prompt"
                )
                logger.info(
                    "SNMP: community loaded from %s; querying %d switch(es)",
                    source, len(args.switches),
                )
                try:
                    switches = run_snmp_module(args.switches, community)
                    snmp_ran = True
                    for switch in switches:
                        if switch.reachable:
                            logger.info(
                                "SNMP %s: reachable (%d MAC entries, %d LLDP neighbors)",
                                switch.ip, len(switch.mac_ports), len(switch.neighbors),
                            )
                        else:
                            logger.warning(
                                "SNMP %s: unreachable (%s)",
                                switch.ip, switch.error or "no response",
                            )
                except SnmpUnavailable as exc:
                    logger.warning("SNMP skipped: pysnmp unavailable (%s)", exc)
                    print(
                        f"SNMP: pysnmp is not available ({exc}); skipping "
                        "switch-port mapping. Install it with: pip install pysnmp",
                        file=sys.stderr,
                    )
            if snmp_ran:
                correlate_devices(results, build_mac_port_map(switches))

        print_report(results, total, show_switch_port=snmp_ran)
        print()
        print(format_tree(segments))
        if snmp_ran:
            print()
            print_snmp_summary(switches)

        if args.map_file:
            dot = build_dot(segments, switches if snmp_ran else None)
            try:
                with open(args.map_file, "w", encoding="utf-8") as handle:
                    handle.write(dot)
            except OSError as exc:
                logger.error("Map write failed (%s): %s", args.map_file, exc)
                print(
                    f"error: could not write map to {args.map_file}: {exc}",
                    file=sys.stderr,
                )
                return 1
            logger.info("Network map written: %s", args.map_file)
            print()
            print(f"Network map written to {args.map_file}")
            print(f"Render it with: dot -Tpng {args.map_file} -o network_map.png")

        logger.info("Scan complete")
        return 0
    except Exception as exc:  # Graceful catch-all: log, report, no traceback.
        logger.exception("Unexpected error during scan")
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(130)
