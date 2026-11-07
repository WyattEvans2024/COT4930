#!/usr/bin/env python3
"""Network discovery command-line tool.

Given a target network in CIDR notation, this tool discovers live hosts and
enriches each one with identifying detail.

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

Only the Python standard library is used.
"""

from __future__ import annotations

import argparse
import ipaddress
import platform
import re
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional, Sequence, Union

IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

# Ports probed by default: SSH, HTTP, HTTPS, SMB and RDP.
COMMON_PORTS: tuple[int, ...] = (22, 80, 443, 445, 3389)

# Upper bound on the number of hosts a single invocation may scan.
MAX_HOSTS: int = 1024

# Default per-connection TCP timeout, in seconds.
DEFAULT_TIMEOUT: float = 1.0

# Default size of the worker thread pool.
DEFAULT_WORKERS: int = 100

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
    """

    ip: str
    open_ports: list[int] = field(default_factory=list)
    pinged: bool = False
    mac: Optional[str] = None
    vendor: Optional[str] = None
    hostname: Optional[str] = None
    device_type: str = "unknown"

    @property
    def is_live(self) -> bool:
        """Return whether either discovery probe found the host to be up."""
        return bool(self.open_ports) or self.pinged


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
) -> list[HostResult]:
    """Probe every usable host in a network concurrently.

    Args:
        network: The validated target network.
        ports: The TCP ports to probe on each host.
        timeout: Per-probe timeout in seconds.
        workers: Maximum number of worker threads.

    Returns:
        One :class:`HostResult` per host, sorted by ascending IP address.
    """
    hosts = [str(host) for host in network.hosts()]
    results: list[HostResult] = []
    with ThreadPoolExecutor(max_workers=min(workers, len(hosts))) as executor:
        futures = [
            executor.submit(probe_host, host, ports, timeout) for host in hosts
        ]
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
        result: A live :class:`HostResult` to enrich in place.
        neighbors: The IP-to-MAC mapping from :func:`read_neighbor_table`.
    """
    result.mac = neighbors.get(result.ip)
    result.vendor = lookup_vendor(result.mac)
    result.hostname = reverse_dns(result.ip)
    result.device_type = guess_device_type(result.open_ports, result.vendor)


def enrich_live_hosts(results: Sequence[HostResult], workers: int) -> None:
    """Enrich every live host in place, concurrently.

    Reads the neighbor table once (after the ping sweep has populated it), then
    runs per-host enrichment across a thread pool, mainly to overlap the
    reverse-DNS lookups.

    Args:
        results: All host results from :func:`discover`.
        workers: Maximum number of worker threads.
    """
    neighbors = read_neighbor_table()
    live = [result for result in results if result.is_live]
    if not live:
        return
    with ThreadPoolExecutor(max_workers=min(workers, len(live))) as executor:
        futures = [executor.submit(enrich_host, result, neighbors) for result in live]
        for future in as_completed(futures):
            future.result()


def print_report(results: Sequence[HostResult], total: int) -> None:
    """Print a table of the live hosts to standard output.

    Args:
        results: Every host result from the scan.
        total: How many hosts were scanned, for the summary line.
    """
    live = [result for result in results if result.is_live]
    if not live:
        print(f"No live hosts found ({total} scanned).")
        return

    headers = (
        "IP ADDRESS",
        "OPEN PORTS",
        "PING",
        "MAC ADDRESS",
        "VENDOR",
        "HOSTNAME",
        "DEVICE TYPE",
    )
    rows = [
        (
            result.ip,
            ",".join(str(port) for port in result.open_ports) or "-",
            "yes" if result.pinged else "no",
            result.mac or "-",
            result.vendor or "-",
            result.hostname or "-",
            result.device_type,
        )
        for result in live
    ]
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
            "single ICMP ping per host, then enrich each with MAC, vendor, "
            "hostname, and a device-type guess."
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
        help=f"Worker thread count (default: {DEFAULT_WORKERS}).",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the tool from command-line arguments.

    Args:
        argv: Argument list to parse. Defaults to ``sys.argv[1:]``.

    Returns:
        A process exit code: 0 on success.
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    total = len(list(args.cidr.hosts()))
    ports_text = ",".join(str(port) for port in args.ports)
    print(
        f"Scanning {args.cidr} ({total} hosts) on ports {ports_text} ...",
        file=sys.stderr,
    )

    results = discover(args.cidr, args.ports, args.timeout, args.workers)
    enrich_live_hosts(results, args.workers)
    print_report(results, total)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(130)
