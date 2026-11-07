#!/usr/bin/env python3
"""Network discovery command-line tool.

Given a target network in CIDR notation, this tool discovers live hosts in two
complementary ways:

1. A TCP connect probe against a small set of commonly open ports. A port that
   accepts a connection within the timeout marks the host as live.
2. A single system ``ping`` per host, issued through :mod:`subprocess`. Besides
   confirming reachability, the echo request makes the operating system resolve
   the host at layer 2, which populates the local ARP / neighbor cache.

A host is reported as live when either probe succeeds. Only the Python standard
library is used.
"""

from __future__ import annotations

import argparse
import ipaddress
import platform
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
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


@dataclass
class HostResult:
    """Outcome of probing a single host.

    Attributes:
        ip: The host address as a string.
        open_port: The first open TCP port found, or ``None`` if none of the
            probed ports accepted a connection.
        pinged: ``True`` if the host answered a single ICMP echo request.
    """

    ip: str
    open_port: Optional[int] = None
    pinged: bool = False

    @property
    def is_live(self) -> bool:
        """Return whether any probe found the host to be up."""
        return self.open_port is not None or self.pinged


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


def tcp_probe(host: str, ports: Sequence[int], timeout: float) -> Optional[int]:
    """Try a TCP connect to each port in turn, stopping at the first that opens.

    Args:
        host: The target address as a string.
        ports: The TCP ports to try, in order.
        timeout: Per-connection timeout in seconds.

    Returns:
        The first open port, or ``None`` if no probed port accepted a
        connection within the timeout.
    """
    for port in ports:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return port
        except OSError:
            # Refused, timed out, unreachable: try the next port.
            continue
    return None


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
        A :class:`HostResult` describing what each probe found.
    """
    open_port = tcp_probe(host, ports, timeout)
    pinged = ping_host(host, timeout)
    return HostResult(ip=host, open_port=open_port, pinged=pinged)


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

    headers = ("IP ADDRESS", "OPEN PORT", "PING")
    rows = [
        (
            result.ip,
            str(result.open_port) if result.open_port is not None else "-",
            "yes" if result.pinged else "no",
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
            "single ICMP ping per host."
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

    hosts = list(args.cidr.hosts())
    total = len(hosts)
    ports_text = ",".join(str(port) for port in args.ports)
    print(
        f"Scanning {args.cidr} ({total} hosts) on ports {ports_text} ...",
        file=sys.stderr,
    )

    results = discover(args.cidr, args.ports, args.timeout, args.workers)
    print_report(results, total)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(130)
