# Network Discovery Tool (`app.py`)

A command-line tool that discovers live hosts on a network, enriches each one
with identifying detail, groups them into segments, and draws a network map.
It is read-only and refuses to run against a real network without an explicit
authorization flag.

## What it does

Given a target network, the tool finds live hosts with TCP connect probes and
one ICMP ping each. For every live host it adds the MAC address (from the local
neighbor table), the hardware vendor (from the MAC's OUI), the reverse-DNS
hostname, and a best-guess device type. It then groups hosts by subnet and
default gateway, prints a table and an indented tree, and can export a Graphviz
map. An optional SNMP module maps each device to the physical switch and port
it sits on and reads LLDP to find switch-to-switch uplinks.

## Requirements

- Python 3.9 or newer. The core tool uses only the standard library.
- `pysnmp` (version 7.x), only for the `--switches` SNMP feature. Install it
  with `pip install pysnmp`. Without it, every other feature still works and
  the SNMP step is skipped with a message.
- Graphviz, only to render a `--map` file into an image. The tool writes the
  DOT text itself with no dependency. Install Graphviz from your package
  manager (`apt install graphviz`, `brew install graphviz`, or
  `choco install graphviz`).

## Usage

```
python app.py <cidr> --authorized [options]
python app.py --self-test [options]
```

The `cidr` target is required unless you pass `--self-test`. A real scan also
requires `--authorized`.

## Flags

- `cidr` (positional, optional): target network in CIDR notation, for example
  `192.168.1.0/24`. Host bits are masked off, so `192.168.1.37/24` is accepted.
  Capped at 1024 hosts. Required unless `--self-test` is used.
- `-p`, `--ports`: comma-separated TCP ports to probe. Default
  `22,80,443,445,3389`. Each port is validated to be in the range 1-65535.
- `-t`, `--timeout`: per-probe timeout in seconds. Default `1.0`.
- `-w`, `--workers`: worker-thread count. Default `100`, hard-capped at `256`.
- `--rate N`: cap probe starts to N hosts per second. Default `100`.
- `--switches IP[,IP...]`: comma-separated managed switch IPs to query over
  SNMP for switch-port mapping. Needs `pysnmp` and a community string. Skipped
  gracefully if either is missing.
- `--authorized`: confirm you are permitted to scan the target. Required for
  any real scan. The tool refuses to run without it.
- `--self-test`: demo mode. Probes only this host and loopback, contacts no
  real network, needs no target and no `--authorized`, and disables SNMP.
- `--map FILE`: write the network map as a Graphviz DOT file to `FILE`.
- `--log FILE`: log file path. Default is a timestamped `netdiscover-*.log` in
  the current directory.
- `-h`, `--help`: show help and exit.

Exit codes: `0` on success, `1` on an error, `2` if a real scan is run without
`--authorized`.

## Example commands

Run the built-in demo against your own machine, no target or authorization
needed:

```
python app.py --self-test
```

Demo and write a map you can render:

```
python app.py --self-test --map demo.dot
```

Scan a /24 you are permitted to test:

```
python app.py 192.168.1.0/24 --authorized
```

Scan with custom ports, a shorter timeout, more workers, and a slower rate:

```
python app.py 10.0.0.0/24 --authorized -p 22,80,443 -t 0.5 -w 128 --rate 50
```

Scan and export a map:

```
python app.py 192.168.1.0/24 --authorized --map net.dot
```

Scan and add SNMP switch-port mapping for two switches:

```
export SNMP_COMMUNITY='your-read-community'
python app.py 192.168.1.0/24 --authorized --switches 10.0.0.2,10.0.0.3 --map net.dot
```

## Rendering the DOT map

`--map` writes a Graphviz DOT file. Turn it into an image with the `dot`
command:

```
dot -Tpng net.dot -o net.png
dot -Tsvg net.dot -o net.svg
```

The map groups devices by subnet. Without SNMP data it draws a logical map:
each device links to its gateway, and the gateway links to an Internet node.
With reachable SNMP switches it draws a physical map instead: each device links
to its switch by port, and switch-to-switch uplinks from LLDP are drawn as bold
edges.

## Supplying the SNMP community string safely

The community string is read only from the `SNMP_COMMUNITY` environment
variable. There is no command-line flag for it on purpose, so it cannot end up
in your shell history or in the process list that other users can see.

Set it for one command:

```
SNMP_COMMUNITY='your-read-community' python app.py 192.168.1.0/24 --authorized --switches 10.0.0.2
```

Or export it for the session:

```
export SNMP_COMMUNITY='your-read-community'      # Linux and macOS
$env:SNMP_COMMUNITY = 'your-read-community'      # Windows PowerShell
set SNMP_COMMUNITY=your-read-community            # Windows cmd
```

If the variable is unset and you run interactively, the tool prompts for the
value without echoing it to the screen. If it is unset and the session is not
interactive, the SNMP step is skipped. The community string is never written to
the log. The log records only where it came from, such as "SNMP_COMMUNITY env
var".

## Output

The tool prints three things to standard output.

A table of live hosts, one row each, with IP address, open ports, ping result,
MAC address, vendor, hostname, and device type. The SNMP run adds SWITCH and
PORT columns.

An indented tree that groups hosts under their segment and marks the gateway.
When SNMP data is present, each host also shows `@ switch:port`.

An SNMP summary, when `--switches` ran, listing each switch as reachable or not
and the switch-to-switch uplinks found through LLDP.

The one-line scan status goes to standard error, so piping standard output
gives you only the report.

## Logs

Every run writes a timestamped log file, `netdiscover-YYYYMMDD-HHMMSS.log` by
default, or the path you give with `--log`. It records the authorization, the
target and settings, discovery counts, the gateway, each switch result, the map
write, and completion, each line stamped in ISO 8601. The default file lands in
the current directory, so if you run from a repository you may want to point
`--log` elsewhere or add `netdiscover-*.log` to your `.gitignore`.

## Security Considerations

### Authorized use

Scanning a network you do not own or administer can be against the law and
against most acceptable-use policies, even when the scan is passive. This tool
requires the `--authorized` flag for any real target and refuses to start
without it. Pass it only when you own the target or hold explicit written
permission to test it. `--self-test` is exempt because it touches only this
host and loopback, which you already control. The authorization decision, and
any refused run, are recorded in the log.

### Read-only by design

The tool never changes any device or switch. It opens TCP connections and
closes them at once, sends one ICMP echo per host, and performs only SNMP GET
and GETNEXT reads. It issues no SNMP SET and writes nothing to a scanned
device. The only files it writes are local: the log and, if you ask for it, the
DOT map.

### Credential handling

The SNMP community string is treated as a secret. It is read only from an
environment variable or a no-echo prompt, is never hardcoded, and is kept out
of the log and the map. Use a read-only community, since the tool needs nothing
more.

### Input validation

Every input is validated before use: the CIDR, each port, and each switch IP.
No user-supplied value reaches a shell, because all subprocess calls pass
argument lists and never use `shell=True`.

### Concurrency and rate limits

Thread count is capped at 256 regardless of `--workers`, and a rate limiter
caps probe starts (100 hosts per second by default, adjustable with `--rate`).
SNMP queries run at most eight switches at once. Lower the rate on sensitive or
congested networks so the scan stays gentle.

### Failure handling

Unreachable hosts, unreachable switches, a missing `pysnmp`, a missing
community string, and file-write errors are all handled without a crash. A
top-level handler logs any unexpected error and exits with a clean message
rather than a traceback.

## Limitations

One scan sees one subnet, so it forms one segment. The gateway line is
meaningful only when the scanned subnet is your local subnet, since a remote
subnet's router cannot be read from here.

MAC and vendor resolve only for hosts on your own layer-2 segment. Anything past
a router shows no MAC, because ARP is local to the segment.

The device type is a heuristic from a small port set and the vendor prefix, not
a fingerprint. Read it as a hint.

Some switches, Cisco in particular, index the Bridge-MIB per VLAN through
community string indexing (the `community@vlan` form), so a single query can
miss MACs in other VLANs. The tool falls back to the VLAN-aware Q-BRIDGE table,
which covers many switches, but per-VLAN queries may be needed for full
coverage. SNMP must also be enabled on each switch with the community you
supply.
