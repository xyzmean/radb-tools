#!/usr/bin/env python3
"""
Filter IP prefix list by excluding entries from disallow.lst.

Supported entry types in disallow.lst:
  - CIDR subnet:   1.2.3.0/24
  - IP address:    1.2.3.4
  - Domain name:   example.com   (resolved via DNS at runtime)
  - AS number:     AS12345       (resolved to announced prefixes via RIPE API)

Subnet splitting: if a disallowed IP/subnet falls inside a prefix,
that prefix is split into smaller subnets covering everything except
the excluded range.

Usage: filter-disallow.py <prefixes.lst> <disallow.lst>
"""
import re
import sys
import socket
import ipaddress
import requests
from aggregate_prefixes import aggregate_prefixes

AS_RE = re.compile(r'^[Aa][Ss]\d+$')


def resolve_host(host):
    try:
        results = socket.getaddrinfo(host, None, socket.AF_INET)
        return list({r[4][0] for r in results})
    except OSError:
        return []


def resolve_asn(asn_str):
    """Return list of IPv4Network announced by the given ASN (e.g. 'AS45102')."""
    num = asn_str.upper().lstrip('AS')
    url = f'https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{num}'
    try:
        data = requests.get(url, timeout=20).json()
        nets = []
        for entry in data.get('data', {}).get('prefixes', []):
            prefix = entry.get('prefix', '')
            try:
                net = ipaddress.ip_network(prefix, strict=False)
                if isinstance(net, ipaddress.IPv4Network):
                    nets.append(net)
            except ValueError:
                pass
        return nets
    except Exception as e:
        print(f"Warning: could not resolve {asn_str}: {e}", file=sys.stderr)
        return []


def subtract_from_list(networks, excl_net):
    result = []
    for net in networks:
        try:
            if net.subnet_of(excl_net):
                continue                          # entirely excluded
            elif excl_net.subnet_of(net):
                result.extend(net.address_exclude(excl_net))  # split
            else:
                result.append(net)
        except TypeError:
            result.append(net)
    return result


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <prefixes.lst> <disallow.lst>", file=sys.stderr)
        sys.exit(1)

    prefixes_file, disallow_file = sys.argv[1], sys.argv[2]

    networks = []
    with open(prefixes_file) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                try:
                    networks.append(ipaddress.ip_network(line, strict=False))
                except ValueError:
                    print(f"Warning: invalid prefix {line!r}, skipping", file=sys.stderr)

    excl_nets = []
    with open(disallow_file) as f:
        for line in f:
            entry = line.strip()
            if not entry or entry.startswith('#'):
                continue

            # AS number
            if AS_RE.match(entry):
                nets = resolve_asn(entry)
                if nets:
                    excl_nets.extend(nets)
                    print(f"  {entry}: {len(nets)} prefixes", file=sys.stderr)
                else:
                    print(f"Warning: no prefixes found for {entry}", file=sys.stderr)
                continue

            # IP or CIDR
            try:
                excl_nets.append(ipaddress.ip_network(entry, strict=False))
                continue
            except ValueError:
                pass

            # Domain name
            ips = resolve_host(entry)
            if ips:
                print(f"  {entry}: {ips}", file=sys.stderr)
                for ip in ips:
                    excl_nets.append(ipaddress.ip_network(ip + '/32'))
            else:
                print(f"Warning: could not resolve {entry!r}, skipping", file=sys.stderr)

    print(f"Loaded {len(networks)} prefixes, {len(excl_nets)} exclusion entries", file=sys.stderr)

    for excl_net in excl_nets:
        networks = subtract_from_list(networks, excl_net)

    result = sorted(
        aggregate_prefixes(str(n) for n in networks),
        key=lambda x: ipaddress.ip_network(x),
    )
    for prefix in result:
        print(prefix)


if __name__ == '__main__':
    main()
