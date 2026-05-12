#!/usr/bin/env python3
"""
Append extra IPs/subnets from an include list to an existing prefix list.

Supported entry types in the include list:
  - Domain name:   example.com   (resolved via Yandex DNS at runtime)
  - IP address:    1.2.3.4
  - CIDR subnet:   1.2.3.0/24
  - AS number:     AS12345       (resolved to announced prefixes via RIPE API)

Usage: filter-disallow.py <prefixes.lst> <extra-include.lst>
Output: aggregated prefix list with include entries merged in, to stdout
"""
import re
import socket
import sys
import ipaddress
import requests
import dns.resolver
from aggregate_prefixes import aggregate_prefixes

AS_RE = re.compile(r'^[Aa][Ss]\d+$')

_resolvers = []
for ns in (['77.88.8.8', '77.88.8.1'], ['8.8.8.8', '8.8.4.4']):
    r = dns.resolver.Resolver()
    r.nameservers = ns
    r.lifetime = 3.0
    _resolvers.append(r)


def resolve_host(host):
    ips = set()
    for r in _resolvers:
        try:
            ips.update(str(a) for a in r.resolve(host, 'A'))
        except Exception:
            pass
    if not ips:
        try:
            ips.update(socket.gethostbyname_ex(host)[2])
        except Exception:
            pass
    return list(ips)


def resolve_asn(asn_str):
    num = asn_str.upper().lstrip('AS')
    url = f'https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{num}'
    try:
        resp = requests.get(url, timeout=20)
        resp.raise_for_status()
        data = resp.json()
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


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <prefixes.lst> <extra-include.lst>", file=sys.stderr)
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

    extra = []
    with open(disallow_file) as f:
        for line in f:
            entry = line.strip()
            if not entry or entry.startswith('#'):
                continue

            if AS_RE.match(entry):
                nets = resolve_asn(entry)
                if nets:
                    extra.extend(nets)
                    print(f"  {entry}: {len(nets)} prefixes", file=sys.stderr)
                else:
                    print(f"Warning: no prefixes found for {entry}", file=sys.stderr)
                continue

            try:
                extra.append(ipaddress.ip_network(entry, strict=False))
                continue
            except ValueError:
                pass

            ips = resolve_host(entry)
            if ips:
                print(f"  {entry}: {ips}", file=sys.stderr)
                for ip in ips:
                    extra.append(ipaddress.ip_network(ip + '/32'))
            else:
                print(f"Warning: could not resolve {entry!r}, skipping", file=sys.stderr)

    print(f"Base: {len(networks)} prefixes, adding {len(extra)} entries", file=sys.stderr)

    networks.extend(extra)

    result = sorted(
        aggregate_prefixes(str(n) for n in networks),
        key=lambda x: ipaddress.ip_network(x),
    )
    for prefix in result:
        print(prefix)


if __name__ == '__main__':
    main()
