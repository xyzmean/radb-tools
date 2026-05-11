#!/usr/bin/env python3
"""
Fetch extra IPv4 prefix sources and output aggregated CIDRs to stdout.

Sources:
  1. russia-mobile-internet-whitelist CIDR list
  2. geoip:RU + geoip:CN from Loyalsoldier v2ray-rules-dat (geoip.dat, protobuf)
  3. geosite:RU + geosite:CN domain resolution from geosite.dat (Yandex+Google DNS)
"""
import io
import sys
import socket
import ipaddress
import requests
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
from aggregate_prefixes import aggregate_prefixes

CIDRWHITELIST_URL = (
    'https://github.com/hxehex/russia-mobile-internet-whitelist'
    '/raw/refs/heads/main/cidrwhitelist.txt'
)
GEOIP_URL   = 'https://github.com/Loyalsoldier/v2ray-rules-dat/raw/release/geoip.dat'
GEOSITE_URL = 'https://github.com/Loyalsoldier/v2ray-rules-dat/raw/release/geosite.dat'
GEOIP_CATEGORIES   = {'RU', 'CN'}
GEOSITE_CATEGORIES = {'RU', 'CATEGORY-RU', 'CATEGORY-IP-GEO-DETECT'}

_resolvers = []
for _ns in (['77.88.8.8', '77.88.8.1'], ['8.8.8.8', '8.8.4.4']):
    _r = dns.resolver.Resolver()
    _r.nameservers = _ns
    _r.lifetime = 3.0
    _resolvers.append(_r)


def resolve_host(host):
    ips = set()
    for r in _resolvers:
        try:
            ips.update(str(a) for a in r.resolve(host, 'A'))
        except Exception:
            pass
    return list(ips)


# ── minimal protobuf wire-format parser ──────────────────────────────────────

def _read_varint(buf):
    result, shift = 0, 0
    while True:
        b = buf.read(1)
        if not b:
            raise EOFError
        b = b[0]
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result
        shift += 7


def _iter_fields(data):
    """Yield (field_number, wire_type, value) from raw protobuf bytes."""
    buf, end = io.BytesIO(data), len(data)
    while buf.tell() < end:
        try:
            tag = _read_varint(buf)
        except EOFError:
            break
        field, wt = tag >> 3, tag & 0x7
        if wt == 0:
            val = _read_varint(buf)
        elif wt == 2:
            val = buf.read(_read_varint(buf))
        elif wt == 1:
            val = buf.read(8)
        elif wt == 5:
            val = buf.read(4)
        else:
            break
        yield field, wt, val


# ── geoip.dat parser ─────────────────────────────────────────────────────────
# GeoIPList { repeated GeoIP entry = 1; }
# GeoIP     { string country_code = 1; repeated CIDR cidr = 2; }
# CIDR      { bytes ip = 1; uint32 prefix = 2; }

def parse_geoip(data, target_codes):
    nets = []
    for f, wt, val in _iter_fields(data):
        if f != 1 or wt != 2:
            continue
        code = None
        entry_cidrs = []
        for f2, wt2, val2 in _iter_fields(val):
            if f2 == 1 and wt2 == 2:
                code = val2.decode()
            elif f2 == 2 and wt2 == 2:
                ip_b, prefix = None, 0
                for f3, wt3, val3 in _iter_fields(val2):
                    if f3 == 1 and wt3 == 2:
                        ip_b = val3
                    elif f3 == 2 and wt3 == 0:
                        prefix = val3
                if ip_b and len(ip_b) == 4:
                    entry_cidrs.append(f'{socket.inet_ntoa(ip_b)}/{prefix}')
        if code in target_codes:
            nets.extend(entry_cidrs)
    return nets


# ── geosite.dat parser ───────────────────────────────────────────────────────
# GeoSiteList { repeated GeoSite entry = 1; }
# GeoSite     { string country_code = 1; repeated Domain domain = 2; }
# Domain      { Type type = 1; string value = 2; }   (Type 2=Domain, 3=Full)

def parse_geosite(data, target_codes):
    """Return list of hostnames to resolve.

    Type 2 (Domain suffix, e.g. 'yandex.ru') → emit both apex and www. prefix,
    since subdomains cannot be enumerated but www covers most web traffic.
    Type 3 (Full match) → emit as-is.
    Types 0/1 (Plain/Regex) → skip, not resolvable via DNS.
    """
    domains = []
    for f, wt, val in _iter_fields(data):
        if f != 1 or wt != 2:
            continue
        code = None
        entry_domains = []
        for f2, wt2, val2 in _iter_fields(val):
            if f2 == 1 and wt2 == 2:
                code = val2.decode()
            elif f2 == 2 and wt2 == 2:
                dtype, dval = 0, None
                for f3, wt3, val3 in _iter_fields(val2):
                    if f3 == 1 and wt3 == 0:
                        dtype = val3
                    elif f3 == 2 and wt3 == 2:
                        dval = val3.decode()
                if dval:
                    if dtype == 2:    # Domain suffix: try apex + www
                        entry_domains.append(dval)
                        entry_domains.append('www.' + dval)
                    elif dtype == 3:  # Full match: exact hostname
                        entry_domains.append(dval)
        if code in target_codes:
            domains.extend(entry_domains)
    return domains


# ── main ─────────────────────────────────────────────────────────────────────

def main():
    all_prefixes = []

    # 1. russia-mobile-internet-whitelist
    print('Fetching cidrwhitelist.txt...', file=sys.stderr)
    resp = requests.get(CIDRWHITELIST_URL, timeout=30)
    count = 0
    for line in resp.text.splitlines():
        line = line.strip()
        if line and not line.startswith('#'):
            try:
                ipaddress.ip_network(line, strict=False)
                all_prefixes.append(line)
                count += 1
            except ValueError:
                pass
    print(f'  {count} CIDRs', file=sys.stderr)

    # 2. geoip.dat → RU + CN IPv4 CIDRs
    print('Fetching geoip.dat...', file=sys.stderr)
    geoip_data = requests.get(GEOIP_URL, timeout=60).content
    geoip_nets = parse_geoip(geoip_data, GEOIP_CATEGORIES)
    print(f'  {len(geoip_nets)} IPv4 CIDRs ({sorted(GEOIP_CATEGORIES)})', file=sys.stderr)
    all_prefixes.extend(geoip_nets)

    # 3. geosite.dat → RU + CATEGORY-RU domains → resolve to IPs
    print('Fetching geosite.dat...', file=sys.stderr)
    geosite_data = requests.get(GEOSITE_URL, timeout=60).content
    domains = list(set(parse_geosite(geosite_data, GEOSITE_CATEGORIES)))
    print(f'  {len(domains)} unique domains to resolve...', file=sys.stderr)

    resolved = 0
    with ThreadPoolExecutor(max_workers=50) as ex:
        futures = {ex.submit(resolve_host, d): d for d in domains}
        for fut in as_completed(futures):
            ips = fut.result()
            if ips:
                resolved += 1
                for ip in ips:
                    all_prefixes.append(ip + '/32')
    print(f'  Resolved {resolved}/{len(domains)} domains', file=sys.stderr)

    result = sorted(
        aggregate_prefixes(all_prefixes),
        key=lambda x: ipaddress.ip_network(x),
    )
    print(f'Extra sources total: {len(result)} aggregated prefixes', file=sys.stderr)
    for prefix in result:
        print(prefix)


if __name__ == '__main__':
    main()
