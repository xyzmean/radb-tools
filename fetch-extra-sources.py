#!/usr/bin/env python3
"""
Fetch extra IPv4 prefix sources and output aggregated CIDRs to stdout.

Sources:
  1. russia-mobile-internet-whitelist CIDR list
  2. geoip:RU + geoip:CN from Loyalsoldier v2ray-rules-dat (geoip.dat, protobuf)
  3. geosite:RU + geosite:CATEGORY-RU + CATEGORY-IP-GEO-DETECT, plus itdoginfo
     allow-domains (Russia/inside-raw) and v2fly category-ru → DNS-resolved
     via Yandex + Google + system resolver
  4. local pyasn DB (asn.txt + ipasn.lst) for RU+CN — BGP-announced prefixes
"""
import io
import os
import sys
import time
import socket
import ipaddress
import requests
import dns.resolver
import pyasn
from concurrent.futures import ThreadPoolExecutor, as_completed
from aggregate_prefixes import aggregate_prefixes


def fetch_with_retry(url, timeout=60, retries=4):
    """GET with exponential backoff: 2s, 4s, 8s between attempts."""
    last_exc = None
    for attempt in range(retries):
        try:
            resp = requests.get(url, timeout=timeout)
            resp.raise_for_status()
            return resp
        except requests.RequestException as e:
            last_exc = e
            if attempt < retries - 1:
                wait = 2 ** (attempt + 1)
                print(f'  fetch {url} failed ({e}); retrying in {wait}s', file=sys.stderr)
                time.sleep(wait)
    raise last_exc

CIDRWHITELIST_URL = (
    'https://github.com/hxehex/russia-mobile-internet-whitelist'
    '/raw/refs/heads/main/cidrwhitelist.txt'
)
GEOIP_URL   = 'https://github.com/Loyalsoldier/v2ray-rules-dat/raw/release/geoip.dat'
GEOSITE_URL = 'https://github.com/Loyalsoldier/v2ray-rules-dat/raw/release/geosite.dat'
GEOIP_CATEGORIES   = {'RU', 'CN'}
GEOSITE_CATEGORIES = {'RU', 'CATEGORY-RU', 'CATEGORY-IP-GEO-DETECT'}
LOCAL_DB_COUNTRIES = {'RU', 'CN'}

ITDOG_URL = (
    'https://github.com/itdoginfo/allow-domains'
    '/raw/main/Russia/outside-raw.lst'
)
V2FLY_DATA_URL = (
    'https://github.com/v2fly/domain-list-community'
    '/raw/master/data/{name}'
)
V2FLY_MAX_DEPTH = 5

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
    if not ips:
        try:
            ips.update(socket.gethostbyname_ex(host)[2])
        except Exception:
            pass
    return list(ips)


# ── extra RU domain lists ────────────────────────────────────────────────────

def fetch_itdog_domains():
    """Fetch itdoginfo allow-domains Russia/outside-raw.lst (plain domain list).

    outside-raw.lst = RF-geofenced domains accessible only from Russian subnets
    (gosuslugi.ru, fssp.gov.ru, kinopoisk.ru, russianpost.ru, etc.). NOT to be
    confused with inside-raw.lst, which is the inverse (blocked-in-RF).
    """
    resp = fetch_with_retry(ITDOG_URL, timeout=60)
    domains = []
    for line in resp.text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        domains.append(line)
    return domains


def fetch_v2fly_ru_domains():
    """Fetch v2fly category-ru and recursively follow all include: directives.

    category-ru includes ~37 RU-specific sub-categories (tld-ru, beget, yandex,
    kaspersky, mts-ru, rostelecom, etc.) and bare domain entries. Each include
    is fetched as the data/<name> file and parsed the same way; nested includes
    are followed up to V2FLY_MAX_DEPTH. Parses domain:/full:/bare-suffix; skips
    regexp:. Inline @attribute tags are stripped.
    """
    domains = []
    seen = set()

    def parse(name, depth):
        if name in seen or depth > V2FLY_MAX_DEPTH:
            return
        seen.add(name)
        try:
            resp = fetch_with_retry(V2FLY_DATA_URL.format(name=name), timeout=30, retries=2)
        except Exception as e:
            print(f'  v2fly: skip {name} ({e})', file=sys.stderr)
            return
        for raw in resp.text.splitlines():
            line = raw.strip()
            if not line or line.startswith('#'):
                continue
            line = line.split('#', 1)[0].split('@', 1)[0].strip()
            if not line:
                continue
            if ':' in line:
                kind, _, value = line.partition(':')
                kind = kind.strip().lower()
                value = value.strip()
                if not value:
                    continue
                if kind == 'domain':
                    domains.append(value)
                    domains.append('www.' + value)
                elif kind == 'full':
                    domains.append(value)
                elif kind == 'include':
                    parse(value, depth + 1)
                # regexp: skipped
            else:
                domains.append(line)
                domains.append('www.' + line)

    parse('category-ru', 0)
    return domains


# ── local pyasn DB (BGP RIB) ─────────────────────────────────────────────────

def parse_local_db(base_dir, country_codes):
    """Return IPv4 prefixes from local pyasn DB for the given country codes.

    Reads asn.txt to collect ASNs per country and resolves each via ipasn.lst.
    Returns [] if either file is missing (e.g. renew-db was not run).
    """
    asn_path = os.path.join(base_dir, 'asn.txt')
    ipasn_path = os.path.join(base_dir, 'ipasn.lst')
    if not (os.path.exists(asn_path) and os.path.exists(ipasn_path)):
        print('  asn.txt or ipasn.lst missing, skipping local DB', file=sys.stderr)
        return []

    asndb = pyasn.pyasn(ipasn_path)
    with open(asn_path) as f:
        asn_list = [t.split(' ')[0] for t in f if t.split(' ')[-1][:2] in country_codes]

    prefixes = []
    for asn in asn_list:
        prefixes.extend(asndb.get_as_prefixes(asn) or [])
    return prefixes


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
    script_dir = os.path.dirname(os.path.abspath(__file__))

    # 1. russia-mobile-internet-whitelist
    print('Fetching cidrwhitelist.txt...', file=sys.stderr)
    resp = fetch_with_retry(CIDRWHITELIST_URL, timeout=30)
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
    geoip_data = fetch_with_retry(GEOIP_URL, timeout=60).content
    geoip_nets = parse_geoip(geoip_data, GEOIP_CATEGORIES)
    print(f'  {len(geoip_nets)} IPv4 CIDRs ({sorted(GEOIP_CATEGORIES)})', file=sys.stderr)
    all_prefixes.extend(geoip_nets)

    # 3. RU-domain pool (geosite.dat + itdoginfo + v2fly) → DNS-resolve to IPs
    print('Fetching geosite.dat...', file=sys.stderr)
    geosite_data = fetch_with_retry(GEOSITE_URL, timeout=60).content
    geosite_domains = parse_geosite(geosite_data, GEOSITE_CATEGORIES)
    print(f'  {len(geosite_domains)} domains from geosite.dat', file=sys.stderr)

    print('Fetching itdoginfo allow-domains...', file=sys.stderr)
    itdog_domains = fetch_itdog_domains()
    print(f'  {len(itdog_domains)} domains from itdoginfo', file=sys.stderr)

    print('Fetching v2fly category-ru...', file=sys.stderr)
    v2fly_domains = fetch_v2fly_ru_domains()
    print(f'  {len(v2fly_domains)} domains from v2fly', file=sys.stderr)

    domains = list({*geosite_domains, *itdog_domains, *v2fly_domains})
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

    # 4. local pyasn DB (BGP RIB snapshot) for RU+CN
    print('Reading local pyasn DB...', file=sys.stderr)
    db_prefixes = parse_local_db(script_dir, LOCAL_DB_COUNTRIES)
    print(f'  {len(db_prefixes)} IPv4 prefixes ({sorted(LOCAL_DB_COUNTRIES)})', file=sys.stderr)
    all_prefixes.extend(str(p) for p in db_prefixes)

    result = sorted(
        aggregate_prefixes(all_prefixes),
        key=lambda x: ipaddress.ip_network(x),
    )
    print(f'Extra sources total: {len(result)} aggregated prefixes', file=sys.stderr)
    for prefix in result:
        print(prefix)


if __name__ == '__main__':
    main()
