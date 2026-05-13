#!/usr/bin/env python3
"""Pack a CIDR list into a v2ray/xray geoip.dat with a single tag.

Usage: build-geoip.py <cidr_list> <output.dat> [tag] [--v4|--v6]
  --v4   Pack only IPv4 networks.
  --v6   Pack only IPv6 networks.
  (default: pack both IPv4 and IPv6)
Default tag is 'rucn'. The tag is upper-cased (v2ray convention).

Wire format (protobuf):
  GeoIPList { repeated GeoIP entry = 1; }
  GeoIP     { string country_code = 1; repeated CIDR cidr = 2; }
  CIDR      { bytes ip = 1; uint32 prefix = 2; }
"""
import sys
import ipaddress


def _varint(n):
    out = bytearray()
    while n > 0x7F:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n & 0x7F)
    return bytes(out)


def _tag(field, wire):
    return _varint((field << 3) | wire)


def _len_delim(field, payload):
    return _tag(field, 2) + _varint(len(payload)) + payload


def _varint_field(field, value):
    return _tag(field, 0) + _varint(value)


def encode_cidr(net):
    return _len_delim(1, net.network_address.packed) + _varint_field(2, net.prefixlen)


def encode_geoip(tag, nets):
    payload = _len_delim(1, tag.encode())
    for n in nets:
        payload += _len_delim(2, encode_cidr(n))
    return payload


def main():
    args = sys.argv[1:]
    v4_only = '--v4' in args
    v6_only = '--v6' in args
    args = [a for a in args if a not in ('--v4', '--v6')]

    if len(args) < 2:
        print(__doc__, file=sys.stderr)
        sys.exit(1)
    src, dst = args[0], args[1]
    tag = (args[2] if len(args) > 2 else 'rucn').upper()

    nets = []
    with open(src) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            try:
                net = ipaddress.ip_network(line, strict=False)
            except ValueError:
                continue
            if v4_only and not isinstance(net, ipaddress.IPv4Network):
                continue
            if v6_only and not isinstance(net, ipaddress.IPv6Network):
                continue
            nets.append(net)

    payload = _len_delim(1, encode_geoip(tag, nets))
    with open(dst, 'wb') as f:
        f.write(payload)

    n4 = sum(1 for n in nets if isinstance(n, ipaddress.IPv4Network))
    n6 = len(nets) - n4
    print(f'{dst}: tag={tag} IPv4={n4} IPv6={n6} bytes={len(payload)}', file=sys.stderr)


if __name__ == '__main__':
    main()
