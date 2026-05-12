#!/usr/bin/env python3
"""Pack an IPv4 CIDR list into a v2ray/xray geoip.dat with a single tag.

Usage: build-geoip.py <cidr_list> <output.dat> [tag]
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
    if len(sys.argv) < 3:
        print(__doc__, file=sys.stderr)
        sys.exit(1)
    src, dst = sys.argv[1], sys.argv[2]
    tag = (sys.argv[3] if len(sys.argv) > 3 else 'rucn').upper()

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
            if isinstance(net, ipaddress.IPv4Network):
                nets.append(net)

    payload = _len_delim(1, encode_geoip(tag, nets))
    with open(dst, 'wb') as f:
        f.write(payload)

    print(f'{dst}: tag={tag} prefixes={len(nets)} bytes={len(payload)}', file=sys.stderr)


if __name__ == '__main__':
    main()
