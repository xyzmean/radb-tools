#!/usr/bin/env python3
# coding: utf-8
# version: 0.5
import os
import sys

import pyasn
from aggregate_prefixes import aggregate_prefixes


def parse_country_code(argv):
    if len(argv) != 2 or len(argv[1]) != 2 or not argv[1].isalpha():
        print(f'Usage: {argv[0]} <two letters country code>', file=sys.stderr)
        sys.exit(1)
    return argv[1].upper()


def main():
    cc = parse_country_code(sys.argv)
    filepath = os.path.dirname(os.path.abspath(sys.argv[0]))
    asndb = pyasn.pyasn(os.path.join(filepath, 'ipasn.lst'))
    asnfile = os.path.join(filepath, 'asn.txt')
    result_path = os.path.join(filepath, f'ip_{cc}.lst')

    with open(asnfile) as f:
        asn_list = [t.split(' ')[0] for t in f if t.split(' ')[-1][:2] == cc]

    networks = []
    for asn in asn_list:
        prefixes = asndb.get_as_prefixes(asn) or []
        networks.extend(prefixes)

    total = 0
    with open(result_path, 'w') as out_file:
        for net in aggregate_prefixes(networks):
            total += net.num_addresses
            print(str(net), file=out_file)
    print(f'Total number of IPs is {total}')


if __name__ == '__main__':
    main()
