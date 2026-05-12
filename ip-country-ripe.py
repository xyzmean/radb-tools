#!/usr/bin/env python3
# coding: utf-8
# version: 0.5
import os
import sys
from ipaddress import IPv4Address, IPv4Network, summarize_address_range

import requests
from aggregate_prefixes import aggregate_prefixes

RIPE_URL = 'https://stat.ripe.net/data/country-resource-list/data.json?resource={cc}'


def parse_country_code(argv):
    if len(argv) != 2 or len(argv[1]) != 2 or not argv[1].isalpha():
        print(f'Usage: {argv[0]} <two letters country code>', file=sys.stderr)
        sys.exit(1)
    return argv[1].upper()


def main():
    cc = parse_country_code(sys.argv)
    filepath = os.path.dirname(os.path.abspath(sys.argv[0]))
    result_path = os.path.join(filepath, f'ip_{cc}.lst')

    resp = requests.get(RIPE_URL.format(cc=cc), timeout=60)
    resp.raise_for_status()
    ripe_ip = resp.json()['data']['resources']['ipv4']

    networks = []
    for record in ripe_ip:
        if '-' in record:
            start, end = record.split('-', 1)
            networks.extend(summarize_address_range(IPv4Address(start), IPv4Address(end)))
        else:
            networks.append(IPv4Network(record))

    total = 0
    with open(result_path, 'w') as out_file:
        for net in aggregate_prefixes(networks):
            total += net.num_addresses
            print(str(net), file=out_file)
    print(f'Total number of IPs is {total}')


if __name__ == '__main__':
    main()
