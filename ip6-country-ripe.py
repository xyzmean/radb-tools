#!/usr/bin/env python3
# coding: utf-8
import ipaddress
import sys
import os
import json
import requests
from aggregate_prefixes import aggregate_prefixes

try:
    country_code = sys.argv[1].upper()
except IndexError:
    print('Usage:', sys.argv[0], '<two-letter country code>')
    sys.exit(1)

filepath = os.path.dirname(os.path.abspath(sys.argv[0]))
result = filepath + '/ip6_' + country_code + '.lst'
url = ('https://stat.ripe.net/data/country-resource-list/data.json'
       '?resource=' + country_code)
ripe_ip6 = json.loads(requests.get(url).content)['data']['resources']['ipv6']

networks = []
for record in ripe_ip6:
    record = record.strip()
    if not record:
        continue
    if '-' in record:
        parts = record.split('-')
        networks.extend(
            ipaddress.summarize_address_range(
                ipaddress.IPv6Address(parts[0]),
                ipaddress.IPv6Address(parts[1]),
            )
        )
    else:
        networks.append(ipaddress.IPv6Network(record, strict=False))

aggregated = list(aggregate_prefixes(str(n) for n in networks))
with open(result, 'w') as f:
    for line in aggregated:
        print(line, file=f)
print(f'IPv6 prefixes: {len(aggregated)}')
