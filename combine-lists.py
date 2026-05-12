#!/usr/bin/env python3
"""Combine multiple prefix lists, aggregate, write sorted CIDRs to output.

Usage: combine-lists.py <output.lst> <input.lst> [<input.lst>...]
"""
import ipaddress
import sys

from aggregate_prefixes import aggregate_prefixes


def main():
    if len(sys.argv) < 3:
        print(f'Usage: {sys.argv[0]} <output.lst> <input.lst> [<input.lst>...]', file=sys.stderr)
        sys.exit(1)

    output = sys.argv[1]
    inputs = sys.argv[2:]

    lines = []
    for path in inputs:
        with open(path) as f:
            lines.extend(f.read().split())

    result = sorted(
        aggregate_prefixes(lines),
        key=lambda x: ipaddress.ip_network(x),
    )
    with open(output, 'w') as f:
        f.write('\n'.join(str(n) for n in result) + '\n')
    print(f'Combined: {len(result)} prefixes')


if __name__ == '__main__':
    main()
