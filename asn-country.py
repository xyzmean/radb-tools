#!/usr/bin/env python3
# coding: utf-8
# version: 0.5
import os
import sys


def parse_country_code(argv):
    if len(argv) != 2 or len(argv[1]) != 2 or not argv[1].isalpha():
        print(f'Usage: {argv[0]} <two letters country code>', file=sys.stderr)
        sys.exit(1)
    return argv[1].upper()


def main():
    cc = parse_country_code(sys.argv)
    filepath = os.path.dirname(os.path.abspath(sys.argv[0]))
    result_path = os.path.join(filepath, f'asn_{cc}.lst')
    asn_path = os.path.join(filepath, 'asn.txt')

    with open(asn_path) as asn_file, open(result_path, 'w') as out_file:
        for line in asn_file:
            parts = line.split(' ')
            if parts[-1][:2] == cc:
                print(parts[0], file=out_file)


if __name__ == '__main__':
    main()
