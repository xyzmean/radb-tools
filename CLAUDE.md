# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Does

`radb-tools` generates lists of IPv4 prefixes and ASNs organized by country code. It supports two data sources: a local PyASN database built from BGP RIB snapshots, and the live RIPE API.

## Setup & Dependencies

```bash
pip install -r requirements.txt
```

The three dependencies are `pyasn`, `aggregate_prefixes`, and `requests`. No build step needed — pure Python scripts.

## Running the Scripts

```bash
# Generate IPv4 prefix list for a country (uses local ipasn.lst + asn.txt)
python3 ./ip-country.py RU

# Extract ASN list for a country
python3 ./asn-country.py RU

# Generate IPv4 prefix list via RIPE API (no local DB needed)
python3 ./ip-country-ripe.py RU
```

Each script writes output to `ip_<CC>.lst` or `asn_<CC>.lst` in the working directory.

## Refreshing the Local Database

The `renew-db` shell script downloads a fresh BGP RIB snapshot from RIPE and rebuilds `ipasn.lst`:

```bash
bash ./renew-db
```

This fetches `asn.txt` from RIPE FTP and uses `pyasn_util_download.py` + `pyasn_util_convert.py` to produce `ipasn.lst`.

## Architecture

**Data flow for `ip-country.py` (RADB path):**
1. Parse `asn.txt` to collect all ASNs matching the given country code (last 2 chars of each line)
2. Query each ASN against `ipasn.lst` using `pyasn.pyasn()`
3. Aggregate overlapping prefixes with `aggregate_prefixes`
4. Write sorted CIDR list to `ip_<CC>.lst`

**Data flow for `ip-country-ripe.py` (RIPE path):**
1. Call `https://stat.ripe.net/data/country-resource-list/data.json?resource=<CC>`
2. Convert any IP ranges (`x.x.x.x-y.y.y.y`) to CIDR notation using `ipaddress.summarize_address_range`
3. Same aggregation and output as above

**`asn-country.py`** is a simpler filter: reads `asn.txt`, outputs ASNs whose line ends with the country code.

**Generated/cached data files** (`*.lst`, `*.bz2`) are gitignored and must be created locally via `renew-db` before using `ip-country.py`. The exception is `extra-include.lst`, which is checked in and lists extra domains/IPs/ASNs that `filter-disallow.py` appends on top of the aggregated prefix list.

**`combine-lists.py`** merges multiple prefix lists, aggregates, and writes the sorted CIDR result to an output file. Used by the CI workflow to combine RU, CN, and extra source outputs.
