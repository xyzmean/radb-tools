# radb-tools

Tools for generating IPv4 prefix lists and ASN lists by country, with daily auto-generated releases for RU+CN.

## Ready-to-use release

A combined RU+CN IPv4 prefix list is published daily via GitHub Actions:

```
https://github.com/xyzmean/radb-tools/releases/download/latest/ru_cn_final.lst
```

Sources merged into the release:
- RIPE API (RU + CN allocations)
- Local pyasn DB built from the latest RIPE BGP RIB snapshot (BGP-announced RU + CN prefixes)
- [russia-mobile-internet-whitelist](https://github.com/hxehex/russia-mobile-internet-whitelist) CIDRs
- Loyalsoldier [geoip.dat](https://github.com/Loyalsoldier/v2ray-rules-dat) — `geoip:RU` + `geoip:CN`
- Loyalsoldier [geosite.dat](https://github.com/Loyalsoldier/v2ray-rules-dat) — `geosite:RU` + `geosite:CATEGORY-RU` (resolved via Yandex + Google DNS)
- `extra-include.lst` — extra domains/IPs/ASNs appended on top (see below)

All sources are aggregated and deduplicated. Currently ~43 000 prefixes.

## extra-include.lst

Add extra entries to include in the final list. Supported formats:

```
example.com       # domain — resolved via Yandex DNS + Google DNS
1.2.3.4           # IPv4 address
1.2.3.0/24        # CIDR subnet
AS45102           # AS number — resolved to announced prefixes via RIPE API
```

## Installation

```bash
git clone --depth=1 git@github.com:xyzmean/radb-tools.git
cd radb-tools
pip3 install -r requirements.txt
```

## Manual usage

```bash
# Generate prefix list for a country via RIPE API
python3 ip-country-ripe.py RU

# Generate prefix list via local PyASN DB (requires renew-db first)
bash renew-db
python3 ip-country.py RU

# Extract ASN list for a country
python3 asn-country.py RU

# Fetch extra sources (cidrwhitelist + geoip.dat + geosite.dat)
python3 fetch-extra-sources.py > extra.lst

# Apply extra-include.lst on top of a prefix list
python3 filter-disallow.py combined.lst extra-include.lst > final.lst
```

## License
[MIT](https://choosealicense.com/licenses/mit/)
