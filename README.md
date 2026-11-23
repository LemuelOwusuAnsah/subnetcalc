# Subnet Calculator

IPv4 and IPv6 subnet calculator. Runs entirely in the browser — no backend, no network calls.

## Live

https://lemuelowusuansah.github.io/subnetcalc/

## Features

- IPv4: network, broadcast, first/last usable, total addresses, usable hosts, subnet mask, wildcard mask, class, private/public
- IPv6: compressed and expanded notation, network, first/last, total addresses, kind
- Binary view: address in bits, with network and host sections split at the prefix
- Splitter: break a CIDR block into N subnets of a larger prefix (up to 4096)
- Export results as .txt or .csv
- Copy results to clipboard

## Stack

- Astro 5
- TypeScript (strict)
- Deployed to GitHub Pages

## Development

    npm install
    npm run dev

Local dev: http://localhost:4321/subnetcalc/

## Build

    npm run build

Output: dist/
