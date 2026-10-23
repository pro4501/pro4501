#!/usr/bin/env bash
# Install the scanner toolchain AEGIS drives.
#
# Run this once per cloud session (or paste it into the environment's setup
# script so it runs on every session start). Needs network access to the
# distro package mirrors -- set the environment's network policy to a level
# that allows package managers.
set -euo pipefail

echo "[aegis] installing scanner toolchain..."

if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update -y
    sudo apt-get install -y \
        nmap \
        nikto \
        whatweb \
        dnsutils \
        whois \
        sslscan \
        gobuster \
        ffuf
elif command -v dnf >/dev/null 2>&1; then
    sudo dnf install -y nmap nikto whatweb bind-utils whois sslscan
else
    echo "[aegis] no supported package manager (apt/dnf) found" >&2
    exit 1
fi

# nuclei ships as a Go binary; install if Go is present.
if command -v go >/dev/null 2>&1; then
    echo "[aegis] installing nuclei via go install..."
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest || \
        echo "[aegis] nuclei install skipped (non-fatal)"
fi

echo "[aegis] installed:"
for t in nmap nikto whatweb dig whois sslscan gobuster ffuf nuclei; do
    if command -v "$t" >/dev/null 2>&1; then
        printf '  %-10s %s\n' "$t" "$(command -v "$t")"
    else
        printf '  %-10s (not installed)\n' "$t"
    fi
done
echo "[aegis] done."
