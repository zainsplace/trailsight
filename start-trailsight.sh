#!/bin/sh
cd "$(dirname "$0")" || exit 1
if command -v python3 >/dev/null 2>&1; then
    exec python3 src/trailsight/launcher.py
fi
echo
echo "TrailSight needs Python, which is not installed."
echo "Get it from https://www.python.org/downloads/ then run this again."
echo
read -r _
