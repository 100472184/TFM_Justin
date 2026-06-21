#!/bin/bash
# Setup script - Make harness scripts executable

echo "Making harness scripts executable..."
chmod +x scripts/bench.py
chmod +x tasks/*/harness/run.sh

echo "Done! You can now run: python scripts/bench.py list"
