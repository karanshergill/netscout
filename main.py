#!/usr/bin/env python3
"""
NetScout - Main Entry Point

A modular, comprehensive tool for discovering IP addresses and associated domains 
from Autonomous System Numbers (ASNs) for given organizations.
"""

import sys

if __name__ == "__main__":
    from netscout.cli import main
    sys.exit(main())