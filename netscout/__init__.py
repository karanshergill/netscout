"""
NetScout - Network Discovery Tool

A comprehensive tool for discovering IP addresses and associated domains 
from Autonomous System Numbers (ASNs) for given organizations.
"""

__version__ = "2.0.0"
__author__ = "NetScout Contributors"

from .core import PerformanceMetrics, setup_logging
from .asn_discovery import ASNDiscovery
from .domain_discovery import DomainDiscovery
from .ip_processing import IPProcessor
from .database import NetScoutDatabase
from .colors import ColorScheme, get_color_scheme
from .utils import sanitize_filename

__all__ = [
    'PerformanceMetrics',
    'setup_logging', 
    'ASNDiscovery',
    'DomainDiscovery',
    'IPProcessor',
    'NetScoutDatabase',
    'ColorScheme',
    'get_color_scheme',
    'sanitize_filename'
]