"""
Core utilities and base classes for the ASN discovery tool.
"""

import time
import logging
import requests
import urllib3
from dataclasses import dataclass, field
from typing import Optional

# Disable SSL warnings for reconnaissance
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@dataclass
class PerformanceMetrics:
    """Track performance metrics for operations"""
    start_time: float = field(default_factory=time.time)
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    total_processed: int = 0
    
    @property
    def elapsed_time(self) -> float:
        return time.time() - self.start_time
    
    @property
    def requests_per_second(self) -> float:
        if self.elapsed_time > 0:
            return self.total_requests / self.elapsed_time
        return 0.0
    
    @property
    def success_rate(self) -> float:
        if self.total_requests > 0:
            return (self.successful_requests / self.total_requests) * 100
        return 0.0
    
    def add_request(self, success: bool = True):
        self.total_requests += 1
        if success:
            self.successful_requests += 1
        else:
            self.failed_requests += 1
    
    def add_processed(self, count: int = 1):
        self.total_processed += count
    
    def get_summary(self) -> str:
        return (f"Processed: {self.total_processed:,} | "
                f"Requests: {self.total_requests:,} | "
                f"Success: {self.success_rate:.1f}% | "
                f"Rate: {self.requests_per_second:.1f}/sec")


class HTTPSessionManager:
    """Manages HTTP sessions with connection pooling"""
    
    _instance = None
    _session = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(HTTPSessionManager, cls).__new__(cls)
        return cls._instance
    
    def get_session(self) -> requests.Session:
        """Get or create HTTP session with connection pooling"""
        if self._session is None:
            self._session = requests.Session()
            
            # Configure connection pooling
            adapter = requests.adapters.HTTPAdapter(
                pool_connections=10,
                pool_maxsize=50,
                max_retries=1
            )
            self._session.mount('http://', adapter)
            self._session.mount('https://', adapter)
            
            # Set common headers
            self._session.headers.update({
                'User-Agent': 'Mozilla/5.0 (compatible; ASN-Tool/2.0)',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive'
            })
        
        return self._session
    
    def close(self):
        """Close the HTTP session"""
        if self._session:
            self._session.close()
            self._session = None


def setup_logging(verbose: bool = False, quiet: bool = False) -> logging.Logger:
    """Setup logging with configurable verbosity"""
    if quiet:
        level = logging.WARNING
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO
    
    # Configure logging format
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )
    
    # Setup console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    
    # Configure logger
    logger = logging.getLogger()
    logger.setLevel(level)
    logger.handlers.clear()
    logger.addHandler(console_handler)
    
    return logger


# Global configuration constants
class Config:
    """Global configuration constants"""
    
    # API URLs
    GQL_URL = "https://api.asrank.caida.org/v2/graphql"
    BGPVIEW_API = "https://api.bgpview.io"
    RIPE_STAT_API = "https://stat.ripe.net/data/announced-prefixes/data.json"
    
    # Default port configurations
    DEFAULT_HTTP_PORTS = [80, 8080, 8000, 8443, 3000, 5000]
    DEFAULT_HTTPS_PORTS = [443, 8443, 8080, 9443, 10443]
    
    # GraphQL queries
    ORG_LIST_QUERY = """
    query($first:Int!,$offset:Int!){
        organizations(first:$first, offset:$offset){
            edges{node{orgId orgName}}
            pageInfo{ hasNextPage }
        }
    }
    """
    
    ASN_LIST_QUERY = """
    query($orgId:String!,$first:Int!,$offset:Int!){
      organization(orgId:$orgId){
        members{
          asns(first:$first, offset:$offset){
            edges{ node { asn } }
            pageInfo{ hasNextPage }
          }
        }
      }
    }
    """
    
    # Known ASNs for major companies
    KNOWN_ASNS = {
        'google': [15169, 36384, 36385, 396982],
        'amazon': [16509, 14618, 8987],
        'microsoft': [8075, 3598, 12076],
        'facebook': [32934, 63293],
        'apple': [714, 6185],
        'cloudflare': [13335, 209242],
        'netflix': [2906, 40027],
        'twitter': [13414, 35995],
        'linkedin': [12025, 12090],
        'yahoo': [10310, 26101, 43515]
    }