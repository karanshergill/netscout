"""
ASN (Autonomous System Number) discovery functionality.

This module handles finding organizations and their associated ASNs
using both ASRank API and BGPView API as fallback.
"""

import requests
import logging
import time
from typing import Optional, Iterator, List, Dict, Any
from tqdm import tqdm

from .core import Config, PerformanceMetrics, HTTPSessionManager


class ASNDiscovery:
    """Handles ASN discovery for organizations"""
    
    def __init__(self, page_size: int = 500):
        self.page_size = page_size
        self.session_manager = HTTPSessionManager()
        self.logger = logging.getLogger(__name__)
        
    def find_organizations_by_name(self, search_term: str, 
                                 metrics: Optional[PerformanceMetrics] = None) -> Iterator[Dict[str, Any]]:
        """
        Find organizations matching the search term using ASRank API.
        
        Args:
            search_term: Organization name or substring to search for
            metrics: Optional performance metrics tracker
            
        Yields:
            Dict containing organization information (orgId, orgName)
        """
        search_term = search_term.lower()
        offset = 0
        session = self.session_manager.get_session()
        
        with tqdm(desc="Searching organizations", unit="pages", leave=False) as pbar:
            while True:
                try:
                    self.logger.debug(f"Fetching organizations page at offset {offset}")
                    
                    response = session.post(
                        Config.GQL_URL, 
                        headers={"Content-Type": "application/json"},
                        json={
                            "query": Config.ORG_LIST_QUERY,
                            "variables": {"first": self.page_size, "offset": offset}
                        }, 
                        timeout=30
                    )
                    response.raise_for_status()
                    response_data = response.json()
                    
                    if metrics:
                        metrics.add_request(success=True)
                    
                    # Check for GraphQL errors
                    if "errors" in response_data:
                        self.logger.error(f"GraphQL errors: {response_data['errors']}")
                        if metrics:
                            metrics.add_request(success=False)
                        return
                        
                    organizations = response_data["data"]["organizations"]
                    matches_found = 0
                    
                    for edge in organizations["edges"]:
                        node = edge["node"]
                        if search_term in node["orgName"].lower():
                            matches_found += 1
                            yield node
                    
                    self.logger.debug(f"Found {matches_found} matching organizations on this page")
                    pbar.set_postfix_str(f"Found: {matches_found}")
                    pbar.update(1)
                    
                    if not organizations["pageInfo"]["hasNextPage"]:
                        break
                    offset += self.page_size
                    
                except requests.exceptions.RequestException as e:
                    self.logger.error(f"Request failed: {e}")
                    self.logger.warning("The ASRank API might be temporarily unavailable.")
                    if metrics:
                        metrics.add_request(success=False)
                    return
                except KeyError as e:
                    self.logger.error(f"Unexpected response format: {e}")
                    if metrics:
                        metrics.add_request(success=False)
                    return

    def fetch_asns_for_organization(self, org_id: str, 
                                  metrics: Optional[PerformanceMetrics] = None) -> List[int]:
        """
        Fetch ASNs for a specific organization using ASRank API.
        
        Args:
            org_id: Organization ID from ASRank
            metrics: Optional performance metrics tracker
            
        Returns:
            List of ASNs associated with the organization
        """
        asns = []
        offset = 0
        session = self.session_manager.get_session()
        
        with tqdm(desc=f"Fetching ASNs for org {org_id}", unit="pages", leave=False) as pbar:
            while True:
                try:
                    self.logger.debug(f"Fetching ASNs for org {org_id}, offset {offset}")
                    
                    response = session.post(
                        Config.GQL_URL,
                        headers={"Content-Type": "application/json"},
                        json={
                            "query": Config.ASN_LIST_QUERY,
                            "variables": {"orgId": org_id, "first": self.page_size, "offset": offset}
                        },
                        timeout=30
                    )
                    response.raise_for_status()
                    response_data = response.json()
                    
                    if metrics:
                        metrics.add_request(success=True)
                    
                    # Check for GraphQL errors
                    if "errors" in response_data:
                        self.logger.error(f"GraphQL errors for org {org_id}: {response_data['errors']}")
                        if metrics:
                            metrics.add_request(success=False)
                        break
                        
                    # Handle case where organization might not exist or have no members
                    organization = response_data["data"]["organization"]
                    if not organization:
                        self.logger.warning(f"No organization found for ID: {org_id}")
                        break
                        
                    members = organization.get("members")
                    if not members:
                        self.logger.warning(f"No members found for organization ID: {org_id}")
                        break
                        
                    asn_block = members["asns"]
                    page_asns = [edge["node"]["asn"] for edge in asn_block["edges"]]
                    asns.extend(page_asns)
                    
                    self.logger.debug(f"Found {len(page_asns)} ASNs on this page")
                    pbar.set_postfix_str(f"Total ASNs: {len(asns)}")
                    pbar.update(1)
                    
                    if not asn_block["pageInfo"]["hasNextPage"]:
                        break
                    offset += self.page_size
                    
                except requests.exceptions.RequestException as e:
                    self.logger.error(f"Request failed for org {org_id}: {e}")
                    if metrics:
                        metrics.add_request(success=False)
                    break
                except KeyError as e:
                    self.logger.error(f"Unexpected response format for org {org_id}: {e}")
                    if metrics:
                        metrics.add_request(success=False)
                    break
                    
        return asns

    def search_asns_bgpview_fallback(self, search_term: str) -> List[Dict[str, Any]]:
        """
        Fallback method using BGPView API and known ASNs.
        
        Args:
            search_term: Organization name to search for
            
        Returns:
            List of dictionaries containing ASN information
        """
        self.logger.info(f"Searching for ASNs containing '{search_term}' using BGPView API...")
        
        search_lower = search_term.lower()
        asns_found = []
        session = self.session_manager.get_session()
        
        # First, check if we have known ASNs for this company
        for company, asn_list in Config.KNOWN_ASNS.items():
            if company in search_lower or search_lower in company:
                self.logger.info(f"Using known ASNs for {company}")
                
                for asn in asn_list:
                    try:
                        url = f"{Config.BGPVIEW_API}/asn/{asn}"
                        response = session.get(url, timeout=10)
                        
                        if response.status_code == 200:
                            data = response.json()
                            if 'data' in data:
                                asn_data = data['data']
                                asns_found.append({
                                    'asn': asn,
                                    'name': asn_data.get('name', ''),
                                    'description': asn_data.get('description_short', '')
                                })
                                self.logger.info(f"Found ASN{asn}: {asn_data.get('name', '')}")
                                
                    except requests.exceptions.RequestException as e:
                        self.logger.warning(f"Failed to fetch ASN{asn}: {e}")
                        
                if asns_found:
                    return asns_found
        
        # If no known ASNs found, do a limited search
        self.logger.info("No known ASNs found, performing limited search...")
        self.logger.warning("Note: This is a basic search. For comprehensive results, ensure ASRank API is accessible.")
        
        # Search a smaller, more targeted range to avoid rate limits
        common_ranges = [
            (13000, 17000, 50),  # Commercial ASNs, sample every 50th
            (36000, 40000, 50),  # More recent ASNs
        ]
        
        for start, end, step in common_ranges:
            for asn in range(start, end, step):
                try:
                    url = f"{Config.BGPVIEW_API}/asn/{asn}"
                    response = session.get(url, timeout=5)
                    
                    if response.status_code == 200:
                        data = response.json()
                        if 'data' in data:
                            asn_data = data['data']
                            name = asn_data.get('name', '').lower()
                            description = asn_data.get('description_short', '').lower()
                            
                            if search_lower in name or search_lower in description:
                                asns_found.append({
                                    'asn': asn,
                                    'name': asn_data.get('name', ''),
                                    'description': asn_data.get('description_short', '')
                                })
                                self.logger.info(f"Found ASN{asn}: {asn_data.get('name', '')}")
                    
                    # Rate limiting
                    time.sleep(0.2)
                            
                except requests.exceptions.RequestException:
                    continue
                    
        return asns_found

    def fetch_prefixes_for_asn(self, asn: int, metrics: Optional[PerformanceMetrics] = None) -> List[str]:
        """
        Query RIPE Stat for announced prefixes of a given ASN.
        Returns only IPv4 prefixes.
        
        Args:
            asn: Autonomous System Number
            metrics: Optional performance metrics tracker
            
        Returns:
            List of IPv4 prefixes (CIDR notation)
        """
        try:
            url = f"{Config.RIPE_STAT_API}?resource=AS{asn}"
            self.logger.debug(f"Fetching prefixes for ASN{asn}")
            
            session = self.session_manager.get_session()
            response = session.get(url, timeout=10)
            response.raise_for_status()
            
            if metrics:
                metrics.add_request(success=True)
            
            data = response.json().get("data", {}).get("prefixes", [])
            prefixes = [
                prefix_info["prefix"]
                for prefix_info in data
                if ":" not in prefix_info.get("prefix", "")  # Filter out IPv6
            ]
            
            self.logger.debug(f"ASN{asn}: Found {len(prefixes)} IPv4 prefixes")
            return prefixes
            
        except Exception as e:
            self.logger.error(f"Failed to fetch prefixes for ASN{asn}: {e}")
            if metrics:
                metrics.add_request(success=False)
            return []

    def discover_asns_for_organization(self, organization_name: str, 
                                     use_fallback: bool = True,
                                     metrics: Optional[PerformanceMetrics] = None) -> List[int]:
        """
        Complete ASN discovery workflow for an organization.
        
        Args:
            organization_name: Name of organization to search for
            use_fallback: Whether to use BGPView fallback if ASRank fails
            metrics: Optional performance metrics tracker
            
        Returns:
            List of unique ASNs associated with the organization
        """
        all_asns = []
        
        # Try ASRank API first
        self.logger.info("Attempting to use ASRank API...")
        organizations = list(self.find_organizations_by_name(organization_name, metrics))
        
        if organizations:
            with tqdm(organizations, desc="Processing organizations", unit="org") as org_pbar:
                for org in org_pbar:
                    self.logger.info(f"Found Org: {org['orgName']} → {org['orgId']}")
                    org_pbar.set_postfix_str(org['orgName'][:30])
                    
                    asns = self.fetch_asns_for_organization(org['orgId'], metrics)
                    self.logger.info(f"  → {len(asns)} ASNs")
                    all_asns.extend(asns)
        elif use_fallback:
            # Use BGPView fallback
            self.logger.warning("ASRank API unavailable or no results found. Trying fallback method...")
            bgp_results = self.search_asns_bgpview_fallback(organization_name)
            all_asns.extend([entry['asn'] for entry in bgp_results])
        
        # Deduplicate while preserving order
        seen = set()
        unique_asns = [asn for asn in all_asns if asn not in seen and not seen.add(asn)]
        
        return unique_asns