"""
Domain discovery functionality using multiple methods.

This module provides comprehensive domain discovery through:
- Reverse DNS lookups
- SSL certificate analysis  
- HTTP banner scanning
- Service banner discovery
"""

import socket
import ssl
import re
import dns.resolver
import dns.reversename
import logging
from typing import Set, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

from .core import Config, PerformanceMetrics, HTTPSessionManager


class DomainValidator:
    """Validates and filters discovered domains"""
    
    @staticmethod
    def extract_domains_from_text(text: str) -> Set[str]:
        """Extract potential domain names from text using regex"""
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        domains = set()
        
        for match in re.finditer(domain_pattern, text):
            domain = match.group().lower()
            # Filter out common false positives
            if not domain.endswith(('.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.woff', '.ttf')):
                domains.add(domain)
        
        return domains

    @staticmethod
    def validate_domain(domain: str) -> bool:
        """Validate if a domain is legitimate and worth keeping"""
        if not domain or len(domain) < 4 or len(domain) > 253:
            return False
        
        # Must contain at least one dot
        if '.' not in domain:
            return False
        
        # Cannot start or end with dot or hyphen
        if domain.startswith(('.', '-')) or domain.endswith(('.', '-')):
            return False
        
        # Cannot be an IP address
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
            return False
        
        # Filter out common false positives
        false_positives = {
            'localhost', 'example.com', 'example.org', 'test.com',
            'www.w3.org', 'schemas.xmlsoap.org', 'www.google.com/recaptcha',
            'maps.googleapis.com', 'ajax.googleapis.com', 'fonts.googleapis.com',
            'cdnjs.cloudflare.com', 'maxcdn.bootstrapcdn.com',
        }
        
        if domain.lower() in false_positives:
            return False
        
        # Filter out file extensions that got picked up
        if domain.endswith(('.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.woff', '.ttf', '.pdf')):
            return False
        
        # Must have valid TLD (at least 2 characters)
        parts = domain.split('.')
        if len(parts[-1]) < 2:
            return False
        
        return True


class ReverseDNSDiscovery:
    """Handles reverse DNS lookups"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def lookup(self, ip_address: str, timeout: int = 3) -> Optional[str]:
        """
        Perform reverse DNS lookup on an IP address.
        
        Args:
            ip_address: IP address to lookup
            timeout: Timeout in seconds
            
        Returns:
            Hostname if found, None otherwise
        """
        try:
            # Try socket reverse lookup first (faster)
            hostname = socket.gethostbyaddr(str(ip_address))[0]
            return hostname
        except (socket.herror, socket.gaierror, OSError):
            try:
                # Try DNS resolver as fallback
                rev_name = dns.reversename.from_address(str(ip_address))
                resolver = dns.resolver.Resolver()
                resolver.timeout = timeout
                resolver.lifetime = timeout
                answers = resolver.resolve(rev_name, "PTR")
                if answers:
                    return str(answers[0]).rstrip('.')
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, Exception):
                pass
        return None


class CertificateDiscovery:
    """Handles SSL certificate domain extraction"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def discover_domains(self, ip_address: str, ports: List[int] = None, 
                        timeout: int = 5, fast_mode: bool = False) -> Set[str]:
        """
        Extract domains from SSL certificates with SNI support.
        
        Args:
            ip_address: IP address to scan
            ports: List of ports to check (defaults to common HTTPS ports)
            timeout: Connection timeout
            fast_mode: Enable optimizations for speed
            
        Returns:
            Set of discovered domains
        """
        if ports is None:
            ports = Config.DEFAULT_HTTPS_PORTS
        
        # In fast mode, only try most common SSL ports
        if fast_mode:
            ports = [443, 8443]
            timeout = min(timeout, 2)
        
        domains = set()
        validator = DomainValidator()
        
        # Try most likely ports first
        priority_ports = [443, 8443] + [p for p in ports if p not in [443, 8443]]
        
        for port in priority_ports:
            if domains and fast_mode:  # Early termination in fast mode
                break
                
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                # Disable unnecessary extensions for speed
                context.set_ciphers('HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA')
                
                with socket.create_connection((str(ip_address), port), timeout=timeout) as sock:
                    try:
                        with context.wrap_socket(sock, server_hostname=str(ip_address)) as ssock:
                            cert = ssock.getpeercert()
                            
                            # Extract Subject Alternative Names (most comprehensive)
                            if 'subjectAltName' in cert:
                                for san_type, san_value in cert['subjectAltName']:
                                    if san_type == 'DNS':
                                        domain = san_value.lower().strip()
                                        if domain and not domain.startswith('*.'):
                                            domains.add(domain)
                                        elif domain.startswith('*.') and len(domain) > 2:
                                            # Add wildcard domain without the wildcard
                                            base_domain = domain[2:]
                                            if validator.validate_domain(base_domain):
                                                domains.add(base_domain)
                            
                            # Extract Common Name from subject
                            if 'subject' in cert:
                                for field in cert['subject']:
                                    if field[0][0] == 'commonName':
                                        domain = field[0][1].lower().strip()
                                        if domain and not domain.startswith('*.'):
                                            if validator.validate_domain(domain):
                                                domains.add(domain)
                                        elif domain.startswith('*.') and len(domain) > 2:
                                            base_domain = domain[2:]
                                            if validator.validate_domain(base_domain):
                                                domains.add(base_domain)
                            
                            # Skip issuer analysis in fast mode
                            if not fast_mode and 'issuer' in cert:
                                for field in cert['issuer']:
                                    if field[0][0] in ['organizationName', 'commonName']:
                                        issuer_domains = validator.extract_domains_from_text(field[0][1])
                                        domains.update(d for d in issuer_domains if validator.validate_domain(d))
                            
                            self.logger.debug(f"Certificate on {ip_address}:{port}: {len(domains)} domains")
                            
                            if domains:
                                break  # Found domains, no need to try other ports
                            
                    except ssl.SSLError:
                        # Try without SNI for older servers (only if no domains found yet)
                        if not domains:
                            try:
                                with context.wrap_socket(sock) as ssock:
                                    cert = ssock.getpeercert()
                                    if cert and 'subjectAltName' in cert:
                                        for san_type, san_value in cert['subjectAltName']:
                                            if san_type == 'DNS':
                                                domain = san_value.lower().strip()
                                                if validator.validate_domain(domain):
                                                    domains.add(domain)
                            except:
                                pass
                            
            except (socket.timeout, socket.error, ssl.SSLError, Exception) as e:
                self.logger.debug(f"Certificate scan failed for {ip_address}:{port}: {e}")
                continue
        
        return domains


class HTTPBannerDiscovery:
    """Handles HTTP banner and content scanning"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.session_manager = HTTPSessionManager()
    
    def discover_domains(self, ip_address: str, ports: List[int] = None,
                        timeout: int = 5, fast_mode: bool = False) -> Set[str]:
        """
        Extract domains from HTTP headers and page content.
        
        Args:
            ip_address: IP address to scan
            ports: List of ports to check (defaults to common HTTP ports)
            timeout: Connection timeout
            fast_mode: Enable optimizations for speed
            
        Returns:
            Set of discovered domains
        """
        if ports is None:
            ports = Config.DEFAULT_HTTP_PORTS
        
        # In fast mode, limit ports and reduce timeout
        if fast_mode:
            ports = [80, 443, 8080]  # Most common ports only
            timeout = min(timeout, 2)  # Max 2 seconds in fast mode
        
        domains = set()
        validator = DomainValidator()
        session = self.session_manager.get_session()
        
        # Try most common ports first
        priority_ports = [80, 443, 8080, 8443] + [p for p in ports if p not in [80, 443, 8080, 8443]]
        
        for port in priority_ports:
            if domains and fast_mode:  # In fast mode, stop after finding domains
                break
                
            for scheme in (['https', 'http'] if port in [443, 8443] else ['http', 'https']):
                # Skip invalid combinations
                if scheme == 'http' and port in [443, 8443]:
                    continue
                if scheme == 'https' and port in [80] and not fast_mode:
                    continue
                    
                try:
                    url = f"{scheme}://{ip_address}:{port}"
                    response = session.get(
                        url, 
                        timeout=timeout,
                        verify=False,
                        allow_redirects=fast_mode,  # Only follow redirects in fast mode
                        stream=True  # Stream to avoid downloading large content
                    )
                    
                    # Extract domains from headers (always fast)
                    for header_name, header_value in response.headers.items():
                        if header_name.lower() in ['server', 'location', 'content-security-policy', 'set-cookie', 'x-powered-by']:
                            domains.update(validator.extract_domains_from_text(str(header_value)))
                    
                    # Content analysis (skip in fast mode unless no domains found yet)
                    if not fast_mode or not domains:
                        if 'text/html' in response.headers.get('content-type', ''):
                            # Only read first chunk in fast mode
                            content_limit = 10000 if fast_mode else 50000
                            content = response.text[:content_limit]
                            
                            # Fast extraction - only title and most common patterns
                            if fast_mode:
                                title_match = re.search(r'<title>([^<]*)</title>', content, re.IGNORECASE)
                                if title_match:
                                    domains.update(validator.extract_domains_from_text(title_match.group(1)))
                            else:
                                # Full analysis for non-fast mode
                                meta_patterns = [
                                    r'<meta[^>]+content=["\']([^"\']*)["\']',
                                    r'href=["\']([^"\']*)["\']',
                                    r'src=["\']([^"\']*)["\']'
                                ]
                                
                                for pattern in meta_patterns:
                                    matches = re.findall(pattern, content, re.IGNORECASE)
                                    for match in matches[:10]:  # Limit matches for speed
                                        domains.update(validator.extract_domains_from_text(match))
                    
                    self.logger.debug(f"HTTP scan {url}: {len(domains)} domains")
                    if domains:
                        break  # Found domains, try next port
                        
                except Exception as e:
                    self.logger.debug(f"Error scanning {scheme}://{ip_address}:{port}: {e}")
                    continue
        
        # Filter and return valid domains
        return {d for d in domains if validator.validate_domain(d)}


class ServiceDiscovery:
    """Handles service banner discovery"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def discover_domains(self, ip_address: str, timeout: int = 5, fast_mode: bool = False) -> Set[str]:
        """
        Discover domains through service banner analysis.
        
        Args:
            ip_address: IP address to scan
            timeout: Connection timeout
            fast_mode: Enable optimizations for speed
            
        Returns:
            Set of discovered domains
        """
        domains = set()
        validator = DomainValidator()
        
        # Common service ports and their protocols
        if fast_mode:
            # Only check most common services in fast mode
            service_ports = {
                25: 'smtp',     # SMTP HELO/EHLO - most likely to have domains
                22: 'ssh',      # SSH banner
            }
            timeout = min(timeout, 1)  # Very short timeout for services
        else:
            service_ports = {
                21: 'ftp',      # FTP banner often contains hostnames
                22: 'ssh',      # SSH banner
                25: 'smtp',     # SMTP HELO/EHLO
                110: 'pop3',    # POP3 banner
                143: 'imap',    # IMAP banner
                587: 'smtp',    # SMTP submission
            }
        
        for port, service in service_ports.items():
            if domains and fast_mode:  # Early termination in fast mode
                break
                
            try:
                with socket.create_connection((str(ip_address), port), timeout=timeout) as sock:
                    if service == 'smtp':
                        # SMTP EHLO command
                        sock.send(b'EHLO example.com\r\n')
                        response = sock.recv(512).decode('utf-8', errors='ignore')
                        service_domains = validator.extract_domains_from_text(response)
                        domains.update(d for d in service_domains if validator.validate_domain(d))
                    
                    elif service in ['ftp', 'ssh', 'pop3', 'imap']:
                        # Just read banner
                        response = sock.recv(512).decode('utf-8', errors='ignore')
                        service_domains = validator.extract_domains_from_text(response)
                        domains.update(d for d in service_domains if validator.validate_domain(d))
                    
                    self.logger.debug(f"Service discovery on {ip_address}:{port} ({service}): {len(domains)} domains")
                    
            except (socket.timeout, socket.error, Exception):
                continue
        
        return domains


class DomainDiscovery:
    """Main domain discovery coordinator"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.reverse_dns = ReverseDNSDiscovery()
        self.certificate = CertificateDiscovery()
        self.http_banner = HTTPBannerDiscovery()
        self.service = ServiceDiscovery()
    
    def discover_domains_for_ip(self, ip_address: str, methods: List[str] = None, 
                               timeout: int = 3, fast_mode: bool = False) -> Tuple[str, List[str]]:
        """
        Discover domains for a single IP using specified methods.
        
        Args:
            ip_address: IP address to analyze
            methods: List of discovery methods to use
            timeout: Timeout for operations
            fast_mode: Enable speed optimizations
            
        Returns:
            Tuple of (ip_address, list_of_domains)
        """
        if methods is None:
            methods = ['dns', 'cert']  # Default to fastest methods
        
        all_domains = set()
        
        # Optimize timeout for fast mode
        if fast_mode:
            timeout = min(timeout, 2)
        
        # Optimize method order: fastest and most reliable first
        method_priority = []
        if 'dns' in methods:
            method_priority.append('dns')
        if 'cert' in methods:
            method_priority.append('cert')  
        if 'http' in methods:
            method_priority.append('http')
        if 'service' in methods:
            method_priority.append('service')
        
        for method in method_priority:
            # Early termination in fast mode if we already found domains
            if fast_mode and all_domains:
                break
                
            try:
                if method == 'dns':
                    # DNS lookup (fastest)
                    hostname = self.reverse_dns.lookup(ip_address, timeout // 2)
                    if hostname and DomainValidator.validate_domain(hostname):
                        all_domains.add(hostname)
                        self.logger.debug(f"DNS: {ip_address} -> {hostname}")
                
                elif method == 'cert':
                    # Certificate domain extraction
                    cert_domains = self.certificate.discover_domains(
                        ip_address, timeout=timeout, fast_mode=fast_mode
                    )
                    valid_cert_domains = {d for d in cert_domains if DomainValidator.validate_domain(d)}
                    all_domains.update(valid_cert_domains)
                    if valid_cert_domains:
                        self.logger.debug(f"CERT: {ip_address} -> {', '.join(valid_cert_domains)}")
                
                elif method == 'http':
                    # HTTP banner scanning
                    http_domains = self.http_banner.discover_domains(
                        ip_address, timeout=timeout, fast_mode=fast_mode
                    )
                    valid_http_domains = {d for d in http_domains if DomainValidator.validate_domain(d)}
                    all_domains.update(valid_http_domains)
                    if valid_http_domains:
                        self.logger.debug(f"HTTP: {ip_address} -> {', '.join(valid_http_domains)}")
                
                elif method == 'service':
                    # Service banner discovery
                    service_domains = self.service.discover_domains(
                        ip_address, timeout=timeout, fast_mode=fast_mode
                    )
                    valid_service_domains = {d for d in service_domains if DomainValidator.validate_domain(d)}
                    all_domains.update(valid_service_domains)
                    if valid_service_domains:
                        self.logger.debug(f"SERVICE: {ip_address} -> {', '.join(valid_service_domains)}")
                        
            except Exception as e:
                self.logger.debug(f"Error in {method} discovery for {ip_address}: {e}")
                continue
        
        return ip_address, list(all_domains)
    
    def discover_domains_batch(self, ip_list: List[Tuple[str, str]], methods: List[str] = None,
                              timeout: int = 3, fast_mode: bool = False, max_workers: int = 50,
                              chunk_size: int = 100, metrics: Optional[PerformanceMetrics] = None) -> List[Tuple[str, str, List[str]]]:
        """
        Discover domains for a batch of IPs using concurrent processing.
        
        Args:
            ip_list: List of (asn, ip_address) tuples
            methods: List of discovery methods to use
            timeout: Timeout for operations
            fast_mode: Enable speed optimizations
            max_workers: Number of concurrent workers
            chunk_size: Size of processing chunks
            metrics: Optional performance metrics tracker
            
        Returns:
            List of (asn, ip_address, domains) tuples
        """
        if methods is None:
            methods = ['dns', 'cert']
        
        results = []
        
        def process_chunk(chunk):
            chunk_results = []
            for asn, ip in chunk:
                try:
                    ip_str, domains = self.discover_domains_for_ip(
                        str(ip), methods=methods, timeout=timeout, fast_mode=fast_mode
                    )
                    
                    if domains:
                        chunk_results.append((asn, ip_str, domains))
                        if metrics:
                            metrics.add_processed(1)
                            metrics.add_request(success=True)
                    
                except Exception as e:
                    self.logger.debug(f"Error processing {ip}: {e}")
                    if metrics:
                        metrics.add_request(success=False)
                    continue
            
            return chunk_results
        
        # Process in chunks
        chunks = [ip_list[i:i+chunk_size] for i in range(0, len(ip_list), chunk_size)]
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            with tqdm(total=len(ip_list), desc="Domain discovery", unit="IPs") as pbar:
                future_to_chunk = {executor.submit(process_chunk, chunk): chunk for chunk in chunks}
                
                for future in as_completed(future_to_chunk):
                    try:
                        chunk_results = future.result()
                        results.extend(chunk_results)
                        pbar.update(len(future_to_chunk[future]))
                        
                        if metrics:
                            domains_found = sum(len(r[2]) for r in chunk_results)
                            pbar.set_postfix_str(f"Domains: {len(results):,} | {metrics.requests_per_second:.1f}/sec")
                    
                    except Exception as e:
                        self.logger.error(f"Chunk processing failed: {e}")
                        continue
        
        return results