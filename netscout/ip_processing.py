"""
IP processing and file handling utilities.

This module handles IP address expansion from CIDR blocks,
file I/O operations, and streaming data processing.
"""

import ipaddress
import logging
import os
from typing import Iterator, Tuple, List, Optional, TextIO
from tqdm import tqdm

from .core import PerformanceMetrics


class IPProcessor:
    """Handles IP address processing and CIDR expansion"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def generate_ips_from_prefixes(self, prefix_file: str, chunk_size: int = 10000, 
                                  metrics: Optional[PerformanceMetrics] = None) -> Iterator[Tuple[str, ipaddress.IPv4Address]]:
        """
        Generator that yields (asn, ip) tuples from prefix file.
        Processes in chunks to avoid memory overload with large prefixes.
        
        Args:
            prefix_file: Path to file containing "ASN CIDR" format
            chunk_size: Maximum number of IPs to process at once from large networks
            metrics: Optional performance metrics tracker
            
        Yields:
            Tuple of (asn, ip_address)
        """
        # Count total prefixes for progress bar
        total_prefixes = 0
        with open(prefix_file, 'r') as f:
            for line in f:
                if line.strip():
                    total_prefixes += 1
        
        with open(prefix_file, 'r') as fin:
            with tqdm(total=total_prefixes, desc="Expanding IP prefixes", unit="prefixes") as pbar:
                for line in fin:
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        asn, cidr = line.split()
                        network = ipaddress.ip_network(cidr, strict=False)
                        
                        if metrics:
                            metrics.add_processed(1)
                        
                        # Process large networks in chunks with sub-progress
                        if network.num_addresses > chunk_size:
                            self.logger.info(f"Processing large network {cidr} ({network.num_addresses:,} IPs)")
                            chunk_count = 0
                            current_chunk = []
                            
                            with tqdm(total=network.num_addresses, desc=f"  {cidr}", 
                                    unit="IPs", leave=False) as subnet_pbar:
                                for ip in network:
                                    current_chunk.append((asn, ip))
                                    if len(current_chunk) >= chunk_size:
                                        yield from current_chunk
                                        current_chunk = []
                                        chunk_count += 1
                                        subnet_pbar.update(chunk_size)
                                
                                # Yield remaining IPs in the last chunk
                                if current_chunk:
                                    yield from current_chunk
                                    subnet_pbar.update(len(current_chunk))
                        else:
                            # Small networks - yield all at once
                            for ip in network:
                                yield (asn, ip)
                        
                        pbar.set_postfix_str(f"{network.num_addresses:,} IPs")
                        pbar.update(1)
                        
                    except ValueError as e:
                        self.logger.warning(f"Skipping malformed line: {line} - {e}")
                        continue

    def generate_ips_from_file(self, ips_file: str, sample_rate: float = 1.0) -> Iterator[Tuple[str, ipaddress.IPv4Address]]:
        """
        Generator that yields (asn, ip) tuples from IP file with optional sampling.
        Memory-efficient streaming approach.
        
        Args:
            ips_file: Path to file containing "ASN IP" format
            sample_rate: Fraction of IPs to process (0.1 = 10%)
            
        Yields:
            Tuple of (asn, ip_address)
        """
        total_ips = 0
        sampled_ips = 0
        
        with open(ips_file, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                
                try:
                    asn, ip = line.split()
                    total_ips += 1
                    
                    # Apply sampling
                    if sample_rate < 1.0:
                        import random
                        if random.random() > sample_rate:
                            continue
                    
                    sampled_ips += 1
                    yield (asn, ipaddress.ip_address(ip))
                    
                except ValueError:
                    self.logger.warning(f"Skipping malformed line {line_num}: {line}")
                    continue
        
        self.logger.info(f"Will process {sampled_ips:,} IP addresses out of {total_ips:,} total")

    def expand_prefixes_to_ips(self, prefix_file: str, output_file: str, chunk_size: int = 10000) -> None:
        """
        Stream-process prefixes to IPs with chunked writing to avoid memory overload.
        
        Args:
            prefix_file: Input file with "ASN CIDR" format
            output_file: Output file for "ASN IP" format
            chunk_size: Size of processing chunks for large networks
        """
        total = 0
        write_buffer = []
        buffer_size = 1000  # Write buffer to reduce I/O operations
        
        with open(output_file, 'w') as fout:
            for asn, ip in self.generate_ips_from_prefixes(prefix_file, chunk_size):
                write_buffer.append(f"{asn} {ip}\n")
                total += 1
                
                # Flush buffer periodically
                if len(write_buffer) >= buffer_size:
                    fout.writelines(write_buffer)
                    write_buffer = []
            
            # Flush remaining buffer
            if write_buffer:
                fout.writelines(write_buffer)

        self.logger.info(f"✔ Wrote {total:,} total IPs to '{output_file}'")


class FileHandler:
    """Handles file I/O operations with streaming support"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def write_asns_to_file(self, asns: List[int], output_file: str) -> None:
        """
        Write list of ASNs to file.
        
        Args:
            asns: List of ASN numbers
            output_file: Output file path
        """
        with open(output_file, 'w') as f:
            for asn in asns:
                f.write(f"{asn}\n")
        
        self.logger.info(f"✔ Wrote {len(asns)} unique ASNs to '{output_file}'")
    
    def write_prefixes_streaming(self, asns: List[int], output_file: str, 
                                asn_discovery, metrics: Optional[PerformanceMetrics] = None) -> int:
        """
        Stream ASN prefix data to file with buffered writes.
        
        Args:
            asns: List of ASN numbers
            output_file: Output file path  
            asn_discovery: ASNDiscovery instance for fetching prefixes
            metrics: Optional performance metrics tracker
            
        Returns:
            Total number of prefixes written
        """
        total_prefixes = 0
        write_buffer = []
        buffer_size = 500
        
        with open(output_file, 'w') as f_pref:
            with tqdm(asns, desc="Fetching IP prefixes", unit="ASN") as asn_pbar:
                for asn in asn_pbar:
                    asn_pbar.set_postfix_str(f"ASN{asn}")
                    
                    try:
                        prefixes = asn_discovery.fetch_prefixes_for_asn(asn, metrics=metrics)
                        prefix_count = len(prefixes)
                        self.logger.debug(f"ASN{asn}: {prefix_count} prefixes")
                        
                        for prefix in prefixes:
                            write_buffer.append(f"{asn} {prefix}\n")
                            total_prefixes += 1
                            
                            # Flush buffer when full
                            if len(write_buffer) >= buffer_size:
                                f_pref.writelines(write_buffer)
                                write_buffer = []
                        
                    except Exception as e:
                        self.logger.error(f"Failed fetching prefixes for ASN{asn}: {e}")
            
            # Flush remaining buffer
            if write_buffer:
                f_pref.writelines(write_buffer)
        
        self.logger.info(f"✔ Wrote {total_prefixes:,} total prefixes to '{output_file}'")
        return total_prefixes
    
    def write_domains_streaming(self, results: List[Tuple[str, str, List[str]]], 
                               output_file: str) -> int:
        """
        Stream domain discovery results to file.
        
        Args:
            results: List of (asn, ip, domains) tuples
            output_file: Output file path
            
        Returns:
            Total number of domain entries written
        """
        total_domains = 0
        
        with open(output_file, 'w') as f:
            for asn, ip, domains in results:
                for domain in domains:
                    f.write(f"{asn} {ip} {domain}\n")
                    total_domains += 1
        
        self.logger.info(f"✔ Wrote {total_domains:,} domain associations to '{output_file}'")
        return total_domains
    
    def ensure_directory_exists(self, file_path: str) -> str:
        """
        Ensure the directory for a file path exists.
        
        Args:
            file_path: File path to check
            
        Returns:
            The original file path
        """
        directory = os.path.dirname(file_path)
        if directory and not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)
            self.logger.debug(f"Created directory: {directory}")
        
        return file_path


class DataProcessor:
    """High-level data processing workflows"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.ip_processor = IPProcessor()
        self.file_handler = FileHandler()
    
    def process_organization_to_files(self, organization_name: str, asn_discovery, 
                                    output_dir: str = None, metrics: Optional[PerformanceMetrics] = None) -> dict:
        """
        Complete workflow: organization -> ASNs -> prefixes -> IPs -> files.
        
        Args:
            organization_name: Name of organization to process
            asn_discovery: ASNDiscovery instance
            output_dir: Output directory (defaults to current directory)
            metrics: Optional performance metrics tracker
            
        Returns:
            Dictionary with paths to generated files and statistics
        """
        if output_dir is None:
            output_dir = os.getcwd()
        
        # Sanitize organization name for filenames
        from .utils import sanitize_filename
        safe_name = sanitize_filename(organization_name)
        
        # Generate file paths
        asn_file = os.path.join(output_dir, f"{safe_name}_asns.txt")
        prefix_file = os.path.join(output_dir, f"{safe_name}_prefixes.txt") 
        ip_file = os.path.join(output_dir, f"{safe_name}_ips.txt")
        
        # Ensure output directory exists
        self.file_handler.ensure_directory_exists(asn_file)
        
        # Step 1: Discover ASNs
        self.logger.info("=== ASN Discovery Phase ===")
        asns = asn_discovery.discover_asns_for_organization(organization_name, metrics=metrics)
        
        if not asns:
            self.logger.error(f"No ASNs found for '{organization_name}'")
            return {}
        
        # Step 2: Write ASNs to file
        self.file_handler.write_asns_to_file(asns, asn_file)
        
        # Step 3: Fetch and write prefixes
        self.logger.info("=== Prefix Discovery Phase ===")
        total_prefixes = self.file_handler.write_prefixes_streaming(
            asns, prefix_file, asn_discovery, metrics=metrics
        )
        
        # Step 4: Expand prefixes to IPs
        self.logger.info("=== IP Expansion Phase ===")
        self.ip_processor.expand_prefixes_to_ips(prefix_file, ip_file)
        
        return {
            'asn_file': asn_file,
            'prefix_file': prefix_file,
            'ip_file': ip_file,
            'stats': {
                'asn_count': len(asns),
                'prefix_count': total_prefixes,
                'organization': organization_name
            }
        }
    
    def process_ips_to_domains(self, ip_file: str, domain_discovery, methods: List[str],
                             output_dir: str = None, fast_mode: bool = False,
                             sample_rate: float = 1.0, max_workers: int = 50,
                             timeout: int = 3, metrics: Optional[PerformanceMetrics] = None) -> str:
        """
        Process IP file to discover domains.
        
        Args:
            ip_file: Path to IP file
            domain_discovery: DomainDiscovery instance
            methods: List of discovery methods
            output_dir: Output directory
            fast_mode: Enable speed optimizations
            sample_rate: Fraction of IPs to process
            max_workers: Number of concurrent workers
            timeout: Timeout for operations
            metrics: Optional performance metrics tracker
            
        Returns:
            Path to domains output file
        """
        if output_dir is None:
            output_dir = os.path.dirname(ip_file)
        
        # Generate domain file path
        base_name = os.path.splitext(os.path.basename(ip_file))[0]
        domain_file = os.path.join(output_dir, f"{base_name}_domains.txt")
        
        # Load IPs from file
        ip_list = list(self.ip_processor.generate_ips_from_file(ip_file, sample_rate))
        
        if not ip_list:
            self.logger.warning("No IPs found to process")
            return domain_file
        
        # Discover domains
        self.logger.info("=== Domain Discovery Phase ===")
        results = domain_discovery.discover_domains_batch(
            ip_list, methods=methods, timeout=timeout, fast_mode=fast_mode,
            max_workers=max_workers, metrics=metrics
        )
        
        # Write results to file
        self.file_handler.write_domains_streaming(results, domain_file)
        
        return domain_file