"""
Utility functions and helpers.
"""

import re
from typing import List, Dict, Any


def sanitize_filename(name: str) -> str:
    """
    Sanitize a string to be safe for use as a filename.
    
    Args:
        name: Original filename or string
        
    Returns:
        Sanitized filename string
    """
    # Replace spaces and illegal filesystem characters
    return "".join(c if c.isalnum() or c in (' ', '_', '-') else '_' for c in name).replace(' ', '_')


def format_file_size(size_bytes: int) -> str:
    """
    Format file size in human readable format.
    
    Args:
        size_bytes: Size in bytes
        
    Returns:
        Formatted size string (e.g., "1.2 MB")
    """
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    import math
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_names[i]}"


def format_duration(seconds: float) -> str:
    """
    Format duration in human readable format.
    
    Args:
        seconds: Duration in seconds
        
    Returns:
        Formatted duration string (e.g., "1h 23m 45s")
    """
    if seconds < 60:
        return f"{seconds:.1f}s"
    
    minutes = int(seconds // 60)
    remaining_seconds = int(seconds % 60)
    
    if minutes < 60:
        return f"{minutes}m {remaining_seconds}s"
    
    hours = int(minutes // 60)
    remaining_minutes = int(minutes % 60)
    
    if hours < 24:
        return f"{hours}h {remaining_minutes}m {remaining_seconds}s"
    
    days = int(hours // 24)
    remaining_hours = int(hours % 24)
    
    return f"{days}d {remaining_hours}h {remaining_minutes}m"


def validate_ip_address(ip_string: str) -> bool:
    """
    Validate if a string is a valid IP address.
    
    Args:
        ip_string: String to validate
        
    Returns:
        True if valid IP address, False otherwise
    """
    import ipaddress
    try:
        ipaddress.ip_address(ip_string)
        return True
    except ValueError:
        return False


def validate_cidr_block(cidr_string: str) -> bool:
    """
    Validate if a string is a valid CIDR block.
    
    Args:
        cidr_string: String to validate
        
    Returns:
        True if valid CIDR block, False otherwise
    """
    import ipaddress
    try:
        ipaddress.ip_network(cidr_string, strict=False)
        return True
    except ValueError:
        return False


def count_lines_in_file(file_path: str) -> int:
    """
    Efficiently count lines in a file.
    
    Args:
        file_path: Path to file
        
    Returns:
        Number of lines in file
    """
    try:
        with open(file_path, 'r') as f:
            return sum(1 for line in f if line.strip())
    except (IOError, OSError):
        return 0


def estimate_processing_time(ip_count: int, methods: List[str], sample_rate: float = 1.0) -> float:
    """
    Estimate processing time for domain discovery.
    
    Args:
        ip_count: Number of IPs to process
        methods: List of discovery methods
        sample_rate: Sampling rate
        
    Returns:
        Estimated time in seconds
    """
    # Base time estimates per method per IP (in seconds)
    method_times = {
        'dns': 0.2,      # DNS lookup
        'cert': 1.5,     # Certificate analysis
        'http': 3.0,     # HTTP banner scanning
        'service': 1.0,  # Service discovery
    }
    
    # Calculate total time per IP
    time_per_ip = sum(method_times.get(method, 1.0) for method in methods)
    
    # Apply sampling rate
    effective_ips = int(ip_count * sample_rate)
    
    # Estimate with some concurrency benefit (not perfect parallelization)
    concurrency_factor = 0.3  # Assume 30% of perfect parallelization
    estimated_time = (effective_ips * time_per_ip) * concurrency_factor
    
    return max(estimated_time, 1.0)  # Minimum 1 second


def create_summary_report(stats: Dict[str, Any]) -> str:
    """
    Create a formatted summary report.
    
    Args:
        stats: Dictionary containing statistics
        
    Returns:
        Formatted report string
    """
    lines = []
    lines.append("=" * 50)
    lines.append("ASN TO IP DISCOVERY SUMMARY")
    lines.append("=" * 50)
    
    if 'organization' in stats:
        lines.append(f"Organization: {stats['organization']}")
        lines.append("")
    
    if 'asn_count' in stats:
        lines.append(f"ASNs discovered: {stats['asn_count']:,}")
    
    if 'prefix_count' in stats:
        lines.append(f"IP prefixes found: {stats['prefix_count']:,}")
    
    if 'ip_count' in stats:
        lines.append(f"IP addresses expanded: {stats['ip_count']:,}")
    
    if 'domain_count' in stats:
        lines.append(f"Domains discovered: {stats['domain_count']:,}")
    
    if 'processing_time' in stats:
        lines.append(f"Total processing time: {format_duration(stats['processing_time'])}")
    
    if 'success_rate' in stats:
        lines.append(f"Success rate: {stats['success_rate']:.1f}%")
    
    if 'methods_used' in stats:
        lines.append(f"Discovery methods: {', '.join(stats['methods_used'])}")
    
    lines.append("=" * 50)
    
    return "\n".join(lines)


def parse_discovery_methods(method_args: List[str]) -> List[str]:
    """
    Parse and validate discovery method arguments.
    
    Args:
        method_args: List of method strings from command line
        
    Returns:
        List of validated method strings
    """
    valid_methods = ['dns', 'cert', 'http', 'service']
    methods = []
    
    for method in method_args:
        if method == 'all':
            return valid_methods
        elif method in valid_methods:
            methods.append(method)
        else:
            raise ValueError(f"Invalid discovery method: {method}")
    
    return methods or ['dns', 'cert']  # Default methods


def validate_port_list(ports: List[int]) -> List[int]:
    """
    Validate and filter port numbers.
    
    Args:
        ports: List of port numbers
        
    Returns:
        List of valid port numbers
    """
    valid_ports = []
    
    for port in ports:
        if 1 <= port <= 65535:
            valid_ports.append(port)
        else:
            import logging
            logging.getLogger(__name__).warning(f"Invalid port number: {port} (must be 1-65535)")
    
    return valid_ports


def merge_domain_results(results_list: List[List[tuple]]) -> List[tuple]:
    """
    Merge multiple domain discovery results and remove duplicates.
    
    Args:
        results_list: List of result lists, each containing (asn, ip, domains) tuples
        
    Returns:
        Merged and deduplicated results
    """
    seen_combinations = set()
    merged_results = []
    
    for results in results_list:
        for asn, ip, domains in results:
            for domain in domains:
                combination = (asn, ip, domain)
                if combination not in seen_combinations:
                    seen_combinations.add(combination)
                    merged_results.append((asn, ip, [domain]))
    
    return merged_results


class ProgressEstimator:
    """Estimates and tracks progress for long-running operations"""
    
    def __init__(self, total_items: int, operation_name: str = "Processing"):
        self.total_items = total_items
        self.operation_name = operation_name
        self.processed_items = 0
        self.start_time = None
        import time
        self.start_time = time.time()
    
    def update(self, processed_count: int = 1):
        """Update progress counter"""
        self.processed_items += processed_count
    
    def get_eta_seconds(self) -> float:
        """Get estimated time to completion in seconds"""
        if self.processed_items == 0:
            return float('inf')
        
        import time
        elapsed = time.time() - self.start_time
        rate = self.processed_items / elapsed
        remaining_items = self.total_items - self.processed_items
        
        if rate > 0:
            return remaining_items / rate
        else:
            return float('inf')
    
    def get_progress_percentage(self) -> float:
        """Get completion percentage"""
        if self.total_items == 0:
            return 100.0
        return (self.processed_items / self.total_items) * 100
    
    def get_status_string(self) -> str:
        """Get formatted status string"""
        percentage = self.get_progress_percentage()
        eta_seconds = self.get_eta_seconds()
        eta_str = format_duration(eta_seconds) if eta_seconds != float('inf') else "Unknown"
        
        return f"{self.operation_name}: {percentage:.1f}% ({self.processed_items:,}/{self.total_items:,}) - ETA: {eta_str}"