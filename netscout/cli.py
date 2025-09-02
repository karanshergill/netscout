"""
Command-line interface for the ASN to IP Domain Discovery Tool.

This module provides the main CLI entry point and argument parsing.
"""

import argparse
import sys
import os
import logging
from typing import List

from .core import PerformanceMetrics, setup_logging, Config
from .asn_discovery import ASNDiscovery
from .domain_discovery import DomainDiscovery
from .ip_processing import DataProcessor
from .database import NetScoutDatabase
from .colors import (
    get_color_scheme, create_ascii_banner, create_neon_separators,
    success, warning, error, info, highlight, stat_number, neon_box
)
from .utils import (
    parse_discovery_methods, validate_port_list, 
    create_summary_report, format_duration
)


class ASNToolCLI:
    """Main CLI application class"""
    
    def __init__(self):
        self.logger = None
        self.performance_metrics = PerformanceMetrics()
        self.colors = None
        
    def create_argument_parser(self) -> argparse.ArgumentParser:
        """Create and configure argument parser"""
        parser = argparse.ArgumentParser(
            description="Fetch ASNs, their announced prefixes, expand to IPs, and discover associated domains for organizations.",
            epilog="Example: %(prog)s -o cloudflare --discover-domains --fast",
            formatter_class=argparse.RawDescriptionHelpFormatter
        )
        
        # Required arguments
        parser.add_argument(
            '-o', '--org', required=True,
            help='Organization name or substring to search for'
        )
        
        # ASN discovery options
        asn_group = parser.add_argument_group('ASN Discovery Options')
        asn_group.add_argument(
            '--page-size', type=int, default=500,
            help='Number of items to fetch per GraphQL page (default: 500)'
        )
        
        # Domain discovery options
        domain_group = parser.add_argument_group('Domain Discovery Options')
        domain_group.add_argument(
            '--discover-domains', action='store_true',
            help='Enable domain discovery from IP addresses (adds significant processing time)'
        )
        domain_group.add_argument(
            '--discovery-methods', nargs='+', 
            choices=['dns', 'cert', 'http', 'service', 'all'],
            default=['dns', 'cert'],
            help='Domain discovery methods to use (default: dns cert)'
        )
        domain_group.add_argument(
            '--domain-workers', type=int, default=50,
            help='Number of concurrent workers for domain discovery (default: 50)'
        )
        domain_group.add_argument(
            '--domain-timeout', type=int, default=3,
            help='Timeout in seconds for domain discovery operations (default: 3)'
        )
        
        # Performance options
        perf_group = parser.add_argument_group('Performance Options')
        perf_group.add_argument(
            '--sample-rate', type=float, default=1.0,
            help='Fraction of IPs to process for domain discovery (0.1 = 10%%, useful for large datasets)'
        )
        perf_group.add_argument(
            '--chunk-size', type=int, default=10000,
            help='Chunk size for processing large IP ranges (default: 10000)'
        )
        perf_group.add_argument(
            '--domain-chunk-size', type=int, default=100,
            help='Chunk size for domain discovery processing (default: 100)'
        )
        perf_group.add_argument(
            '--fast', action='store_true',
            help='Enable fast mode (reduced timeouts, fewer ports, early termination)'
        )
        
        # Network options
        net_group = parser.add_argument_group('Network Options')
        net_group.add_argument(
            '--http-ports', nargs='+', type=int,
            default=Config.DEFAULT_HTTP_PORTS,
            help='HTTP ports to scan for domain discovery'
        )
        net_group.add_argument(
            '--https-ports', nargs='+', type=int, 
            default=Config.DEFAULT_HTTPS_PORTS,
            help='HTTPS ports to scan for certificate domains'
        )
        
        # Output options
        output_group = parser.add_argument_group('Output Options')
        output_group.add_argument(
            '--output-dir', '-d', 
            help='Output directory for generated files (default: current directory)'
        )
        output_group.add_argument(
            '--quiet', '-q', action='store_true',
            help='Enable quiet mode (warnings and errors only)'
        )
        output_group.add_argument(
            '--verbose', '-v', action='store_true',
            help='Enable verbose logging (debug level)'
        )
        output_group.add_argument(
            '--no-color', action='store_true',
            help='Disable colorized output'
        )
        output_group.add_argument(
            '--no-banner', action='store_true',
            help='Skip ASCII art banner'
        )
        
        # Database options
        db_group = parser.add_argument_group('Database Options')
        db_group.add_argument(
            '--use-database', action='store_true',
            help='Store results in SQLite database for future use'
        )
        db_group.add_argument(
            '--database-path', default='netscout.db',
            help='Path to SQLite database file (default: netscout.db)'
        )
        db_group.add_argument(
            '--export-from-db', action='store_true',
            help='Export previously stored results from database to files'
        )
        
        # Advanced options
        advanced_group = parser.add_argument_group('Advanced Options')
        advanced_group.add_argument(
            '--no-fallback', action='store_true',
            help='Disable BGPView API fallback when ASRank API fails'
        )
        advanced_group.add_argument(
            '--skip-ip-expansion', action='store_true',
            help='Skip IP expansion phase (only generate ASN and prefix files)'
        )
        
        return parser
    
    def validate_arguments(self, args: argparse.Namespace) -> bool:
        """Validate command line arguments"""
        # Validate sample rate
        if args.sample_rate <= 0 or args.sample_rate > 1:
            self.logger.error("Error: --sample-rate must be between 0 and 1")
            return False
        
        # Validate port lists
        try:
            args.http_ports = validate_port_list(args.http_ports)
            args.https_ports = validate_port_list(args.https_ports)
        except Exception as e:
            self.logger.error(f"Port validation error: {e}")
            return False
        
        # Validate discovery methods
        try:
            args.discovery_methods = parse_discovery_methods(args.discovery_methods)
        except ValueError as e:
            self.logger.error(f"Discovery method validation error: {e}")
            return False
        
        # Set output directory
        if args.output_dir is None:
            args.output_dir = os.getcwd()
        elif not os.path.exists(args.output_dir):
            try:
                os.makedirs(args.output_dir, exist_ok=True)
                self.logger.info(f"Created output directory: {args.output_dir}")
            except OSError as e:
                self.logger.error(f"Cannot create output directory: {e}")
                return False
        
        # Validate database options
        if args.export_from_db and not args.use_database:
            args.use_database = True  # Auto-enable database for export
        
        return True
    
    def setup_components(self, args: argparse.Namespace) -> tuple:
        """Setup and configure application components"""
        # Initialize core components
        asn_discovery = ASNDiscovery(page_size=args.page_size)
        domain_discovery = DomainDiscovery() if args.discover_domains else None
        data_processor = DataProcessor()
        database = NetScoutDatabase(args.database_path) if args.use_database else None
        
        # Configure global settings
        Config.DEFAULT_HTTP_PORTS = args.http_ports
        Config.DEFAULT_HTTPS_PORTS = args.https_ports
        
        return asn_discovery, domain_discovery, data_processor, database
    
    def show_banner(self):
        """Display neon ASCII art banner"""
        banner = create_ascii_banner()
        separators = create_neon_separators()
        
        print(self.colors.rainbow_text(banner))
        print(self.colors.highlight(separators['stars']))
        print()
    
    def print_configuration(self, args: argparse.Namespace):
        """Print current configuration"""
        separators = create_neon_separators()
        
        print(self.colors.title("═══ CONFIGURATION ═══"))
        print(f"{self.colors.info('Organization:')} {self.colors.highlight(args.org)}")
        print(f"{self.colors.info('Output directory:')} {self.colors.file_path(args.output_dir)}")
        
        if args.use_database:
            print(f"{self.colors.info('Database:')} {self.colors.file_path(args.database_path)}")
            if args.export_from_db:
                print(f"{self.colors.info('Mode:')} {self.colors.warning('Export from database')}")
        
        if args.discover_domains:
            methods_colored = [self.colors.success(method) for method in args.discovery_methods]
            print(f"{self.colors.info('Domain discovery:')} {', '.join(methods_colored)}")
            if args.fast:
                print(f"{self.colors.info('Fast mode:')} {self.colors.success('enabled')}")
            print(f"{self.colors.info('Workers:')} {self.colors.stat_number(str(args.domain_workers))}")
            print(f"{self.colors.info('Timeout:')} {self.colors.stat_number(str(args.domain_timeout))}s")
            if args.sample_rate < 1.0:
                print(f"{self.colors.info('Sample rate:')} {self.colors.stat_number(f'{args.sample_rate*100:.1f}%')}")
        else:
            print(f"{self.colors.info('Domain discovery:')} {self.colors.dim('disabled')}")
        
        print(self.colors.highlight(separators['dots']))
        print()
    
    def run_asn_discovery_phase(self, args: argparse.Namespace, asn_discovery: ASNDiscovery, 
                               data_processor: DataProcessor, database: NetScoutDatabase = None) -> dict:
        """Run the ASN discovery and file generation phase"""
        print(self.colors.title("🔍 STARTING ASN DISCOVERY"))
        
        # Process organization to files
        results = data_processor.process_organization_to_files(
            args.org, 
            asn_discovery, 
            args.output_dir, 
            metrics=self.performance_metrics
        )
        
        if not results:
            print(self.colors.error(f"❌ No ASNs found for organization '{args.org}'"))
            return {}
        
        # Log results
        stats = results['stats']
        print(self.colors.success(f"✔ Found {self.colors.stat_number(str(stats['asn_count']))} ASNs"))
        print(self.colors.success(f"✔ Found {self.colors.stat_number(str(stats['prefix_count']))} IP prefixes"))
        
        return results
    
    def run_domain_discovery_phase(self, args: argparse.Namespace, results: dict, 
                                  domain_discovery: DomainDiscovery, data_processor: DataProcessor, 
                                  database: NetScoutDatabase = None) -> str:
        """Run the domain discovery phase"""
        print(self.colors.title("🌐 STARTING DOMAIN DISCOVERY"))
        print(self.colors.warning("⚠️  This process can take significant time for large IP ranges!"))
        
        if args.sample_rate < 1.0:
            print(self.colors.warning(f"⚠️  Processing {self.colors.stat_number(f'{args.sample_rate*100:.1f}%')} sample of IPs"))
        
        domain_file = data_processor.process_ips_to_domains(
            results['ip_file'],
            domain_discovery,
            args.discovery_methods,
            output_dir=args.output_dir,
            fast_mode=args.fast,
            sample_rate=args.sample_rate,
            max_workers=args.domain_workers,
            timeout=args.domain_timeout,
            metrics=self.performance_metrics
        )
        
        return domain_file
    
    def print_final_summary(self, args: argparse.Namespace, results: dict, domain_file: str = None):
        """Print final execution summary"""
        # Collect statistics
        stats = {
            'organization': args.org,
            'processing_time': self.performance_metrics.elapsed_time,
        }
        
        if 'stats' in results:
            stats.update(results['stats'])
        
        if domain_file and os.path.exists(domain_file):
            from .utils import count_lines_in_file
            stats['domain_count'] = count_lines_in_file(domain_file)
            stats['methods_used'] = args.discovery_methods
        
        if self.performance_metrics.total_requests > 0:
            stats['success_rate'] = self.performance_metrics.success_rate
        
        # Print summary
        separators = create_neon_separators()
        print(self.colors.title("🎯 DISCOVERY COMPLETE"))
        
        # Create a neon box with the stats
        summary_text = f"""Organization: {args.org}
Processing Time: {format_duration(self.performance_metrics.elapsed_time)}
Requests Made: {self.performance_metrics.total_requests:,}
Success Rate: {self.performance_metrics.success_rate:.1f}%"""
        
        if 'stats' in results:
            result_stats = results['stats']
            summary_text += f"""
ASNs Found: {result_stats.get('asn_count', 0):,}
IP Prefixes: {result_stats.get('prefix_count', 0):,}"""
            
        if domain_file and os.path.exists(domain_file):
            from .utils import count_lines_in_file
            domain_count = count_lines_in_file(domain_file)
            summary_text += f"\nDomains Discovered: {domain_count:,}"
        
        print(self.colors.neon_box(summary_text))
        
        # Print file locations
        print(self.colors.title("📁 GENERATED FILES"))
        if 'asn_file' in results:
            print(f"{self.colors.success('✔')} {self.colors.info('ASNs:')} {self.colors.file_path(results['asn_file'])}")
        if 'prefix_file' in results:
            print(f"{self.colors.success('✔')} {self.colors.info('Prefixes:')} {self.colors.file_path(results['prefix_file'])}")
        if 'ip_file' in results:
            print(f"{self.colors.success('✔')} {self.colors.info('IPs:')} {self.colors.file_path(results['ip_file'])}")
        if domain_file:
            print(f"{self.colors.success('✔')} {self.colors.info('Domains:')} {self.colors.file_path(domain_file)}")
        
        print(self.colors.highlight(separators['thick']))
    
    def run_database_export(self, args: argparse.Namespace, database: NetScoutDatabase) -> bool:
        """Export data from database to files"""
        print(self.colors.title("💾 EXPORTING FROM DATABASE"))
        
        try:
            # Check if organization exists in database
            stats = database.get_organization_stats(args.org)
            if not stats:
                print(self.colors.error(f"❌ No data found for organization '{args.org}' in database"))
                return False
            
            print(self.colors.info(f"Found organization: {self.colors.highlight(args.org)}"))
            print(self.colors.info(f"ASNs: {self.colors.stat_number(str(stats['actual_asn_count']))}"))
            print(self.colors.info(f"Prefixes: {self.colors.stat_number(str(stats['actual_prefix_count']))}"))
            print(self.colors.info(f"Domains: {self.colors.stat_number(str(stats['actual_domain_count']))}"))
            
            # Export to files
            files = database.export_to_files(args.org, args.output_dir)
            
            separators = create_neon_separators()
            print(self.colors.title("📄 EXPORTED FILES"))
            for file_type, file_path in files.items():
                file_label = file_type.replace('_', ' ').title()
                print(f"{self.colors.success('✔')} {self.colors.info(file_label)}: {self.colors.file_path(file_path)}")
            
            print(self.colors.highlight(separators['thick']))
            return True
            
        except Exception as e:
            print(self.colors.error(f"❌ Database export failed: {e}"))
            return False
    
    def main(self, argv: List[str] = None) -> int:
        """Main CLI entry point"""
        # Parse arguments
        parser = self.create_argument_parser()
        args = parser.parse_args(argv)
        
        # Setup logging
        self.logger = setup_logging(verbose=args.verbose, quiet=args.quiet)
        
        # Setup colors
        self.colors = get_color_scheme(enabled=not args.no_color)
        
        # Show banner
        if not args.no_banner and not args.quiet:
            self.show_banner()
        
        # Validate arguments
        if not self.validate_arguments(args):
            return 1
        
        # Print configuration
        self.print_configuration(args)
        
        # Setup components
        asn_discovery, domain_discovery, data_processor, database = self.setup_components(args)
        
        try:
            # Handle database export mode
            if args.export_from_db:
                success = self.run_database_export(args, database)
                return 0 if success else 1
            
            # Start database session if using database
            session_id = None
            if database:
                session_id = database.start_discovery_session(
                    args.org, 
                    args.discovery_methods if args.discover_domains else None
                )
            
            # Phase 1: ASN Discovery and File Generation
            results = self.run_asn_discovery_phase(args, asn_discovery, data_processor, database)
            if not results:
                if database and session_id:
                    database.end_discovery_session(session_id, error="No ASNs found")
                return 1
            
            # Phase 2: Domain Discovery (optional)
            domain_file = None
            if args.discover_domains and not args.skip_ip_expansion:
                domain_file = self.run_domain_discovery_phase(args, results, domain_discovery, data_processor, database)
            
            # End database session
            if database and session_id:
                database.end_discovery_session(session_id, self.performance_metrics)
            
            # Print final summary
            self.print_final_summary(args, results, domain_file)
            
            return 0
            
        except KeyboardInterrupt:
            self.logger.warning("Interrupted by user")
            if database and session_id:
                database.end_discovery_session(session_id, error="Interrupted by user")
            return 130
        except Exception as e:
            self.logger.error(f"Unexpected error: {e}")
            if database and session_id:
                database.end_discovery_session(session_id, error=str(e))
            if args.verbose:
                import traceback
                self.logger.debug(traceback.format_exc())
            return 1
        finally:
            # Close database connection
            if database:
                database.close()


def main(argv: List[str] = None) -> int:
    """Main entry point for the CLI application"""
    cli = ASNToolCLI()
    return cli.main(argv)


if __name__ == "__main__":
    sys.exit(main())