"""
SQLite database functionality for NetScout.

This module provides database storage and retrieval for ASN discovery results,
allowing for persistent storage and querying of discovered data.
"""

import sqlite3
import logging
import ipaddress
from datetime import datetime
from typing import List, Dict, Optional, Tuple, Any
from pathlib import Path

from .core import PerformanceMetrics


class NetScoutDatabase:
    """SQLite database manager for NetScout results"""
    
    def __init__(self, db_path: str = "netscout.db"):
        """
        Initialize database connection and create tables if they don't exist.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = Path(db_path)
        self.logger = logging.getLogger(__name__)
        self.conn = None
        self._connect()
        self._create_tables()
    
    def _connect(self):
        """Establish database connection"""
        try:
            self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
            self.conn.row_factory = sqlite3.Row  # Enable column access by name
            self.logger.info(f"Connected to database: {self.db_path}")
        except sqlite3.Error as e:
            self.logger.error(f"Database connection failed: {e}")
            raise
    
    def _create_tables(self):
        """Create database tables if they don't exist"""
        cursor = self.conn.cursor()
        
        # Organizations table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS organizations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                search_term TEXT NOT NULL,
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                asn_count INTEGER DEFAULT 0,
                prefix_count INTEGER DEFAULT 0,
                ip_count INTEGER DEFAULT 0,
                domain_count INTEGER DEFAULT 0
            )
        """)
        
        # ASNs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS asns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                organization_id INTEGER NOT NULL,
                asn INTEGER NOT NULL,
                description TEXT,
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (organization_id) REFERENCES organizations (id),
                UNIQUE(organization_id, asn)
            )
        """)
        
        # IP Prefixes table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ip_prefixes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asn_id INTEGER NOT NULL,
                prefix TEXT NOT NULL,
                prefix_length INTEGER NOT NULL,
                network_address TEXT NOT NULL,
                broadcast_address TEXT,
                ip_count INTEGER NOT NULL,
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (asn_id) REFERENCES asns (id),
                UNIQUE(asn_id, prefix)
            )
        """)
        
        # Individual IPs table (optional, for sampled IPs)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ip_addresses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                prefix_id INTEGER NOT NULL,
                ip_address TEXT NOT NULL,
                ip_int INTEGER NOT NULL,
                processed_for_domains BOOLEAN DEFAULT FALSE,
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (prefix_id) REFERENCES ip_prefixes (id),
                UNIQUE(prefix_id, ip_address)
            )
        """)
        
        # Discovered domains table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS domains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                domain TEXT NOT NULL,
                discovery_method TEXT NOT NULL,
                port INTEGER,
                ssl_info TEXT,
                http_status INTEGER,
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(ip_address, domain, discovery_method)
            )
        """)
        
        # Discovery sessions table for tracking runs
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS discovery_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                organization_name TEXT NOT NULL,
                start_time TIMESTAMP NOT NULL,
                end_time TIMESTAMP,
                total_asns INTEGER DEFAULT 0,
                total_prefixes INTEGER DEFAULT 0,
                total_ips INTEGER DEFAULT 0,
                total_domains INTEGER DEFAULT 0,
                discovery_methods TEXT,
                status TEXT DEFAULT 'running',
                error_message TEXT
            )
        """)
        
        # Create indexes for better performance
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_asns_org ON asns(organization_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_prefixes_asn ON ip_prefixes(asn_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_ips_prefix ON ip_addresses(prefix_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_domains_ip ON domains(ip_address)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_domains_domain ON domains(domain)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_ips_int ON ip_addresses(ip_int)")
        
        self.conn.commit()
        self.logger.debug("Database tables created/verified")
    
    def start_discovery_session(self, organization_name: str, discovery_methods: List[str] = None) -> int:
        """
        Start a new discovery session.
        
        Args:
            organization_name: Name of organization being discovered
            discovery_methods: List of discovery methods being used
            
        Returns:
            Session ID
        """
        cursor = self.conn.cursor()
        methods_str = ','.join(discovery_methods) if discovery_methods else None
        
        cursor.execute("""
            INSERT INTO discovery_sessions (organization_name, start_time, discovery_methods)
            VALUES (?, ?, ?)
        """, (organization_name, datetime.now(), methods_str))
        
        session_id = cursor.lastrowid
        self.conn.commit()
        self.logger.info(f"Started discovery session {session_id} for {organization_name}")
        return session_id
    
    def end_discovery_session(self, session_id: int, metrics: PerformanceMetrics = None, error: str = None):
        """
        End a discovery session with final statistics.
        
        Args:
            session_id: Session ID to end
            metrics: Performance metrics from the session
            error: Error message if session failed
        """
        cursor = self.conn.cursor()
        status = 'error' if error else 'completed'
        
        cursor.execute("""
            UPDATE discovery_sessions 
            SET end_time = ?, status = ?, error_message = ?
            WHERE id = ?
        """, (datetime.now(), status, error, session_id))
        
        self.conn.commit()
        self.logger.info(f"Ended discovery session {session_id} with status: {status}")
    
    def store_organization(self, name: str, search_term: str) -> int:
        """
        Store organization information.
        
        Args:
            name: Organization name
            search_term: Search term used to find the organization
            
        Returns:
            Organization ID
        """
        cursor = self.conn.cursor()
        
        cursor.execute("""
            INSERT OR IGNORE INTO organizations (name, search_term)
            VALUES (?, ?)
        """, (name, search_term))
        
        # Get the organization ID
        cursor.execute("SELECT id FROM organizations WHERE name = ?", (name,))
        org_id = cursor.fetchone()[0]
        
        self.conn.commit()
        return org_id
    
    def store_asns(self, organization_id: int, asns: List[Dict[str, Any]]):
        """
        Store ASN information.
        
        Args:
            organization_id: Organization ID
            asns: List of ASN dictionaries with 'asn' and optional 'description'
        """
        cursor = self.conn.cursor()
        
        asn_data = [(organization_id, asn_info['asn'], asn_info.get('description')) 
                    for asn_info in asns]
        
        cursor.executemany("""
            INSERT OR IGNORE INTO asns (organization_id, asn, description)
            VALUES (?, ?, ?)
        """, asn_data)
        
        self.conn.commit()
        self.logger.info(f"Stored {len(asns)} ASNs for organization {organization_id}")
    
    def store_prefixes(self, asn_number: int, prefixes: List[str], organization_id: int):
        """
        Store IP prefixes for an ASN.
        
        Args:
            asn_number: ASN number
            prefixes: List of CIDR prefixes
            organization_id: Organization ID (to find ASN ID)
        """
        cursor = self.conn.cursor()
        
        # Get ASN ID
        cursor.execute("""
            SELECT id FROM asns WHERE organization_id = ? AND asn = ?
        """, (organization_id, asn_number))
        
        result = cursor.fetchone()
        if not result:
            self.logger.error(f"ASN {asn_number} not found for organization {organization_id}")
            return
        
        asn_id = result[0]
        prefix_data = []
        
        for prefix_str in prefixes:
            try:
                network = ipaddress.ip_network(prefix_str)
                prefix_data.append((
                    asn_id,
                    prefix_str,
                    network.prefixlen,
                    str(network.network_address),
                    str(network.broadcast_address),
                    network.num_addresses
                ))
            except ValueError as e:
                self.logger.warning(f"Invalid prefix {prefix_str}: {e}")
                continue
        
        cursor.executemany("""
            INSERT OR IGNORE INTO ip_prefixes 
            (asn_id, prefix, prefix_length, network_address, broadcast_address, ip_count)
            VALUES (?, ?, ?, ?, ?, ?)
        """, prefix_data)
        
        self.conn.commit()
        self.logger.info(f"Stored {len(prefix_data)} prefixes for ASN {asn_number}")
    
    def store_domains(self, domains_data: List[Dict[str, Any]]):
        """
        Store discovered domains.
        
        Args:
            domains_data: List of domain dictionaries with ip, domain, method, etc.
        """
        cursor = self.conn.cursor()
        
        domain_records = []
        for domain_info in domains_data:
            domain_records.append((
                domain_info['ip'],
                domain_info['domain'],
                domain_info['method'],
                domain_info.get('port'),
                domain_info.get('ssl_info'),
                domain_info.get('http_status')
            ))
        
        cursor.executemany("""
            INSERT OR IGNORE INTO domains 
            (ip_address, domain, discovery_method, port, ssl_info, http_status)
            VALUES (?, ?, ?, ?, ?, ?)
        """, domain_records)
        
        self.conn.commit()
        self.logger.info(f"Stored {len(domain_records)} domain records")
    
    def get_organization_stats(self, organization_name: str) -> Optional[Dict[str, Any]]:
        """
        Get statistics for an organization.
        
        Args:
            organization_name: Organization name
            
        Returns:
            Dictionary with organization statistics or None if not found
        """
        cursor = self.conn.cursor()
        
        cursor.execute("""
            SELECT o.*, 
                   COUNT(DISTINCT a.asn) as actual_asn_count,
                   COUNT(DISTINCT p.prefix) as actual_prefix_count,
                   SUM(p.ip_count) as total_ips,
                   COUNT(DISTINCT d.domain) as actual_domain_count
            FROM organizations o
            LEFT JOIN asns a ON o.id = a.organization_id
            LEFT JOIN ip_prefixes p ON a.id = p.asn_id
            LEFT JOIN domains d ON d.ip_address IN (
                SELECT network_address FROM ip_prefixes WHERE asn_id = a.id
            )
            WHERE o.name = ?
            GROUP BY o.id
        """, (organization_name,))
        
        result = cursor.fetchone()
        if result:
            return dict(result)
        return None
    
    def search_domains_by_pattern(self, pattern: str, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Search for domains matching a pattern.
        
        Args:
            pattern: SQL LIKE pattern (e.g., '%.google.com')
            limit: Maximum number of results
            
        Returns:
            List of domain records
        """
        cursor = self.conn.cursor()
        
        cursor.execute("""
            SELECT d.*, o.name as organization_name
            FROM domains d
            JOIN ip_prefixes p ON d.ip_address LIKE (p.network_address || '%')
            JOIN asns a ON p.asn_id = a.id
            JOIN organizations o ON a.organization_id = o.id
            WHERE d.domain LIKE ?
            ORDER BY d.discovered_at DESC
            LIMIT ?
        """, (pattern, limit))
        
        return [dict(row) for row in cursor.fetchall()]
    
    def get_asns_for_organization(self, organization_name: str) -> List[Dict[str, Any]]:
        """Get all ASNs for an organization"""
        cursor = self.conn.cursor()
        
        cursor.execute("""
            SELECT a.asn, a.description, COUNT(p.id) as prefix_count
            FROM organizations o
            JOIN asns a ON o.id = a.organization_id
            LEFT JOIN ip_prefixes p ON a.id = p.asn_id
            WHERE o.name = ?
            GROUP BY a.id, a.asn, a.description
            ORDER BY a.asn
        """, (organization_name,))
        
        return [dict(row) for row in cursor.fetchall()]
    
    def export_to_files(self, organization_name: str, output_dir: str):
        """
        Export organization data to text files (compatible with original format).
        
        Args:
            organization_name: Organization to export
            output_dir: Output directory path
        """
        from .utils import sanitize_filename
        import os
        
        safe_name = sanitize_filename(organization_name)
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        cursor = self.conn.cursor()
        
        # Export ASNs
        cursor.execute("""
            SELECT a.asn FROM organizations o
            JOIN asns a ON o.id = a.organization_id
            WHERE o.name = ?
            ORDER BY a.asn
        """, (organization_name,))
        
        asn_file = output_path / f"{safe_name}_asns.txt"
        with open(asn_file, 'w') as f:
            for row in cursor.fetchall():
                f.write(f"{row[0]}\n")
        
        # Export prefixes
        cursor.execute("""
            SELECT a.asn, p.prefix FROM organizations o
            JOIN asns a ON o.id = a.organization_id
            JOIN ip_prefixes p ON a.id = p.asn_id
            WHERE o.name = ?
            ORDER BY a.asn, p.prefix
        """, (organization_name,))
        
        prefix_file = output_path / f"{safe_name}_prefixes.txt"
        with open(prefix_file, 'w') as f:
            for row in cursor.fetchall():
                f.write(f"{row[0]} {row[1]}\n")
        
        # Export domains
        cursor.execute("""
            SELECT DISTINCT d.domain FROM organizations o
            JOIN asns a ON o.id = a.organization_id
            JOIN ip_prefixes p ON a.id = p.asn_id
            JOIN domains d ON d.ip_address LIKE (p.network_address || '%')
            WHERE o.name = ?
            ORDER BY d.domain
        """, (organization_name,))
        
        domain_file = output_path / f"{safe_name}_domains.txt"
        with open(domain_file, 'w') as f:
            for row in cursor.fetchall():
                f.write(f"{row[0]}\n")
        
        self.logger.info(f"Exported data for {organization_name} to {output_path}")
        return {
            'asn_file': str(asn_file),
            'prefix_file': str(prefix_file),
            'domain_file': str(domain_file)
        }
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
            self.logger.info("Database connection closed")
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()