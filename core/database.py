#!/usr/bin/env python3
"""
Database Manager
===============

Optimized database operations for the vulnerability scanner.
Handles SQLite database with proper indexing, connection pooling,
and efficient query management.
"""

import sqlite3
import json
import threading
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from contextlib import contextmanager
import logging

logger = logging.getLogger(__name__)

class DatabaseManager:
    """Optimized database management with connection pooling"""

    def __init__(self, db_path: str = 'scanner_results.db'):
        self.db_path = db_path
        self.connection_pool: Dict[str, sqlite3.Connection] = {}
        self.pool_lock = threading.Lock()
        self.init_database()

    @contextmanager
    def get_connection(self):
        """Get a database connection with automatic cleanup"""
        thread_id = threading.current_thread().ident

        with self.pool_lock:
            if thread_id not in self.connection_pool:
                self.connection_pool[thread_id] = sqlite3.connect(self.db_path)

            conn = self.connection_pool[thread_id]
            conn.execute("BEGIN")

        try:
            yield conn
        except Exception as e:
            conn.execute("ROLLBACK")
            raise e
        finally:
            conn.execute("COMMIT")

    def init_database(self) -> None:
        """Initialize database with optimized schema and indexes"""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Create scan_results table with enhanced schema
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    target_url TEXT NOT NULL,
                    vulnerability_type TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    response_code INTEGER,
                    response_content TEXT,
                    is_vulnerable BOOLEAN DEFAULT 0,
                    confidence_score REAL DEFAULT 0.0,
                    data_extracted BOOLEAN DEFAULT 0,
                    extracted_data TEXT,
                    severity TEXT DEFAULT 'LOW',
                    scan_session_id TEXT,
                    target_domain TEXT,
                    response_time REAL,
                    payload_category TEXT,
                    risk_score REAL DEFAULT 0.0,
                    remediation TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Create indexes for performance
            indexes = [
                ('idx_scan_results_timestamp', 'timestamp'),
                ('idx_scan_results_target_url', 'target_url'),
                ('idx_scan_results_vulnerability_type', 'vulnerability_type'),
                ('idx_scan_results_is_vulnerable', 'is_vulnerable'),
                ('idx_scan_results_severity', 'severity'),
                ('idx_scan_results_scan_session', 'scan_session_id'),
                ('idx_scan_results_target_domain', 'target_domain'),
                ('idx_scan_results_data_extracted', 'data_extracted'),
                ('idx_scan_results_confidence', 'confidence_score'),
                ('idx_scan_results_risk', 'risk_score'),
                ('idx_scan_results_payload_category', 'payload_category')
            ]

            for index_name, column in indexes:
                try:
                    cursor.execute(f'CREATE INDEX IF NOT EXISTS {index_name} ON scan_results ({column})')
                except sqlite3.Error as e:
                    logger.warning(f"Failed to create index {index_name}: {e}")

            # Create scan_sessions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_sessions (
                    id TEXT PRIMARY KEY,
                    target_url TEXT NOT NULL,
                    start_time TEXT NOT NULL,
                    end_time TEXT,
                    status TEXT DEFAULT 'running',
                    total_urls INTEGER DEFAULT 0,
                    scanned_urls INTEGER DEFAULT 0,
                    vulnerabilities_found INTEGER DEFAULT 0,
                    critical_findings INTEGER DEFAULT 0,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Create discovered_urls table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS discovered_urls (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_session_id TEXT NOT NULL,
                    url TEXT NOT NULL UNIQUE,
                    status_code INTEGER,
                    title TEXT,
                    discovered_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    last_scanned TEXT,
                    is_tested BOOLEAN DEFAULT 0,
                    FOREIGN KEY (scan_session_id) REFERENCES scan_sessions (id)
                )
            ''')

            # Create indexes for scan_sessions and discovered_urls
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_sessions_start_time ON scan_sessions (start_time)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_sessions_status ON scan_sessions (status)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_discovered_urls_session ON discovered_urls (scan_session_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_discovered_urls_url ON discovered_urls (url)')

            logger.info("Database initialized with optimized schema")

    def save_scan_result(self, result: Dict[str, Any], scan_session_id: Optional[str] = None) -> int:
        """Save scan result with enhanced metadata"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()

                # Calculate risk score based on severity and data extraction
                risk_score = self._calculate_risk_score(
                    result.get('severity', 'LOW'),
                    result.get('data_extracted', False),
                    result.get('confidence_score', 0.0)
                )

                # Extract target domain for indexing
                target_domain = self._extract_domain(result.get('target_url', ''))

                # Insert or update result
                cursor.execute('''
                    INSERT OR REPLACE INTO scan_results (
                        timestamp, target_url, vulnerability_type, payload,
                        response_code, response_content, is_vulnerable, confidence_score,
                        data_extracted, extracted_data, severity, scan_session_id,
                        target_domain, response_time, payload_category, risk_score,
                        updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ''', (
                    result.get('timestamp', datetime.now().isoformat()),
                    result.get('target_url', ''),
                    result.get('vulnerability_type', ''),
                    result.get('payload', ''),
                    result.get('response_code'),
                    result.get('response_content', '')[:10000],  # Limit response content size
                    result.get('is_vulnerable', False),
                    result.get('confidence_score', 0.0),
                    result.get('data_extracted', False),
                    json.dumps(result.get('extracted_data')) if result.get('extracted_data') else None,
                    result.get('severity', 'LOW'),
                    scan_session_id,
                    target_domain,
                    result.get('response_time'),
                    result.get('payload_category'),
                    risk_score
                ))

                result_id = cursor.lastrowid

                # Update scan session statistics
                if scan_session_id:
                    self._update_session_stats(scan_session_id, result)

                logger.info(f"Saved scan result {result_id} for {result.get('vulnerability_type')}")
                return result_id

        except Exception as e:
            logger.error(f"Error saving scan result: {e}")
            return -1

    def _calculate_risk_score(self, severity: str, data_extracted: bool, confidence: float) -> float:
        """Calculate risk score based on multiple factors"""
        base_score = {
            'LOW': 1.0,
            'MEDIUM': 3.0,
            'HIGH': 7.0,
            'CRITICAL': 10.0
        }.get(severity, 1.0)

        # Increase score for data extraction
        if data_extracted:
            base_score *= 2.0

        # Adjust based on confidence
        risk_score = base_score * (0.5 + confidence * 0.5)

        return min(risk_score, 10.0)  # Cap at 10.0

    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL for indexing"""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return f"{parsed.scheme}://{parsed.netloc}"
        except Exception:
            return url.split('/')[0] if '//' in url else url

    def _update_session_stats(self, session_id: str, result: Dict[str, Any]) -> None:
        """Update scan session statistics"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()

                # Update vulnerabilities count
                if result.get('is_vulnerable'):
                    cursor.execute('''
                        UPDATE scan_sessions
                        SET vulnerabilities_found = vulnerabilities_found + 1
                        WHERE id = ?
                    ''', (session_id,))

                # Update critical findings count
                if result.get('data_extracted'):
                    cursor.execute('''
                        UPDATE scan_sessions
                        SET critical_findings = critical_findings + 1
                        WHERE id = ?
                    ''', (session_id,))

        except Exception as e:
            logger.warning(f"Error updating session stats: {e}")

    def get_scan_results(self, filters: Dict[str, Any] = None,
                        limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """Get scan results with filtering and pagination"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()

                # Build query
                query = "SELECT * FROM scan_results WHERE 1=1"
                params = []

                if filters:
                    if 'target_domain' in filters:
                        query += " AND target_domain = ?"
                        params.append(filters['target_domain'])

                    if 'vulnerability_type' in filters:
                        query += " AND vulnerability_type = ?"
                        params.append(filters['vulnerability_type'])

                    if 'is_vulnerable' in filters:
                        query += " AND is_vulnerable = ?"
                        params.append(filters['is_vulnerable'])

                    if 'data_extracted' in filters:
                        query += " AND data_extracted = ?"
                        params.append(filters['data_extracted'])

                    if 'severity' in filters:
                        query += " AND severity = ?"
                        params.append(filters['severity'])

                    if 'scan_session_id' in filters:
                        query += " AND scan_session_id = ?"
                        params.append(filters['scan_session_id'])

                    if 'min_confidence' in filters:
                        query += " AND confidence_score >= ?"
                        params.append(filters['min_confidence'])

                    if 'min_risk_score' in filters:
                        query += " AND risk_score >= ?"
                        params.append(filters['min_risk_score'])

                    # Date range filter
                    if 'start_date' in filters:
                        query += " AND timestamp >= ?"
                        params.append(filters['start_date'])

                    if 'end_date' in filters:
                        query += " AND timestamp <= ?"
                        params.append(filters['end_date'])

                # Add ordering and pagination
                query += " ORDER BY risk_score DESC, timestamp DESC LIMIT ? OFFSET ?"
                params.extend([limit, offset])

                cursor.execute(query, params)
                rows = cursor.fetchall()

                # Convert to dictionaries
                results = []
                for row in rows:
                    result = self._row_to_dict(row)
                    results.append(result)

                return results

        except Exception as e:
            logger.error(f"Error getting scan results: {e}")
            return []

    def _row_to_dict(self, row) -> Dict[str, Any]:
        """Convert database row to dictionary"""
        columns = [
            'id', 'timestamp', 'target_url', 'vulnerability_type', 'payload',
            'response_code', 'response_content', 'is_vulnerable', 'confidence_score',
            'data_extracted', 'extracted_data', 'severity', 'scan_session_id',
            'target_domain', 'response_time', 'payload_category', 'risk_score',
            'remediation', 'created_at', 'updated_at'
        ]

        result = {}
        for i, column in enumerate(columns):
            if i < len(row):
                value = row[i]
                if column == 'extracted_data' and value:
                    try:
                        result[column] = json.loads(value)
                    except:
                        result[column] = value
                else:
                    result[column] = value

        return result

    def create_scan_session(self, target_url: str, session_id: Optional[str] = None) -> str:
        """Create a new scan session"""
        if not session_id:
            session_id = f"scan_{int(datetime.now().timestamp())}"

        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()

                cursor.execute('''
                    INSERT OR REPLACE INTO scan_sessions (id, target_url, start_time)
                    VALUES (?, ?, ?)
                ''', (session_id, target_url, datetime.now().isoformat()))

                logger.info(f"Created scan session {session_id} for {target_url}")
                return session_id

        except Exception as e:
            logger.error(f"Error creating scan session: {e}")
            return ""

    def update_scan_session(self, session_id: str, **updates) -> bool:
        """Update scan session information"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()

                # Build update query
                update_fields = []
                params = []

                for key, value in updates.items():
                    if key == 'end_time':
                        update_fields.append("end_time = ?")
                        params.append(value)
                    elif key == 'status':
                        update_fields.append("status = ?")
                        params.append(value)
                    elif key == 'total_urls':
                        update_fields.append("total_urls = ?")
                        params.append(value)
                    elif key == 'scanned_urls':
                        update_fields.append("scanned_urls = ?")
                        params.append(value)

                if update_fields:
                    query = f"UPDATE scan_sessions SET {', '.join(update_fields)} WHERE id = ?"
                    params.append(session_id)

                    cursor.execute(query, params)

                    logger.info(f"Updated scan session {session_id}")
                    return True

        except Exception as e:
            logger.error(f"Error updating scan session: {e}")
            return False

    def get_scan_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get scan session information"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()

                cursor.execute("SELECT * FROM scan_sessions WHERE id = ?", (session_id,))
                row = cursor.fetchone()

                if row:
                    columns = ['id', 'target_url', 'start_time', 'end_time', 'status',
                             'total_urls', 'scanned_urls', 'vulnerabilities_found',
                             'critical_findings', 'created_at']

                    session = {}
                    for i, column in enumerate(columns):
                        if i < len(row):
                            session[column] = row[i]

                    return session

        except Exception as e:
            logger.error(f"Error getting scan session: {e}")

        return None

    def cleanup_old_sessions(self, days_old: int = 30) -> int:
        """Clean up old scan sessions and results"""
        try:
            cutoff_date = datetime.now() - timedelta(days=days_old)

            with self.get_connection() as conn:
                cursor = conn.cursor()

                # Get sessions to delete
                cursor.execute("SELECT id FROM scan_sessions WHERE created_at < ?",
                             (cutoff_date.isoformat(),))
                old_sessions = [row[0] for row in cursor.fetchall()]

                deleted_count = 0

                for session_id in old_sessions:
                    # Delete results for this session
                    cursor.execute("DELETE FROM scan_results WHERE scan_session_id = ?", (session_id,))
                    deleted_results = cursor.rowcount

                    # Delete discovered URLs for this session
                    cursor.execute("DELETE FROM discovered_urls WHERE scan_session_id = ?", (session_id,))
                    deleted_urls = cursor.rowcount

                    # Delete session
                    cursor.execute("DELETE FROM scan_sessions WHERE id = ?", (session_id,))
                    deleted_count += 1

                    logger.info(f"Cleaned up session {session_id}: {deleted_results} results, {deleted_urls} URLs")

                return deleted_count

        except Exception as e:
            logger.error(f"Error cleaning up old sessions: {e}")
            return 0

    def get_statistics(self, target_domain: Optional[str] = None) -> Dict[str, Any]:
        """Get scan statistics"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()

                stats = {}

                # Basic counts
                base_query = "SELECT COUNT(*) FROM scan_results WHERE 1=1"
                params = []

                if target_domain:
                    base_query += " AND target_domain = ?"
                    params.append(target_domain)

                # Total scans
                cursor.execute(base_query, params)
                stats['total_scans'] = cursor.fetchone()[0]

                # Vulnerable scans
                cursor.execute(base_query + " AND is_vulnerable = 1", params)
                stats['vulnerable_scans'] = cursor.fetchone()[0]

                # Critical findings
                cursor.execute(base_query + " AND data_extracted = 1", params)
                stats['critical_findings'] = cursor.fetchone()[0]

                # By severity
                for severity in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']:
                    cursor.execute(base_query + " AND severity = ?", params + [severity])
                    stats[f'{severity.lower()}_count'] = cursor.fetchone()[0]

                # By vulnerability type
                cursor.execute("SELECT vulnerability_type, COUNT(*) FROM scan_results WHERE 1=1" +
                             (" AND target_domain = ?" if target_domain else "") +
                             " GROUP BY vulnerability_type ORDER BY COUNT(*) DESC LIMIT 10", params)
                stats['vulnerability_types'] = {row[0]: row[1] for row in cursor.fetchall()}

                # Average risk score
                cursor.execute("SELECT AVG(risk_score) FROM scan_results WHERE 1=1" +
                             (" AND target_domain = ?" if target_domain else ""), params)
                avg_risk = cursor.fetchone()[0]
                stats['average_risk_score'] = round(avg_risk or 0, 2)

                return stats

        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
            return {}

# Global database manager instance
db_manager = DatabaseManager()