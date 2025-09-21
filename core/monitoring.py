#!/usr/bin/env python3
"""
Monitoring Manager
=================

Comprehensive monitoring and logging system for the vulnerability scanner.
Includes performance monitoring, security event tracking, and system health checks.
"""

import time
import threading
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime
import logging
import json
import os

logger = logging.getLogger(__name__)

# Optional psutil import for system monitoring
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    logger.warning("psutil not available - system monitoring features will be limited")

@dataclass
class SystemMetrics:
    """System performance metrics"""
    timestamp: float
    cpu_percent: float
    memory_percent: float
    disk_usage_percent: float
    network_connections: int
    open_files: int
    thread_count: int
    scan_queue_size: int = 0

@dataclass
class ScanMetrics:
    """Scan performance metrics"""
    session_id: str
    target_url: str
    start_time: float
    end_time: Optional[float] = None
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    vulnerabilities_found: int = 0
    critical_findings: int = 0
    average_response_time: float = 0.0
    errors: List[str] = field(default_factory=list)

@dataclass
class SecurityEvent:
    """Security event for tracking"""
    timestamp: float
    event_type: str
    severity: str
    message: str
    source_ip: str = ""
    target_url: str = ""
    payload: str = ""
    response_code: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

class MonitoringManager:
    """Comprehensive monitoring and metrics collection"""

    def __init__(self):
        self.system_metrics: List[SystemMetrics] = []
        self.scan_metrics: Dict[str, ScanMetrics] = {}
        self.security_events: List[SecurityEvent] = []
        self.active_scans: Dict[str, threading.Thread] = {}

        # Monitoring configuration
        self.metrics_interval = 30  # seconds
        self.max_metrics_history = 1000
        self.max_events_history = 5000

        # Start background monitoring
        self._start_system_monitoring()
        logger.info("Monitoring manager initialized")

    def _start_system_monitoring(self) -> None:
        """Start background system monitoring"""
        def monitor_system():
            while True:
                try:
                    if PSUTIL_AVAILABLE:
                        metrics = SystemMetrics(
                            timestamp=time.time(),
                            cpu_percent=psutil.cpu_percent(interval=1),
                            memory_percent=psutil.virtual_memory().percent,
                            disk_usage_percent=psutil.disk_usage('/').percent,
                            network_connections=len(psutil.net_connections()),
                            open_files=len(psutil.Process().open_files()),
                            thread_count=threading.active_count(),
                            scan_queue_size=len(self.active_scans)
                        )
                    else:
                        # Limited metrics without psutil
                        metrics = SystemMetrics(
                            timestamp=time.time(),
                            cpu_percent=0.0,  # Cannot measure without psutil
                            memory_percent=0.0,  # Cannot measure without psutil
                            disk_usage_percent=0.0,  # Cannot measure without psutil
                            network_connections=0,  # Cannot measure without psutil
                            open_files=0,  # Cannot measure without psutil
                            thread_count=threading.active_count(),
                            scan_queue_size=len(self.active_scans)
                        )

                    self.system_metrics.append(metrics)

                    # Keep only recent metrics
                    if len(self.system_metrics) > self.max_metrics_history:
                        self.system_metrics = self.system_metrics[-self.max_metrics_history:]

                    time.sleep(self.metrics_interval)

                except Exception as e:
                    logger.error(f"System monitoring error: {e}")
                    time.sleep(self.metrics_interval)

        monitor_thread = threading.Thread(target=monitor_system, daemon=True)
        monitor_thread.start()

    def start_scan_monitoring(self, session_id: str, target_url: str) -> None:
        """Start monitoring a scan session"""
        self.scan_metrics[session_id] = ScanMetrics(
            session_id=session_id,
            target_url=target_url,
            start_time=time.time()
        )

        logger.info(f"Started monitoring scan session {session_id} for {target_url}")

    def update_scan_metrics(self, session_id: str, **updates) -> None:
        """Update scan metrics"""
        if session_id not in self.scan_metrics:
            return

        metrics = self.scan_metrics[session_id]

        for key, value in updates.items():
            if hasattr(metrics, key):
                setattr(metrics, key, value)

        # Calculate average response time
        if metrics.total_requests > 0:
            metrics.average_response_time = sum(
                getattr(thread, 'total_response_time', 0)
                for thread in self.active_scans.values()
                if hasattr(thread, 'total_response_time')
            ) / metrics.total_requests

    def end_scan_monitoring(self, session_id: str) -> None:
        """End monitoring a scan session"""
        if session_id not in self.scan_metrics:
            return

        metrics = self.scan_metrics[session_id]
        metrics.end_time = time.time()

        duration = metrics.end_time - metrics.start_time

        logger.info(f"Scan session {session_id} completed in {duration:.2f}s")
        logger.info(f"Requests: {metrics.total_requests}, Vulnerabilities: {metrics.vulnerabilities_found}, Critical: {metrics.critical_findings}")

        # Remove from active scans
        if session_id in self.active_scans:
            del self.active_scans[session_id]

    def log_security_event(self, event_type: str, severity: str, message: str,
                          source_ip: str = "", target_url: str = "",
                          payload: str = "", response_code: int = 0,
                          **metadata) -> None:
        """Log a security event"""
        event = SecurityEvent(
            timestamp=time.time(),
            event_type=event_type,
            severity=severity,
            message=message,
            source_ip=source_ip,
            target_url=target_url,
            payload=payload,
            response_code=response_code,
            metadata=metadata
        )

        self.security_events.append(event)

        # Keep only recent events
        if len(self.security_events) > self.max_events_history:
            self.security_events = self.security_events[-self.max_events_history:]

        # Log based on severity
        log_method = {
            'LOW': logger.info,
            'MEDIUM': logger.warning,
            'HIGH': logger.error,
            'CRITICAL': logger.critical
        }.get(severity, logger.info)

        log_method(f"Security Event [{event_type}]: {message}")

    def get_system_health(self) -> Dict[str, Any]:
        """Get current system health status"""
        if not self.system_metrics:
            return {'status': 'unknown', 'message': 'No metrics available'}

        latest = self.system_metrics[-1]

        # Determine health status
        cpu_high = latest.cpu_percent > 80
        memory_high = latest.memory_percent > 85
        disk_high = latest.disk_usage_percent > 90

        if cpu_high or memory_high or disk_high:
            status = 'unhealthy'
            issues = []
            if cpu_high:
                issues.append(f"High CPU usage: {latest.cpu_percent:.1f}%")
            if memory_high:
                issues.append(f"High memory usage: {latest.memory_percent:.1f}%")
            if disk_high:
                issues.append(f"High disk usage: {latest.disk_usage_percent:.1f}%")
            message = ', '.join(issues)
        else:
            status = 'healthy'
            message = 'System running normally'

        return {
            'status': status,
            'message': message,
            'metrics': {
                'cpu_percent': latest.cpu_percent,
                'memory_percent': latest.memory_percent,
                'disk_usage_percent': latest.disk_usage_percent,
                'network_connections': latest.network_connections,
                'open_files': latest.open_files,
                'thread_count': latest.thread_count,
                'active_scans': latest.scan_queue_size
            },
            'timestamp': latest.timestamp
        }

    def get_scan_statistics(self) -> Dict[str, Any]:
        """Get comprehensive scan statistics"""
        total_scans = len(self.scan_metrics)
        active_scans = len(self.active_scans)
        completed_scans = sum(1 for m in self.scan_metrics.values() if m.end_time is not None)

        # Calculate totals
        total_requests = sum(m.total_requests for m in self.scan_metrics.values())
        total_vulnerabilities = sum(m.vulnerabilities_found for m in self.scan_metrics.values())
        total_critical = sum(m.critical_findings for m in self.scan_metrics.values())
        total_errors = sum(len(m.errors) for m in self.scan_metrics.values())

        # Calculate average performance
        avg_response_time = 0.0
        if total_requests > 0:
            total_response_time = sum(
                m.average_response_time * m.total_requests
                for m in self.scan_metrics.values()
            )
            avg_response_time = total_response_time / total_requests

        return {
            'total_scans': total_scans,
            'active_scans': active_scans,
            'completed_scans': completed_scans,
            'total_requests': total_requests,
            'total_vulnerabilities': total_vulnerabilities,
            'total_critical_findings': total_critical,
            'total_errors': total_errors,
            'average_response_time': avg_response_time,
            'system_health': self.get_system_health()
        }

    def get_recent_security_events(self, limit: int = 50,
                                 event_type: Optional[str] = None,
                                 severity: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get recent security events with optional filtering"""
        events = self.security_events[-limit:]  # Get most recent

        if event_type:
            events = [e for e in events if e.event_type == event_type]

        if severity:
            events = [e for e in events if e.severity == severity]

        # Convert to dictionaries
        return [
            {
                'timestamp': e.timestamp,
                'event_type': e.event_type,
                'severity': e.severity,
                'message': e.message,
                'source_ip': e.source_ip,
                'target_url': e.target_url,
                'payload': e.payload[:100] + '...' if len(e.payload) > 100 else e.payload,
                'response_code': e.response_code,
                'metadata': e.metadata
            }
            for e in events
        ]

    def export_metrics(self, format: str = 'json') -> str:
        """Export monitoring data in specified format"""
        data = {
            'system_metrics': [
                {
                    'timestamp': m.timestamp,
                    'cpu_percent': m.cpu_percent,
                    'memory_percent': m.memory_percent,
                    'disk_usage_percent': m.disk_usage_percent,
                    'network_connections': m.network_connections,
                    'scan_queue_size': m.scan_queue_size
                }
                for m in self.system_metrics[-100:]  # Last 100 metrics
            ],
            'scan_statistics': self.get_scan_statistics(),
            'security_events': self.get_recent_security_events(100),
            'export_timestamp': time.time()
        }

        if format == 'json':
            return json.dumps(data, indent=2, default=str)
        else:
            # Could implement CSV or other formats
            return json.dumps(data, indent=2, default=str)

    def cleanup_old_data(self, days: int = 7) -> None:
        """Clean up old monitoring data"""
        cutoff_time = time.time() - (days * 24 * 60 * 60)

        # Clean up system metrics
        self.system_metrics = [m for m in self.system_metrics if m.timestamp > cutoff_time]

        # Clean up security events
        self.security_events = [e for e in self.security_events if e.timestamp > cutoff_time]

        logger.info(f"Cleaned up monitoring data older than {days} days")

    def set_performance_thresholds(self, thresholds: Dict[str, float]) -> None:
        """Set performance monitoring thresholds"""
        self.performance_thresholds = thresholds

    def check_performance_alerts(self) -> List[str]:
        """Check for performance issues and return alerts"""
        alerts = []
        health = self.get_system_health()

        if health['status'] == 'unhealthy':
            alerts.append(f"System health issue: {health['message']}")

        # Check scan queue
        if len(self.active_scans) > 10:
            alerts.append(f"High scan queue: {len(self.active_scans)} active scans")

        # Check error rates
        stats = self.get_scan_statistics()
        if stats['total_requests'] > 0:
            error_rate = stats['total_errors'] / stats['total_requests']
            if error_rate > 0.1:  # 10% error rate
                alerts.append(f"High error rate: {error_rate:.1%}")

        return alerts

# Global monitoring manager instance
monitoring_manager = MonitoringManager()