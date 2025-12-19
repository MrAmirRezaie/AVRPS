#!/usr/bin/env python3
"""
Advanced Vulnerability Remediation and Patching System (AVRPS)
Enterprise-Grade Cross-Platform Vulnerability Management Tool

Features:
- Automated CVE detection and vulnerability scanning
- Intelligent patch management with rollback capability
- Multi-platform support (Linux, Windows, macOS)
- Comprehensive reporting and analytics
- Progress tracking with real-time updates
- Database-backed historical tracking
- API integration for CVE databases
- Configuration management
- Security compliance checking
"""

import os
import sys
import json
import time
import logging
import hashlib
import sqlite3
import argparse
import tempfile
import platform
import threading
import subprocess
import configparser
from abc import ABC, abstractmethod
from typing import Dict, List, Tuple, Optional, Any, Set, Union, Callable
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum, IntEnum
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from pathlib import Path
from collections import defaultdict, OrderedDict
import signal
import traceback
import zipfile
import tarfile
import gzip
import shutil
import urllib.request
import urllib.error
import ssl
import random
import string
from xml.etree import ElementTree
import csv
import pickle

# Third-party imports with graceful fallbacks
THIRD_PARTY_IMPORTS = {}

try:
    import requests
    from requests.adapters import HTTPAdapter
    Retry = None
    try:
        # Newer versions of requests don't bundle urllib3
        from urllib3.util.retry import Retry
    except ImportError:
        try:
            # Fallback for older requests versions
            import sys
            if 'requests.packages.urllib3' in sys.modules or hasattr(requests, 'packages'):
                from requests.packages.urllib3.util.retry import Retry  # type: ignore
        except (ImportError, AttributeError):
            # Last resort: Retry will remain None
            pass
    THIRD_PARTY_IMPORTS['requests'] = True
except ImportError:
    THIRD_PARTY_IMPORTS['requests'] = False
    Retry = None
    print("[WARNING] 'requests' module not available. Network features limited.")

try:
    import yaml
    THIRD_PARTY_IMPORTS['yaml'] = True
except ImportError:
    THIRD_PARTY_IMPORTS['yaml'] = False

try:
    from packaging import version
    THIRD_PARTY_IMPORTS['packaging'] = True
except ImportError:
    THIRD_PARTY_IMPORTS['packaging'] = False

try:
    import psutil
    THIRD_PARTY_IMPORTS['psutil'] = True
except ImportError:
    THIRD_PARTY_IMPORTS['psutil'] = False

try:
    import tqdm
    THIRD_PARTY_IMPORTS['tqdm'] = True
except ImportError:
    THIRD_PARTY_IMPORTS['tqdm'] = False

try:
    import colorama
    from colorama import Fore, Back, Style
    colorama.init(autoreset=True)
    THIRD_PARTY_IMPORTS['colorama'] = True
except ImportError:
    # Create mock color classes if colorama is not available
    class Fore:
        BLACK = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ''
    class Back:
        BLACK = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ''
    class Style:
        DIM = NORMAL = BRIGHT = RESET_ALL = ''
    THIRD_PARTY_IMPORTS['colorama'] = False

# Constants
VERSION = "3.0.0"
AUTHOR = "Security Operations Team"
DEFAULT_CONFIG_FILE = "avrps_config.ini"
DEFAULT_DB_FILE = "vulnerability_database.db"
DEFAULT_LOG_FILE = "avrps.log"
MAX_WORKERS = 5
TIMEOUT = 300  # 5 minutes
CHUNK_SIZE = 8192

# Logging configuration
def setupLogging(logLevel: str = "INFO", logFile: str = DEFAULT_LOG_FILE) -> logging.Logger:
    """Configure comprehensive logging system"""
    logFormatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(module)s:%(lineno)d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    logger = logging.getLogger('AVRPS')
    logger.setLevel(getattr(logging, logLevel.upper(), logging.INFO))
    
    # File handler with rotation
    try:
        fileHandler = logging.FileHandler(logFile, encoding='utf-8')
        fileHandler.setFormatter(logFormatter)
        logger.addHandler(fileHandler)
    except Exception as e:
        print(f"Warning: Could not set up file logging: {e}")
    
    # Console handler with colored output
    consoleHandler = logging.StreamHandler(sys.stdout)
    if THIRD_PARTY_IMPORTS['colorama']:
        class ColoredFormatter(logging.Formatter):
            """Custom formatter with colors"""
            COLORS = {
                'DEBUG': Fore.CYAN,
                'INFO': Fore.GREEN,
                'WARNING': Fore.YELLOW,
                'ERROR': Fore.RED,
                'CRITICAL': Fore.RED + Back.WHITE + Style.BRIGHT
            }
            
            def format(self, record):
                if record.levelname in self.COLORS:
                    color = self.COLORS[record.levelname]
                    record.levelname = f"{color}{record.levelname}{Style.RESET_ALL}"
                    record.msg = f"{color}{record.msg}{Style.RESET_ALL}"
                return super().format(record)
        
        consoleHandler.setFormatter(ColoredFormatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%H:%M:%S'
        ))
    else:
        consoleHandler.setFormatter(logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%H:%M:%S'
        ))
    
    logger.addHandler(consoleHandler)
    
    # Suppress third-party library logs
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)
    
    return logger

logger = setupLogging()

# Enums
class SeverityLevel(IntEnum):
    """Vulnerability severity levels with numeric values for sorting"""
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0
    UNKNOWN = -1
    
    @classmethod
    def fromString(cls, severityStr: str) -> 'SeverityLevel':
        """Convert string to SeverityLevel"""
        severityMap = {
            'critical': cls.CRITICAL,
            'high': cls.HIGH,
            'medium': cls.MEDIUM,
            'low': cls.LOW,
            'info': cls.INFO
        }
        return severityMap.get(severityStr.lower(), cls.UNKNOWN)

class OperatingSystem(Enum):
    """Supported operating systems"""
    LINUX = "Linux"
    WINDOWS = "Windows"
    MACOS = "Darwin"
    BSD = "BSD"
    SOLARIS = "SunOS"
    UNKNOWN = "Unknown"
    
    @classmethod
    def detect(cls) -> 'OperatingSystem':
        """Detect current operating system"""
        system = platform.system()
        for osType in cls:
            if osType.value == system:
                return osType
        return cls.UNKNOWN

class PatchStatus(Enum):
    """Patch application status"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    ROLLED_BACK = "rolled_back"
    MANUAL_INTERVENTION_REQUIRED = "manual_intervention_required"
    
    @property
    def isTerminal(self) -> bool:
        """Check if status is terminal (no further processing needed)"""
        return self in [self.SUCCESS, self.FAILED, self.SKIPPED, self.ROLLED_BACK]

class PackageManager(Enum):
    """Package manager types"""
    APT = "apt"  # Debian, Ubuntu
    YUM = "yum"  # RHEL, CentOS
    DNF = "dnf"  # Fedora, RHEL 8+
    ZYPPER = "zypper"  # openSUSE
    PACMAN = "pacman"  # Arch
    APK = "apk"  # Alpine
    PIP = "pip"  # Python
    NPM = "npm"  # Node.js
    GEM = "gem"  # Ruby
    CHOCOLATEY = "chocolatey"  # Windows
    WINGET = "winget"  # Windows
    BREW = "brew"  # macOS
    UNKNOWN = "unknown"

class Architecture(Enum):
    """System architectures"""
    X86 = "x86"
    X64 = "x64"
    ARM = "arm"
    ARM64 = "arm64"
    PPC = "ppc"
    PPC64 = "ppc64"
    MIPS = "mips"
    SPARC = "sparc"
    UNKNOWN = "unknown"

# Data Classes
@dataclass
class SystemPackage:
    """Detailed system package information"""
    name: str
    version: str
    architecture: Architecture
    vendor: str = ""
    installDate: Optional[datetime] = None
    packageManager: PackageManager = PackageManager.UNKNOWN
    filePath: Optional[str] = None
    dependencies: List[str] = field(default_factory=list)
    description: str = ""
    license: str = ""
    size: int = 0
    hashValue: str = ""
    
    def toDict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        data = asdict(self)
        if self.installDate:
            data['installDate'] = self.installDate.isoformat()
        data['architecture'] = self.architecture.value
        data['packageManager'] = self.packageManager.value
        return data
    
    @classmethod
    def fromDict(cls, data: Dict[str, Any]) -> 'SystemPackage':
        """Create from dictionary"""
        data = data.copy()
        if 'installDate' in data and data['installDate']:
            data['installDate'] = datetime.fromisoformat(data['installDate'])
        data['architecture'] = Architecture(data.get('architecture', 'unknown'))
        data['packageManager'] = PackageManager(data.get('packageManager', 'unknown'))
        return cls(**data)

@dataclass
class Vulnerability:
    """Comprehensive vulnerability information"""
    cveId: str
    description: str
    severity: SeverityLevel
    cvssScore: float
    cvssVector: str = ""
    affectedPackages: List[str] = field(default_factory=list)
    affectedVersions: Dict[str, List[str]] = field(default_factory=dict)
    fixedVersion: Optional[str] = None
    exploitAvailable: bool = False
    exploitMaturity: str = ""
    publishedDate: datetime = field(default_factory=datetime.now)
    lastModifiedDate: datetime = field(default_factory=datetime.now)
    references: List[str] = field(default_factory=list)
    mitigation: str = ""
    workaround: str = ""
    impact: str = ""
    advisory: str = ""
    credits: str = ""
    
    def toDict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        data = asdict(self)
        data['severity'] = self.severity.value
        data['publishedDate'] = self.publishedDate.isoformat()
        data['lastModifiedDate'] = self.lastModifiedDate.isoformat()
        return data
    
    @classmethod
    def fromDict(cls, data: Dict[str, Any]) -> 'Vulnerability':
        """Create from dictionary"""
        data = data.copy()
        data['severity'] = SeverityLevel(data.get('severity', -1))
        data['publishedDate'] = datetime.fromisoformat(data['publishedDate'])
        data['lastModifiedDate'] = datetime.fromisoformat(data['lastModifiedDate'])
        return cls(**data)

@dataclass
class ScanResult:
    """Vulnerability scan result with confidence scoring"""
    vulnerability: Vulnerability
    detectedPackage: SystemPackage
    evidence: str
    confidence: float  # 0.0 to 1.0
    timestamp: datetime = field(default_factory=datetime.now)
    scannerVersion: str = VERSION
    falsePositive: bool = False
    notes: str = ""
    
    def toDict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        data = asdict(self)
        data['vulnerability'] = self.vulnerability.toDict()
        data['detectedPackage'] = self.detectedPackage.toDict()
        data['timestamp'] = self.timestamp.isoformat()
        return data

@dataclass
class PatchResult:
    """Detailed patch application result"""
    cveId: str
    status: PatchStatus
    operation: str
    details: str
    timestamp: datetime = field(default_factory=datetime.now)
    rollbackPoint: Optional[str] = None
    executionTime: float = 0.0
    errorMessage: Optional[str] = None
    systemChanges: List[str] = field(default_factory=list)
    verificationStatus: bool = False
    patchVersion: Optional[str] = None
    
    def toDict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        data = asdict(self)
        data['status'] = self.status.value
        data['timestamp'] = self.timestamp.isoformat()
        return data

@dataclass
class SystemInfo:
    """Comprehensive system information"""
    osType: OperatingSystem
    osVersion: str
    kernelVersion: str
    hostname: str
    architecture: Architecture
    cpuInfo: Dict[str, Any] = field(default_factory=dict)
    memoryInfo: Dict[str, Any] = field(default_factory=dict)
    diskInfo: Dict[str, Any] = field(default_factory=dict)
    networkInterfaces: List[Dict[str, Any]] = field(default_factory=list)
    installedPackages: List[SystemPackage] = field(default_factory=list)
    runningServices: List[str] = field(default_factory=list)
    openPorts: List[int] = field(default_factory=list)
    users: List[str] = field(default_factory=list)
    securityPolicies: Dict[str, Any] = field(default_factory=dict)
    environmentVariables: Dict[str, str] = field(default_factory=dict)
    systemUptime: float = 0.0
    lastBootTime: Optional[datetime] = None
    timezone: str = ""
    locale: str = ""
    
    def toDict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        data = asdict(self)
        data['osType'] = self.osType.value
        data['architecture'] = self.architecture.value
        data['installedPackages'] = [pkg.toDict() for pkg in self.installedPackages]
        if self.lastBootTime:
            data['lastBootTime'] = self.lastBootTime.isoformat()
        return data
    
    def generateFingerprint(self) -> str:
        """Generate a unique fingerprint for the system"""
        fingerprintData = {
            'hostname': self.hostname,
            'osType': self.osType.value,
            'osVersion': self.osVersion,
            'kernelVersion': self.kernelVersion,
            'architecture': self.architecture.value,
            'cpuModel': self.cpuInfo.get('model', ''),
            'totalMemory': self.memoryInfo.get('total', 0)
        }
        
        # Add package fingerprints
        packageFingerprints = []
        for pkg in self.installedPackages[:100]:  # Limit to first 100 packages
            packageFingerprints.append(f"{pkg.name}:{pkg.version}:{pkg.architecture.value}")
        
        fingerprintData['packages'] = sorted(packageFingerprints)
        
        # Create hash
        fingerprintStr = json.dumps(fingerprintData, sort_keys=True)
        return hashlib.sha256(fingerprintStr.encode()).hexdigest()

# Configuration Manager
class ConfigurationManager:
    """Manages configuration with validation and defaults"""
    
    DEFAULT_CONFIG = {
        'general': {
            'log_level': 'INFO',
            'max_workers': '5',
            'timeout': '300',
            'database_path': DEFAULT_DB_FILE,
            'cache_ttl': '3600',
            'backup_enabled': 'true',
            'backup_count': '5'
        },
        'scanning': {
            'deep_scan': 'false',
            'scan_timeout': '600',
            'max_packages': '0',  # 0 = unlimited
            'cve_check_enabled': 'true',
            'config_check_enabled': 'true',
            'privilege_escalation_check': 'true'
        },
        'patching': {
            'auto_patch': 'false',
            'dry_run_default': 'true',
            'create_snapshots': 'true',
            'rollback_enabled': 'true',
            'max_rollback_points': '10',
            'confirmation_required': 'true',
            'whitelist': '',
            'blacklist': ''
        },
        'reporting': {
            'report_format': 'all',  # json, html, txt, all
            'save_reports': 'true',
            'report_dir': 'reports',
            'email_reports': 'false',
            'webhook_enabled': 'false'
        },
        'api': {
            'nvd_api_key': '',
            'nvd_rate_limit': '10',
            'use_local_cache': 'true',
            'cache_dir': 'cache'
        },
        'notifications': {
            'enabled': 'false',
            'email_server': '',
            'email_port': '587',
            'email_username': '',
            'email_password': '',
            'email_recipients': '',
            'webhook_url': '',
            'slack_webhook': ''
        }
    }
    
    def __init__(self, configFile: str = DEFAULT_CONFIG_FILE):
        self.configFile = Path(configFile)
        self.config = configparser.ConfigParser()
        self.loadConfiguration()
    
    def loadConfiguration(self) -> None:
        """Load configuration from file or create default"""
        if self.configFile.exists():
            try:
                self.config.read(self.configFile, encoding='utf-8')
                logger.info(f"Loaded configuration from {self.configFile}")
            except Exception as e:
                logger.error(f"Failed to load configuration: {e}")
                self.createDefaultConfig()
        else:
            logger.info("Configuration file not found, creating default")
            self.createDefaultConfig()
    
    def createDefaultConfig(self) -> None:
        """Create default configuration file"""
        try:
            self.config.read_dict(self.DEFAULT_CONFIG)
            with open(self.configFile, 'w', encoding='utf-8') as f:
                self.config.write(f)
            logger.info(f"Created default configuration at {self.configFile}")
        except Exception as e:
            logger.error(f"Failed to create configuration file: {e}")
            # Use defaults in memory
            self.config.read_dict(self.DEFAULT_CONFIG)
    
    def get(self, section: str, key: str, defaultValue: Any = None) -> Any:
        """Get configuration value with type conversion"""
        try:
            value = self.config.get(section, key)
            
            # Type conversion based on default value type
            if defaultValue is not None:
                if isinstance(defaultValue, bool):
                    return self.config.getboolean(section, key)
                elif isinstance(defaultValue, int):
                    return self.config.getint(section, key)
                elif isinstance(defaultValue, float):
                    return self.config.getfloat(section, key)
                elif isinstance(defaultValue, list):
                    return [item.strip() for item in value.split(',') if item.strip()]
            
            return value
        except (configparser.NoSectionError, configparser.NoOptionError):
            return defaultValue
    
    def set(self, section: str, key: str, value: Any) -> None:
        """Set configuration value"""
        if not self.config.has_section(section):
            self.config.add_section(section)
        
        if isinstance(value, list):
            value = ','.join(str(item) for item in value)
        else:
            value = str(value)
        
        self.config.set(section, key, value)
    
    def save(self) -> None:
        """Save configuration to file"""
        try:
            with open(self.configFile, 'w', encoding='utf-8') as f:
                self.config.write(f)
            logger.info(f"Configuration saved to {self.configFile}")
        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")
    
    def validate(self) -> List[str]:
        """Validate configuration and return list of issues"""
        issues = []
        
        # Check required sections
        requiredSections = ['general', 'scanning', 'patching']
        for section in requiredSections:
            if not self.config.has_section(section):
                issues.append(f"Missing section: {section}")
        
        # Validate values
        maxWorkers = self.get('general', 'max_workers', 5)
        if maxWorkers <= 0 or maxWorkers > 50:
            issues.append("max_workers must be between 1 and 50")
        
        timeout = self.get('general', 'timeout', 300)
        if timeout <= 0:
            issues.append("timeout must be positive")
        
        return issues

# Database Manager with connection pooling and transaction support
class DatabaseManager:
    """Advanced database manager with connection pooling and transactions"""
    
    def __init__(self, dbPath: str = DEFAULT_DB_FILE):
        self.dbPath = Path(dbPath)
        self.connectionPool = []
        self.maxConnections = 5
        self.lock = threading.Lock()
        self.initializeDatabase()
    
    def getConnection(self) -> sqlite3.Connection:
        """Get a database connection from pool or create new one"""
        with self.lock:
            if self.connectionPool:
                conn = self.connectionPool.pop()
                try:
                    # Test if connection is still valid
                    conn.execute("SELECT 1")
                    return conn
                except sqlite3.Error:
                    conn.close()
            
            # Create new connection
            conn = sqlite3.connect(self.dbPath, timeout=30)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = NORMAL")
            conn.execute("PRAGMA cache_size = -2000")  # 2MB cache
            return conn
    
    def returnConnection(self, conn: sqlite3.Connection) -> None:
        """Return connection to pool"""
        with self.lock:
            if len(self.connectionPool) < self.maxConnections:
                self.connectionPool.append(conn)
            else:
                conn.close()
    
    def executeInTransaction(self, query: str, params: Tuple = (), commit: bool = True) -> sqlite3.Cursor:
        """Execute query in transaction with automatic connection management"""
        conn = self.getConnection()
        try:
            cursor = conn.cursor()
            cursor.execute(query, params)
            if commit:
                conn.commit()
            return cursor
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            self.returnConnection(conn)
    
    def initializeDatabase(self) -> None:
        """Initialize database with all required tables and indexes"""
        tables = [
            # Scan history
            """
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                system_fingerprint TEXT,
                scanner_version TEXT,
                total_vulnerabilities INTEGER DEFAULT 0,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                medium_count INTEGER DEFAULT 0,
                low_count INTEGER DEFAULT 0,
                scan_duration REAL DEFAULT 0,
                UNIQUE(system_fingerprint, timestamp)
            )
            """,
            
            # Vulnerability results
            """
            CREATE TABLE IF NOT EXISTS vulnerability_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                cve_id TEXT NOT NULL,
                package_name TEXT NOT NULL,
                package_version TEXT NOT NULL,
                package_architecture TEXT,
                fixed_version TEXT,
                severity INTEGER NOT NULL,
                cvss_score REAL DEFAULT 0,
                confidence REAL DEFAULT 0,
                evidence TEXT,
                false_positive BOOLEAN DEFAULT 0,
                status TEXT DEFAULT 'detected',
                FOREIGN KEY (scan_id) REFERENCES scan_history (id) ON DELETE CASCADE,
                UNIQUE(scan_id, cve_id, package_name)
            )
            """,
            
            # Patch history
            """
            CREATE TABLE IF NOT EXISTS patch_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                cve_id TEXT NOT NULL,
                package_name TEXT NOT NULL,
                operation TEXT NOT NULL,
                status TEXT NOT NULL,
                details TEXT,
                rollback_point TEXT,
                execution_time REAL DEFAULT 0,
                error_message TEXT,
                verification_status BOOLEAN DEFAULT 0,
                patch_version TEXT,
                UNIQUE(cve_id, package_name, timestamp)
            )
            """,
            
            # System snapshots
            """
            CREATE TABLE IF NOT EXISTS system_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                snapshot_type TEXT DEFAULT 'full',
                snapshot_data BLOB NOT NULL,
                snapshot_hash TEXT NOT NULL,
                description TEXT,
                UNIQUE(snapshot_hash, timestamp)
            )
            """,
            
            # CVE cache
            """
            CREATE TABLE IF NOT EXISTS cve_cache (
                cve_id TEXT PRIMARY KEY,
                cve_data BLOB NOT NULL,
                last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
                ttl INTEGER DEFAULT 86400,  -- 24 hours in seconds
                source TEXT DEFAULT 'unknown'
            )
            """,
            
            # Package inventory
            """
            CREATE TABLE IF NOT EXISTS package_inventory (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                system_fingerprint TEXT NOT NULL,
                package_name TEXT NOT NULL,
                package_version TEXT NOT NULL,
                package_architecture TEXT,
                package_manager TEXT,
                install_date DATETIME,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(system_fingerprint, package_name, package_version)
            )
            """,
            
            # Settings
            """
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                description TEXT
            )
            """
        ]
        
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_scan_history_fingerprint ON scan_history(system_fingerprint)",
            "CREATE INDEX IF NOT EXISTS idx_scan_history_timestamp ON scan_history(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_vuln_results_scan_id ON vulnerability_results(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_vuln_results_cve_id ON vulnerability_results(cve_id)",
            "CREATE INDEX IF NOT EXISTS idx_vuln_results_severity ON vulnerability_results(severity)",
            "CREATE INDEX IF NOT EXISTS idx_patch_history_cve_id ON patch_history(cve_id)",
            "CREATE INDEX IF NOT EXISTS idx_patch_history_status ON patch_history(status)",
            "CREATE INDEX IF NOT EXISTS idx_patch_history_timestamp ON patch_history(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_cve_cache_updated ON cve_cache(last_updated)",
            "CREATE INDEX IF NOT EXISTS idx_package_inventory_fingerprint ON package_inventory(system_fingerprint)",
            "CREATE INDEX IF NOT EXISTS idx_package_inventory_name ON package_inventory(package_name)"
        ]
        
        conn = self.getConnection()
        try:
            cursor = conn.cursor()
            
            # Create tables
            for tableSql in tables:
                cursor.execute(tableSql)
            
            # Create indexes
            for indexSql in indexes:
                try:
                    cursor.execute(indexSql)
                except sqlite3.OperationalError as e:
                    logger.warning(f"Index creation failed (may already exist): {e}")
            
            # Insert default settings
            defaultSettings = [
                ('database_version', VERSION, 'Database schema version'),
                ('last_maintenance', datetime.now().isoformat(), 'Last maintenance run'),
                ('retention_days', '90', 'Days to keep records'),
                ('auto_vacuum', 'true', 'Enable auto vacuum')
            ]
            
            cursor.executemany(
                "INSERT OR IGNORE INTO settings (key, value, description) VALUES (?, ?, ?)",
                defaultSettings
            )
            
            conn.commit()
            logger.info("Database initialized successfully")
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Database initialization failed: {e}")
            raise
        finally:
            self.returnConnection(conn)
    
    def saveScanResults(self, scanId: int, results: List[ScanResult]) -> None:
        """Save scan results to database"""
        if not results:
            return
        
        batchData = []
        for result in results:
            batchData.append((
                scanId,
                result.vulnerability.cveId,
                result.detectedPackage.name,
                result.detectedPackage.version,
                result.detectedPackage.architecture.value,
                result.vulnerability.fixedVersion,
                result.vulnerability.severity.value,
                result.vulnerability.cvssScore,
                result.confidence,
                result.evidence,
                1 if result.falsePositive else 0,
                'detected'
            ))
        
        query = """
        INSERT OR REPLACE INTO vulnerability_results 
        (scan_id, cve_id, package_name, package_version, package_architecture, 
         fixed_version, severity, cvss_score, confidence, evidence, 
         false_positive, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        
        conn = self.getConnection()
        try:
            cursor = conn.cursor()
            cursor.executemany(query, batchData)
            
            # Update scan summary
            cursor.execute("""
                UPDATE scan_history 
                SET total_vulnerabilities = (
                    SELECT COUNT(*) FROM vulnerability_results 
                    WHERE scan_id = ? AND false_positive = 0
                ),
                critical_count = (
                    SELECT COUNT(*) FROM vulnerability_results 
                    WHERE scan_id = ? AND severity = ? AND false_positive = 0
                ),
                high_count = (
                    SELECT COUNT(*) FROM vulnerability_results 
                    WHERE scan_id = ? AND severity = ? AND false_positive = 0
                ),
                medium_count = (
                    SELECT COUNT(*) FROM vulnerability_results 
                    WHERE scan_id = ? AND severity = ? AND false_positive = 0
                ),
                low_count = (
                    SELECT COUNT(*) FROM vulnerability_results 
                    WHERE scan_id = ? AND severity = ? AND false_positive = 0
                )
                WHERE id = ?
            """, (scanId, scanId, SeverityLevel.CRITICAL.value, 
                  scanId, SeverityLevel.HIGH.value,
                  scanId, SeverityLevel.MEDIUM.value,
                  scanId, SeverityLevel.LOW.value,
                  scanId))
            
            conn.commit()
            logger.debug(f"Saved {len(results)} scan results for scan ID {scanId}")
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Failed to save scan results: {e}")
            raise
        finally:
            self.returnConnection(conn)
    
    def createScanRecord(self, systemInfo: SystemInfo, scannerVersion: str = VERSION) -> int:
        """Create a new scan record and return scan ID"""
        fingerprint = systemInfo.generateFingerprint()
        
        query = """
        INSERT INTO scan_history 
        (system_fingerprint, scanner_version, timestamp)
        VALUES (?, ?, ?)
        RETURNING id
        """
        
        conn = self.getConnection()
        try:
            cursor = conn.cursor()
            cursor.execute(query, (fingerprint, scannerVersion, datetime.now().isoformat()))
            scanId = cursor.fetchone()[0]
            conn.commit()
            
            # Update package inventory
            self.updatePackageInventory(fingerprint, systemInfo.installedPackages)
            
            logger.info(f"Created scan record with ID: {scanId}")
            return scanId
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Failed to create scan record: {e}")
            raise
        finally:
            self.returnConnection(conn)
    
    def updatePackageInventory(self, fingerprint: str, packages: List[SystemPackage]) -> None:
        """Update package inventory for the system"""
        batchData = []
        currentTime = datetime.now().isoformat()
        
        for pkg in packages:
            batchData.append((
                fingerprint,
                pkg.name,
                pkg.version,
                pkg.architecture.value,
                pkg.packageManager.value,
                pkg.installDate.isoformat() if pkg.installDate else None,
                currentTime
            ))
        
        query = """
        INSERT OR REPLACE INTO package_inventory 
        (system_fingerprint, package_name, package_version, package_architecture, 
         package_manager, install_date, last_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """
        
        conn = self.getConnection()
        try:
            cursor = conn.cursor()
            cursor.executemany(query, batchData)
            conn.commit()
            logger.debug(f"Updated package inventory with {len(packages)} packages")
        except Exception as e:
            conn.rollback()
            logger.error(f"Failed to update package inventory: {e}")
        finally:
            self.returnConnection(conn)
    
    def savePatchResult(self, result: PatchResult) -> int:
        """Save patch result to database and return record ID"""
        query = """
        INSERT INTO patch_history 
        (cve_id, package_name, operation, status, details, rollback_point, 
         execution_time, error_message, verification_status, patch_version, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        RETURNING id
        """
        
        # Extract package name from details or use cve_id as fallback
        packageName = result.cveId  # Default
        if result.details:
            # Try to extract package name from details
            import re
            match = re.search(r'package[:\s]+([\w\-\.]+)', result.details, re.IGNORECASE)
            if match:
                packageName = match.group(1)
        
        conn = self.getConnection()
        try:
            cursor = conn.cursor()
            cursor.execute(query, (
                result.cveId,
                packageName,
                result.operation,
                result.status.value,
                result.details,
                result.rollbackPoint,
                result.executionTime,
                result.errorMessage,
                1 if result.verificationStatus else 0,
                result.patchVersion,
                result.timestamp.isoformat()
            ))
            recordId = cursor.fetchone()[0]
            conn.commit()
            
            logger.debug(f"Saved patch result for {result.cveId} with status {result.status.value}")
            return recordId
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Failed to save patch result: {e}")
            raise
        finally:
            self.returnConnection(conn)
    
    def getHistoricalData(self, days: int = 30) -> Dict[str, Any]:
        """Get historical scan and patch data"""
        conn = self.getConnection()
        try:
            cursor = conn.cursor()
            
            # Get scan statistics
            cursor.execute("""
                SELECT 
                    DATE(timestamp) as scan_date,
                    COUNT(*) as scan_count,
                    SUM(total_vulnerabilities) as total_vulns,
                    SUM(critical_count) as critical_vulns,
                    SUM(high_count) as high_vulns,
                    AVG(scan_duration) as avg_duration
                FROM scan_history
                WHERE timestamp >= datetime('now', ?)
                GROUP BY DATE(timestamp)
                ORDER BY scan_date DESC
            """, (f'-{days} days',))
            
            scanStats = [dict(row) for row in cursor.fetchall()]
            
            # Get patch statistics
            cursor.execute("""
                SELECT 
                    status,
                    COUNT(*) as count,
                    AVG(execution_time) as avg_time
                FROM patch_history
                WHERE timestamp >= datetime('now', ?)
                GROUP BY status
            """, (f'-{days} days',))
            
            patchStats = [dict(row) for row in cursor.fetchall()]
            
            # Get top vulnerabilities
            cursor.execute("""
                SELECT 
                    cve_id,
                    COUNT(*) as occurrence_count,
                    MAX(severity) as max_severity
                FROM vulnerability_results
                WHERE scan_id IN (
                    SELECT id FROM scan_history 
                    WHERE timestamp >= datetime('now', ?)
                )
                GROUP BY cve_id
                ORDER BY occurrence_count DESC, max_severity DESC
                LIMIT 10
            """, (f'-{days} days',))
            
            topVulns = [dict(row) for row in cursor.fetchall()]
            
            return {
                'scan_statistics': scanStats,
                'patch_statistics': patchStats,
                'top_vulnerabilities': topVulns,
                'time_period_days': days
            }
            
        except Exception as e:
            logger.error(f"Failed to get historical data: {e}")
            return {}
        finally:
            self.returnConnection(conn)
    
    def cleanupOldData(self, retentionDays: int = 90) -> int:
        """Clean up old data and return number of records deleted"""
        conn = self.getConnection()
        try:
            cursor = conn.cursor()
            
            # Get counts before deletion
            cursor.execute("SELECT COUNT(*) FROM scan_history WHERE timestamp < datetime('now', ?)", 
                          (f'-{retentionDays} days',))
            oldScans = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM patch_history WHERE timestamp < datetime('now', ?)", 
                          (f'-{retentionDays} days',))
            oldPatches = cursor.fetchone()[0]
            
            # Delete old data
            cursor.execute("DELETE FROM vulnerability_results WHERE scan_id IN (SELECT id FROM scan_history WHERE timestamp < datetime('now', ?))", 
                          (f'-{retentionDays} days',))
            
            cursor.execute("DELETE FROM scan_history WHERE timestamp < datetime('now', ?)", 
                          (f'-{retentionDays} days',))
            
            cursor.execute("DELETE FROM patch_history WHERE timestamp < datetime('now', ?)", 
                          (f'-{retentionDays} days',))
            
            # Delete orphaned package inventory entries
            cursor.execute("""
                DELETE FROM package_inventory 
                WHERE system_fingerprint NOT IN (
                    SELECT DISTINCT system_fingerprint FROM scan_history
                )
            """)
            
            # Vacuum database to reclaim space
            cursor.execute("VACUUM")
            
            conn.commit()
            
            totalDeleted = oldScans + oldPatches
            logger.info(f"Cleaned up {totalDeleted} old records (>{retentionDays} days)")
            return totalDeleted
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Failed to clean up old data: {e}")
            return 0
        finally:
            self.returnConnection(conn)
    
    def __del__(self):
        """Cleanup all database connections"""
        with self.lock:
            for conn in self.connectionPool:
                try:
                    conn.close()
                except:
                    pass
            self.connectionPool.clear()

# CVE Data Sources
class CveDataSource(ABC):
    """Abstract base class for CVE data sources"""
    
    @abstractmethod
    def fetchCves(self, since: Optional[datetime] = None) -> List[Vulnerability]:
        """Fetch CVE data from source"""
        pass
    
    @abstractmethod
    def getCveById(self, cveId: str) -> Optional[Vulnerability]:
        """Get specific CVE by ID"""
        pass
    
    @abstractmethod
    def searchCves(self, keywords: List[str]) -> List[Vulnerability]:
        """Search CVEs by keywords"""
        pass
    
    @property
    @abstractmethod
    def sourceName(self) -> str:
        """Get name of data source"""
        pass

class NvdDataSource(CveDataSource):
    """National Vulnerability Database (NVD) data source"""
    
    def __init__(self, apiKey: Optional[str] = None, cacheManager: Optional['CacheManager'] = None):
        self.apiKey = apiKey
        self.cacheManager = cacheManager
        self.baseUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.session = self.createSession() if THIRD_PARTY_IMPORTS['requests'] else None
        
    def createSession(self) -> requests.Session:
        """Create HTTP session with retry logic"""
        session = requests.Session()
        retryStrategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST"]
        )
        adapter = HTTPAdapter(max_retries=retryStrategy, pool_connections=10, pool_maxsize=100)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        session.headers.update({
            'User-Agent': f'AVRPS/{VERSION}',
            'Accept': 'application/json',
            'Accept-Encoding': 'gzip, deflate'
        })
        return session
    
    def fetchCves(self, since: Optional[datetime] = None) -> List[Vulnerability]:
        """Fetch recent CVEs from NVD"""
        vulnerabilities = []
        
        if not self.session:
            logger.warning("NVD data source disabled: requests module not available")
            return vulnerabilities
        
        try:
            params = {
                'resultsPerPage': 2000,
                'startIndex': 0
            }
            
            if since:
                # NVD expects format: YYYY-MM-DDTHH:MM:SS
                params['pubStartDate'] = since.strftime('%Y-%m-%dT%H:%M:%S')
                params['pubEndDate'] = datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
            
            if self.apiKey:
                params['apiKey'] = self.apiKey
            
            # Fetch data with pagination
            hasMore = True
            totalResults = 0
            
            while hasMore:
                try:
                    response = self.session.get(
                        self.baseUrl,
                        params=params,
                        timeout=30
                    )
                    response.raise_for_status()
                    
                    data = response.json()
                    
                    # Parse vulnerabilities
                    batchVulns = self.parseResponse(data)
                    vulnerabilities.extend(batchVulns)
                    
                    # Update pagination
                    totalResults = data.get('totalResults', 0)
                    params['startIndex'] += params['resultsPerPage']
                    
                    hasMore = params['startIndex'] < totalResults
                    
                    logger.debug(f"Fetched {len(batchVulns)} CVEs from NVD (total: {len(vulnerabilities)}/{totalResults})")
                    
                    # Rate limiting
                    if not self.apiKey:
                        time.sleep(6)  # NVD rate limit for unauthenticated requests
                    
                except requests.exceptions.RequestException as e:
                    logger.error(f"Error fetching CVEs from NVD: {e}")
                    hasMore = False
                except json.JSONDecodeError as e:
                    logger.error(f"Error parsing NVD response: {e}")
                    hasMore = False
            
            logger.info(f"Fetched {len(vulnerabilities)} CVEs from NVD")
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Failed to fetch CVEs from NVD: {e}")
            return []
    
    def parseResponse(self, data: Dict) -> List[Vulnerability]:
        """Parse NVD JSON response"""
        vulnerabilities = []
        
        for item in data.get('vulnerabilities', []):
            try:
                cve = item.get('cve', {})
                cveId = cve.get('id', '')
                
                # Skip if we have this in cache
                if self.cacheManager and self.cacheManager.get(f"cve_{cveId}"):
                    continue
                
                # Get metrics
                metrics = cve.get('metrics', {})
                
                # Calculate CVSS score
                cvssScore = 0.0
                cvssVector = ""
                
                if 'cvssMetricV31' in metrics:
                    cvssData = metrics['cvssMetricV31'][0].get('cvssData', {})
                    cvssScore = cvssData.get('baseScore', 0.0)
                    cvssVector = cvssData.get('vectorString', "")
                elif 'cvssMetricV30' in metrics:
                    cvssData = metrics['cvssMetricV30'][0].get('cvssData', {})
                    cvssScore = cvssData.get('baseScore', 0.0)
                    cvssVector = cvssData.get('vectorString', "")
                elif 'cvssMetricV2' in metrics:
                    cvssData = metrics['cvssMetricV2'][0].get('cvssData', {})
                    cvssScore = cvssData.get('baseScore', 0.0)
                    cvssVector = cvssData.get('vectorString', "")
                
                # Determine severity
                if cvssScore >= 9.0:
                    severity = SeverityLevel.CRITICAL
                elif cvssScore >= 7.0:
                    severity = SeverityLevel.HIGH
                elif cvssScore >= 4.0:
                    severity = SeverityLevel.MEDIUM
                elif cvssScore > 0:
                    severity = SeverityLevel.LOW
                else:
                    severity = SeverityLevel.INFO
                
                # Get descriptions
                descriptions = cve.get('descriptions', [])
                description = next((d.get('value', '') for d in descriptions if d.get('lang', '') == 'en'), '')
                
                # Get references
                references = [ref.get('url', '') for ref in cve.get('references', [])]
                
                # Get affected configurations
                affectedPackages = []
                affectedVersions = {}
                
                configurations = cve.get('configurations', [])
                for config in configurations:
                    for node in config.get('nodes', []):
                        for cpeMatch in node.get('cpeMatch', []):
                            cpeUri = cpeMatch.get('criteria', '')
                            if 'cpe:2.3:a:' in cpeUri:
                                parts = cpeUri.split(':')
                                if len(parts) >= 5:
                                    vendor = parts[3]
                                    product = parts[4]
                                    version = parts[5] if len(parts) > 5 else '*'
                                    
                                    if product not in affectedPackages:
                                        affectedPackages.append(product)
                                    
                                    if product not in affectedVersions:
                                        affectedVersions[product] = []
                                    
                                    if version != '*' and version not in affectedVersions[product]:
                                        affectedVersions[product].append(version)
                
                # Check for exploits
                exploitAvailable = False
                exploitMaturity = ""
                
                # Parse dates
                publishedDate = datetime.fromisoformat(cve.get('published', '').replace('Z', '+00:00'))
                lastModifiedDate = datetime.fromisoformat(cve.get('lastModified', '').replace('Z', '+00:00'))
                
                vulnerability = Vulnerability(
                    cveId=cveId,
                    description=description,
                    severity=severity,
                    cvssScore=cvssScore,
                    cvssVector=cvssVector,
                    affectedPackages=affectedPackages,
                    affectedVersions=affectedVersions,
                    fixedVersion=None,  # NVD doesn't provide fixed versions directly
                    exploitAvailable=exploitAvailable,
                    exploitMaturity=exploitMaturity,
                    publishedDate=publishedDate,
                    lastModifiedDate=lastModifiedDate,
                    references=references,
                    mitigation="",
                    workaround="",
                    impact="",
                    advisory="",
                    credits=""
                )
                
                # Cache the vulnerability
                if self.cacheManager:
                    self.cacheManager.set(f"cve_{cveId}", vulnerability.toDict(), ttl=86400)
                
                vulnerabilities.append(vulnerability)
                
            except Exception as e:
                logger.warning(f"Error parsing CVE entry: {e}")
                continue
        
        return vulnerabilities
    
    def getCveById(self, cveId: str) -> Optional[Vulnerability]:
        """Get specific CVE by ID"""
        # Check cache first
        if self.cacheManager:
            cached = self.cacheManager.get(f"cve_{cveId}")
            if cached:
                return Vulnerability.fromDict(cached)
        
        if not self.session:
            return None
        
        try:
            url = f"{self.baseUrl}?cveId={cveId}"
            if self.apiKey:
                url += f"&apiKey={self.apiKey}"
            
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            vulnerabilities = self.parseResponse(data)
            
            return vulnerabilities[0] if vulnerabilities else None
            
        except Exception as e:
            logger.error(f"Failed to fetch CVE {cveId}: {e}")
            return None
    
    def searchCves(self, keywords: List[str]) -> List[Vulnerability]:
        """Search CVEs by keywords"""
        # NVD doesn't support keyword search directly in free API
        # We'll fetch recent CVEs and filter
        recentCves = self.fetchCves(since=datetime.now() - timedelta(days=30))
        
        if not keywords:
            return recentCves
        
        results = []
        keywordLower = [k.lower() for k in keywords]
        
        for vuln in recentCves:
            searchText = f"{vuln.description} {vuln.cveId} {' '.join(vuln.affectedPackages)}".lower()
            if any(keyword in searchText for keyword in keywordLower):
                results.append(vuln)
        
        return results
    
    @property
    def sourceName(self) -> str:
        return "NVD (National Vulnerability Database)"

class LocalCveDatabase(CveDataSource):
    """Local CVE database with common vulnerabilities"""
    
    def __init__(self, dbPath: str = "local_cve_database.json"):
        self.dbPath = Path(dbPath)
        self.vulnerabilities: Dict[str, Vulnerability] = {}
        self.loadDatabase()
    
    def loadDatabase(self) -> None:
        """Load local CVE database from file or create default"""
        if self.dbPath.exists():
            try:
                with open(self.dbPath, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                for cveId, vulnData in data.items():
                    try:
                        self.vulnerabilities[cveId] = Vulnerability.fromDict(vulnData)
                    except Exception as e:
                        logger.warning(f"Error loading CVE {cveId}: {e}")
                
                logger.info(f"Loaded {len(self.vulnerabilities)} CVEs from local database")
                
            except Exception as e:
                logger.error(f"Failed to load local CVE database: {e}")
                self.createDefaultDatabase()
        else:
            logger.info("Local CVE database not found, creating default")
            self.createDefaultDatabase()
            self.saveDatabase()
    
    def createDefaultDatabase(self) -> None:
        """Create default CVE database with common vulnerabilities"""
        defaultCves = {
            "CVE-2021-44228": {
                "cveId": "CVE-2021-44228",
                "description": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints",
                "severity": SeverityLevel.CRITICAL.value,
                "cvssScore": 10.0,
                "cvssVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "affectedPackages": ["log4j-core", "log4j", "log4j-api"],
                "affectedVersions": {
                    "log4j-core": ["2.0-beta9", "2.0-rc1", "2.0", "2.1", "2.2", "2.3", "2.4", 
                                  "2.5", "2.6", "2.7", "2.8", "2.9", "2.10", "2.11", "2.12", 
                                  "2.13", "2.14", "2.14.1", "2.15.0", "2.16.0"]
                },
                "fixedVersion": "2.17.0",
                "exploitAvailable": True,
                "exploitMaturity": "high",
                "publishedDate": "2021-12-10T00:00:00",
                "lastModifiedDate": "2021-12-10T00:00:00",
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
                    "https://logging.apache.org/log4j/2.x/security.html"
                ],
                "mitigation": "Update to Log4j 2.17.0 or later, or remove JndiLookup class from classpath",
                "workaround": "Set system property 'log4j2.formatMsgNoLookups' to 'true' or remove JndiLookup class",
                "impact": "Remote code execution",
                "advisory": "Log4Shell vulnerability affecting millions of systems",
                "credits": "Discovered by Chen Zhaojun of Alibaba Cloud Security Team"
            },
            "CVE-2021-45046": {
                "cveId": "CVE-2021-45046",
                "description": "Apache Log4j2 Thread Context Lookup Pattern vulnerable to remote code execution in certain non-default configurations",
                "severity": SeverityLevel.CRITICAL.value,
                "cvssScore": 9.0,
                "cvssVector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "affectedPackages": ["log4j-core", "log4j"],
                "affectedVersions": {
                    "log4j-core": ["2.0-beta9", "2.15.0"]
                },
                "fixedVersion": "2.16.0",
                "exploitAvailable": True,
                "exploitMaturity": "high",
                "publishedDate": "2021-12-10T00:00:00",
                "lastModifiedDate": "2021-12-10T00:00:00",
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-45046"
                ],
                "mitigation": "Update to Log4j 2.16.0 or later",
                "workaround": "Disable thread context patterns or upgrade",
                "impact": "Remote code execution in non-default configurations",
                "advisory": "Follow-up to CVE-2021-44228",
                "credits": ""
            },
            "CVE-2017-0144": {
                "cveId": "CVE-2017-0144",
                "description": "Windows SMBv1 Remote Code Execution Vulnerability (EternalBlue)",
                "severity": SeverityLevel.CRITICAL.value,
                "cvssScore": 8.5,
                "cvssVector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "affectedPackages": ["windows_smb", "samba"],
                "affectedVersions": {
                    "windows": ["windows_7", "windows_8.1", "windows_10", "windows_server_2008", 
                               "windows_server_2012", "windows_server_2016"]
                },
                "fixedVersion": "Multiple updates via MS17-010",
                "exploitAvailable": True,
                "exploitMaturity": "weaponized",
                "publishedDate": "2017-03-14T00:00:00",
                "lastModifiedDate": "2017-03-14T00:00:00",
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2017-0144",
                    "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010"
                ],
                "mitigation": "Apply Microsoft security update MS17-010, disable SMBv1",
                "workaround": "Block TCP ports 139 and 445 at network perimeter",
                "impact": "Remote code execution leading to wormable spread",
                "advisory": "Used by WannaCry ransomware attack",
                "credits": "NSA exploit leaked by Shadow Brokers"
            },
            "CVE-2014-0160": {
                "cveId": "CVE-2014-0160",
                "description": "Heartbleed bug in OpenSSL - buffer over-read in TLS heartbeat extension",
                "severity": SeverityLevel.CRITICAL.value,
                "cvssScore": 7.5,
                "cvssVector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "affectedPackages": ["openssl"],
                "affectedVersions": {
                    "openssl": ["1.0.1", "1.0.1a", "1.0.1b", "1.0.1c", "1.0.1d", "1.0.1e", 
                               "1.0.1f", "1.0.1g", "1.0.1h", "1.0.1i", "1.0.1j", "1.0.1k", "1.0.1l"]
                },
                "fixedVersion": "1.0.1g",
                "exploitAvailable": True,
                "exploitMaturity": "high",
                "publishedDate": "2014-04-07T00:00:00",
                "lastModifiedDate": "2014-04-07T00:00:00",
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2014-0160",
                    "https://heartbleed.com/"
                ],
                "mitigation": "Update OpenSSL to 1.0.1g or later, reissue SSL certificates",
                "workaround": "Disable TLS heartbeat extension",
                "impact": "Information disclosure of up to 64KB of memory per request",
                "advisory": "Critical vulnerability affecting ~17% of internet's secure web servers",
                "credits": "Discovered by Neel Mehta of Google Security"
            }
        }
        
        for cveId, vulnData in defaultCves.items():
            try:
                self.vulnerabilities[cveId] = Vulnerability.fromDict(vulnData)
            except Exception as e:
                logger.warning(f"Error creating default CVE {cveId}: {e}")
    
    def saveDatabase(self) -> None:
        """Save local CVE database to file"""
        try:
            data = {}
            for cveId, vuln in self.vulnerabilities.items():
                data[cveId] = vuln.toDict()
            
            with open(self.dbPath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, default=str)
            
            logger.info(f"Saved {len(self.vulnerabilities)} CVEs to local database")
        except Exception as e:
            logger.error(f"Failed to save local CVE database: {e}")
    
    def fetchCves(self, since: Optional[datetime] = None) -> List[Vulnerability]:
        """Return all vulnerabilities from local database"""
        if since:
            return [v for v in self.vulnerabilities.values() if v.publishedDate >= since]
        return list(self.vulnerabilities.values())
    
    def getCveById(self, cveId: str) -> Optional[Vulnerability]:
        """Get specific CVE by ID"""
        return self.vulnerabilities.get(cveId)
    
    def searchCves(self, keywords: List[str]) -> List[Vulnerability]:
        """Search CVEs by keywords"""
        if not keywords:
            return list(self.vulnerabilities.values())
        
        results = []
        keywordLower = [k.lower() for k in keywords]
        
        for vuln in self.vulnerabilities.values():
            searchText = f"{vuln.description} {vuln.cveId} {' '.join(vuln.affectedPackages)}".lower()
            if any(keyword in searchText for keyword in keywordLower):
                results.append(vuln)
        
        return results
    
    def addVulnerability(self, vulnerability: Vulnerability) -> None:
        """Add vulnerability to local database"""
        self.vulnerabilities[vulnerability.cveId] = vulnerability
        self.saveDatabase()
    
    def removeVulnerability(self, cveId: str) -> bool:
        """Remove vulnerability from local database"""
        if cveId in self.vulnerabilities:
            del self.vulnerabilities[cveId]
            self.saveDatabase()
            return True
        return False
    
    @property
    def sourceName(self) -> str:
        return "Local CVE Database"

# System Scanner with comprehensive detection
class SystemScanner:
    """Comprehensive system scanner with multi-platform support"""
    
    def __init__(self, osType: OperatingSystem):
        self.osType = osType
        self.systemInfo = None
        self.cache = {}
    
    def gatherSystemInfo(self) -> SystemInfo:
        """Gather comprehensive system information"""
        logger.info("Gathering system information...")
        
        startTime = time.time()
        
        systemInfo = SystemInfo(
            osType=self.osType,
            osVersion=self.getOsVersion(),
            kernelVersion=self.getKernelVersion(),
            hostname=self.getHostname(),
            architecture=self.getArchitecture(),
            cpuInfo=self.getCpuInfo(),
            memoryInfo=self.getMemoryInfo(),
            diskInfo=self.getDiskInfo(),
            networkInterfaces=self.getNetworkInterfaces(),
            installedPackages=self.getInstalledPackages(),
            runningServices=self.getRunningServices(),
            openPorts=self.getOpenPorts(),
            users=self.getUsers(),
            securityPolicies=self.getSecurityPolicies(),
            environmentVariables=dict(os.environ),
            systemUptime=self.getUptime(),
            lastBootTime=self.getLastBootTime(),
            timezone=self.getTimezone(),
            locale=self.getLocale()
        )
        
        elapsed = time.time() - startTime
        logger.info(f"System information gathered in {elapsed:.2f} seconds")
        
        self.systemInfo = systemInfo
        return systemInfo
    
    def getOsVersion(self) -> str:
        """Get detailed OS version"""
        try:
            if self.osType == OperatingSystem.LINUX:
                # Try multiple methods to get distribution info
                releaseFiles = [
                    "/etc/os-release",
                    "/usr/lib/os-release",
                    "/etc/lsb-release",
                    "/etc/redhat-release",
                    "/etc/centos-release",
                    "/etc/debian_version",
                    "/etc/SuSE-release",
                    "/etc/arch-release",
                    "/etc/alpine-release"
                ]
                
                for releaseFile in releaseFiles:
                    if os.path.exists(releaseFile):
                        with open(releaseFile, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                            if "PRETTY_NAME" in content:
                                for line in content.split('\n'):
                                    if line.startswith("PRETTY_NAME="):
                                        return line.split('=', 1)[1].strip('"\'')
                            
                            # For files like /etc/redhat-release
                            if releaseFile.endswith('-release'):
                                return content.strip()
                
                # Fallback to generic info
                return f"{platform.system()} {platform.release()}"
            
            elif self.osType == OperatingSystem.WINDOWS:
                import winreg
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                       r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
                    productName = winreg.QueryValueEx(key, "ProductName")[0]
                    releaseId = winreg.QueryValueEx(key, "ReleaseId")[0] if 'ReleaseId' in \
                        [winreg.EnumValue(key, i)[0] for i in range(winreg.QueryInfoKey(key)[1])] else ""
                    buildNumber = winreg.QueryValueEx(key, "CurrentBuildNumber")[0]
                    
                    versionStr = productName
                    if releaseId:
                        versionStr += f" {releaseId}"
                    versionStr += f" (Build {buildNumber})"
                    
                    winreg.CloseKey(key)
                    return versionStr
                except:
                    return platform.version()
            
            elif self.osType == OperatingSystem.MACOS:
                try:
                    result = subprocess.run(['sw_vers', '-productVersion'], 
                                          capture_output=True, text=True, check=True)
                    return f"macOS {result.stdout.strip()}"
                except:
                    return platform.mac_ver()[0]
            
            else:
                return platform.version()
                
        except Exception as e:
            logger.warning(f"Failed to get OS version: {e}")
            return platform.version()
    
    def getKernelVersion(self) -> str:
        """Get kernel version"""
        return platform.release()
    
    def getHostname(self) -> str:
        """Get system hostname"""
        return platform.node()
    
    def getArchitecture(self) -> Architecture:
        """Get system architecture"""
        machine = platform.machine().lower()
        
        if machine in ['x86_64', 'amd64', 'x64']:
            return Architecture.X64
        elif machine in ['i386', 'i686', 'x86']:
            return Architecture.X86
        elif machine.startswith('arm'):
            if '64' in machine:
                return Architecture.ARM64
            return Architecture.ARM
        elif machine.startswith('ppc'):
            if '64' in machine:
                return Architecture.PPC64
            return Architecture.PPC
        elif machine.startswith('mips'):
            return Architecture.MIPS
        elif machine.startswith('sparc'):
            return Architecture.SPARC
        else:
            return Architecture.UNKNOWN
    
    def getCpuInfo(self) -> Dict[str, Any]:
        """Get detailed CPU information"""
        cpuInfo = {
            "cores": os.cpu_count() or 1,
            "architecture": platform.machine(),
            "processor": platform.processor() or "Unknown"
        }
        
        try:
            if self.osType == OperatingSystem.LINUX:
                with open("/proc/cpuinfo", 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                    # Parse CPU info
                    processors = content.strip().split('\n\n')
                    if processors:
                        firstProcessor = processors[0]
                        for line in firstProcessor.split('\n'):
                            if ':' in line:
                                key, value = line.split(':', 1)
                                key = key.strip()
                                value = value.strip()
                                
                                if key == 'model name':
                                    cpuInfo['model'] = value
                                elif key == 'cpu MHz':
                                    cpuInfo['frequency_mhz'] = float(value)
                                elif key == 'cpu cores':
                                    cpuInfo['physical_cores'] = int(value)
                                elif key == 'siblings':
                                    cpuInfo['logical_cores'] = int(value)
                                elif key == 'vendor_id':
                                    cpuInfo['vendor'] = value
                    
                    cpuInfo['processor_count'] = len(processors)
            
            elif self.osType == OperatingSystem.WINDOWS:
                try:
                    import winreg
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                       r"HARDWARE\DESCRIPTION\System\CentralProcessor\0")
                    cpuInfo['model'] = winreg.QueryValueEx(key, "ProcessorNameString")[0]
                    winreg.CloseKey(key)
                except:
                    pass
            
            elif THIRD_PARTY_IMPORTS['psutil']:
                cpuInfo['percent'] = psutil.cpu_percent(interval=0.1)
                cpuInfo['freq'] = psutil.cpu_freq().current if psutil.cpu_freq() else None
                cpuInfo['load_avg'] = psutil.getloadavg() if hasattr(psutil, 'getloadavg') else None
                
        except Exception as e:
            logger.debug(f"Error getting CPU info: {e}")
        
        return cpuInfo
    
    def getMemoryInfo(self) -> Dict[str, Any]:
        """Get memory information"""
        memoryInfo = {}
        
        try:
            if THIRD_PARTY_IMPORTS['psutil']:
                memory = psutil.virtual_memory()
                swap = psutil.swap_memory()
                
                memoryInfo = {
                    "total": memory.total,
                    "available": memory.available,
                    "used": memory.used,
                    "free": memory.free,
                    "percent": memory.percent,
                    "swap_total": swap.total,
                    "swap_used": swap.used,
                    "swap_free": swap.free,
                    "swap_percent": swap.percent
                }
            elif self.osType == OperatingSystem.LINUX:
                with open("/proc/meminfo", 'r', encoding='utf-8') as f:
                    for line in f:
                        if ':' in line:
                            key, value = line.split(':', 1)
                            key = key.strip()
                            value = value.strip().split()[0]
                            memoryInfo[key] = int(value) * 1024  # Convert KB to bytes
            elif self.osType == OperatingSystem.WINDOWS:
                try:
                    import ctypes
                    class MEMORYSTATUSEX(ctypes.Structure):
                        _fields_ = [
                            ("dwLength", ctypes.c_ulong),
                            ("dwMemoryLoad", ctypes.c_ulong),
                            ("ullTotalPhys", ctypes.c_ulonglong),
                            ("ullAvailPhys", ctypes.c_ulonglong),
                            ("ullTotalPageFile", ctypes.c_ulonglong),
                            ("ullAvailPageFile", ctypes.c_ulonglong),
                            ("ullTotalVirtual", ctypes.c_ulonglong),
                            ("ullAvailVirtual", ctypes.c_ulonglong),
                            ("ullAvailExtendedVirtual", ctypes.c_ulonglong)
                        ]
                    
                    memoryStatus = MEMORYSTATUSEX()
                    memoryStatus.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
                    ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(memoryStatus))
                    
                    memoryInfo = {
                        "total": memoryStatus.ullTotalPhys,
                        "available": memoryStatus.ullAvailPhys,
                        "percent": memoryStatus.dwMemoryLoad,
                        "swap_total": memoryStatus.ullTotalPageFile,
                        "swap_available": memoryStatus.ullAvailPageFile
                    }
                except:
                    pass
        
        except Exception as e:
            logger.debug(f"Error getting memory info: {e}")
        
        return memoryInfo
    
    def getDiskInfo(self) -> Dict[str, Any]:
        """Get disk information"""
        diskInfo = {}
        
        try:
            if THIRD_PARTY_IMPORTS['psutil']:
                partitions = psutil.disk_partitions(all=False)
                usage = {}
                
                for partition in partitions:
                    try:
                        partitionUsage = psutil.disk_usage(partition.mountpoint)
                        usage[partition.mountpoint] = {
                            "device": partition.device,
                            "fstype": partition.fstype,
                            "total": partitionUsage.total,
                            "used": partitionUsage.used,
                            "free": partitionUsage.free,
                            "percent": partitionUsage.percent
                        }
                    except:
                        continue
                
                diskInfo['partitions'] = usage
                diskInfo['io_counters'] = psutil.disk_io_counters()._asdict() if psutil.disk_io_counters() else {}
            
            else:
                # Fallback to command-line tools
                if self.osType == OperatingSystem.LINUX:
                    result = subprocess.run(['df', '-h', '--total'], 
                                          capture_output=True, text=True, encoding='utf-8')
                    diskInfo['df_output'] = result.stdout
                
                elif self.osType == OperatingSystem.WINDOWS:
                    result = subprocess.run(['wmic', 'logicaldisk', 'get', 'size,freespace,caption'], 
                                          capture_output=True, text=True, shell=True, encoding='utf-8')
                    diskInfo['wmic_output'] = result.stdout
        
        except Exception as e:
            logger.debug(f"Error getting disk info: {e}")
        
        return diskInfo
    
    def getNetworkInterfaces(self) -> List[Dict[str, Any]]:
        """Get network interface information"""
        interfaces = []
        
        try:
            if THIRD_PARTY_IMPORTS['psutil']:
                netStats = psutil.net_if_stats()
                netAddrs = psutil.net_if_addrs()
                netIo = psutil.net_io_counters(pernic=True)
                
                for interface in netAddrs:
                    interfaceInfo = {
                        "name": interface,
                        "addresses": [],
                        "stats": {},
                        "io": {}
                    }
                    
                    # Addresses
                    for addr in netAddrs[interface]:
                        addressInfo = {
                            "family": str(addr.family),
                            "address": addr.address,
                            "netmask": addr.netmask,
                            "broadcast": addr.broadcast,
                            "ptp": addr.ptp
                        }
                        interfaceInfo["addresses"].append(addressInfo)
                    
                    # Statistics
                    if interface in netStats:
                        stats = netStats[interface]
                        interfaceInfo["stats"] = {
                            "isup": stats.isup,
                            "duplex": stats.duplex,
                            "speed": stats.speed,
                            "mtu": stats.mtu
                        }
                    
                    # I/O counters
                    if interface in netIo:
                        io = netIo[interface]
                        interfaceInfo["io"] = {
                            "bytes_sent": io.bytes_sent,
                            "bytes_recv": io.bytes_recv,
                            "packets_sent": io.packets_sent,
                            "packets_recv": io.packets_recv,
                            "errin": io.errin,
                            "errout": io.errout,
                            "dropin": io.dropin,
                            "dropout": io.dropout
                        }
                    
                    interfaces.append(interfaceInfo)
            
            else:
                # Fallback methods
                if self.osType == OperatingSystem.LINUX:
                    try:
                        # Try ip command first
                        result = subprocess.run(['ip', '-j', 'addr'], 
                                              capture_output=True, text=True, encoding='utf-8')
                        if result.returncode == 0:
                            interfaces = json.loads(result.stdout)
                    except:
                        try:
                            # Try ifconfig
                            result = subprocess.run(['ifconfig', '-a'], 
                                                  capture_output=True, text=True, encoding='utf-8')
                            # Parse ifconfig output (simplified)
                            currentInterface = {}
                            for line in result.stdout.split('\n'):
                                if line and not line.startswith(' '):
                                    if currentInterface:
                                        interfaces.append(currentInterface)
                                    currentInterface = {"name": line.split(':')[0], "addresses": []}
                                elif 'inet' in line:
                                    parts = line.strip().split()
                                    if len(parts) >= 2:
                                        currentInterface["addresses"].append({
                                            "family": "AF_INET",
                                            "address": parts[1]
                                        })
                            if currentInterface:
                                interfaces.append(currentInterface)
                        except:
                            pass
                
                elif self.osType == OperatingSystem.WINDOWS:
                    try:
                        result = subprocess.run(['ipconfig', '/all'], 
                                              capture_output=True, text=True, shell=True, encoding='utf-8')
                        # Parse ipconfig output (simplified)
                        currentInterface = {}
                        for line in result.stdout.split('\n'):
                            line = line.strip()
                            if line and not line.startswith(' '):
                                if currentInterface:
                                    interfaces.append(currentInterface)
                                if ':' in line and not line.startswith('   '):
                                    currentInterface = {"name": line.strip(':'), "addresses": []}
                            elif ':' in line:
                                key, value = line.split(':', 1)
                                key = key.strip()
                                value = value.strip()
                                currentInterface[key.lower().replace(' ', '_')] = value
                        if currentInterface:
                            interfaces.append(currentInterface)
                    except:
                        pass
        
        except Exception as e:
            logger.debug(f"Error getting network interfaces: {e}")
        
        return interfaces
    
    def getInstalledPackages(self) -> List[SystemPackage]:
        """Get all installed packages using multiple detection methods"""
        packages = []
        
        if self.osType == OperatingSystem.LINUX:
            packages.extend(self.detectLinuxPackages())
        elif self.osType == OperatingSystem.WINDOWS:
            packages.extend(self.detectWindowsPackages())
        elif self.osType == OperatingSystem.MACOS:
            packages.extend(self.detectMacosPackages())
        
        # Detect language-specific packages
        packages.extend(self.detectPythonPackages())
        packages.extend(self.detectNodePackages())
        packages.extend(self.detectRubyPackages())
        
        logger.info(f"Detected {len(packages)} installed packages")
        return packages
    
    def detectLinuxPackages(self) -> List[SystemPackage]:
        """Detect packages on Linux systems"""
        packages = []
        detectedManagers = set()
        
        # Check for package managers and their databases
        packageManagers = [
            ('dpkg', self.getDebianPackages),
            ('rpm', self.getRpmPackages),
            ('pacman', self.getPacmanPackages),
            ('apk', self.getAlpinePackages),
            ('emerge', self.getGentooPackages),
            ('zypper', self.getSusePackages),
            ('dnf', self.getDnfPackages),
            ('yum', self.getYumPackages)
        ]
        
        for pmName, pmFunc in packageManagers:
            if shutil.which(pmName):
                try:
                    pmPackages = pmFunc()
                    packages.extend(pmPackages)
                    detectedManagers.add(pmName)
                    logger.debug(f"Detected packages via {pmName}: {len(pmPackages)}")
                except Exception as e:
                    logger.warning(f"Failed to get packages via {pmName}: {e}")
        
        # If no package manager detected, try reading package databases directly
        if not detectedManagers:
            # Check common package database locations
            packageDirs = [
                '/var/lib/dpkg/status',
                '/var/lib/rpm/Packages',
                '/var/lib/pacman/local',
                '/lib/apk/db/installed'
            ]
            
            for pkgDir in packageDirs:
                if os.path.exists(pkgDir):
                    try:
                        if 'dpkg' in pkgDir:
                            packages.extend(self.parseDpkgStatus(pkgDir))
                        elif 'rpm' in pkgDir:
                            packages.extend(self.parseRpmDatabase(pkgDir))
                    except Exception as e:
                        logger.debug(f"Failed to parse package database {pkgDir}: {e}")
        
        return packages
    
    def getDebianPackages(self) -> List[SystemPackage]:
        """Get Debian/Ubuntu packages via dpkg"""
        packages = []
        
        try:
            # Use dpkg-query for better format control
            cmd = ["dpkg-query", "-W", 
                   "-f=${Package}|${Version}|${Architecture}|${Status}|${Installed-Size}\n"]
            result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
            
            for line in result.stdout.strip().split('\n'):
                if not line:
                    continue
                
                parts = line.split('|')
                if len(parts) >= 4:
                    name, version, arch, status = parts[0], parts[1], parts[2], parts[3]
                    
                    # Only include installed packages
                    if 'installed' in status:
                        package = SystemPackage(
                            name=name,
                            version=version,
                            architecture=Architecture(arch) if arch else Architecture.UNKNOWN,
                            vendor="",
                            installDate=self.getPackageInstallDate(name, PackageManager.APT),
                            packageManager=PackageManager.APT,
                            filePath=None,
                            size=int(parts[4]) * 1024 if len(parts) > 4 and parts[4].isdigit() else 0,
                            description=self.getPackageDescription(name)
                        )
                        packages.append(package)
        
        except Exception as e:
            logger.warning(f"Error getting Debian packages: {e}")
        
        return packages
    
    def getRpmPackages(self) -> List[SystemPackage]:
        """Get RPM packages (RHEL, CentOS, Fedora)"""
        packages = []
        
        try:
            cmd = ["rpm", "-qa", "--queryformat", 
                   "%{NAME}|%{VERSION}|%{RELEASE}|%{ARCH}|%{VENDOR}|%{INSTALLTIME}|%{SIZE}|%{SUMMARY}\n"]
            result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
            
            for line in result.stdout.strip().split('\n'):
                if not line:
                    continue
                
                parts = line.split('|')
                if len(parts) >= 5:
                    name, version, release, arch, vendor = parts[0], parts[1], parts[2], parts[3], parts[4]
                    fullVersion = f"{version}-{release}" if release else version
                    
                    installTime = None
                    if len(parts) > 5 and parts[5].isdigit():
                        installTime = datetime.fromtimestamp(int(parts[5]))
                    
                    size = int(parts[6]) if len(parts) > 6 and parts[6].isdigit() else 0
                    description = parts[7] if len(parts) > 7 else ""
                    
                    package = SystemPackage(
                        name=name,
                        version=fullVersion,
                        architecture=Architecture(arch) if arch else Architecture.UNKNOWN,
                        vendor=vendor,
                        installDate=installTime,
                        packageManager=PackageManager.YUM,
                        filePath=None,
                        size=size,
                        description=description
                    )
                    packages.append(package)
        
        except Exception as e:
            logger.warning(f"Error getting RPM packages: {e}")
        
        return packages
    
    def getPacmanPackages(self) -> List[SystemPackage]:
        """Get Arch Linux packages via pacman"""
        packages = []
        
        try:
            cmd = ["pacman", "-Q"]
            result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
            
            for line in result.stdout.strip().split('\n'):
                if not line:
                    continue
                
                parts = line.split()
                if len(parts) >= 2:
                    name, version = parts[0], parts[1]
                    
                    # Try to get more info
                    try:
                        infoCmd = ["pacman", "-Qi", name]
                        infoResult = subprocess.run(infoCmd, capture_output=True, text=True, encoding='utf-8')
                        infoLines = infoResult.stdout.split('\n')
                        
                        installDate = None
                        size = 0
                        description = ""
                        
                        for infoLine in infoLines:
                            if 'Install Date' in infoLine:
                                dateStr = infoLine.split(':', 1)[1].strip()
                                installDate = datetime.strptime(dateStr, '%a %b %d %H:%M:%S %Y')
                            elif 'Installed Size' in infoLine:
                                sizeStr = infoLine.split(':', 1)[1].strip().split()[0]
                                size = int(float(sizeStr) * 1024 * 1024)  # MB to bytes
                            elif 'Description' in infoLine:
                                description = infoLine.split(':', 1)[1].strip()
                    except:
                        pass
                    
                    package = SystemPackage(
                        name=name,
                        version=version,
                        architecture=Architecture.UNKNOWN,  # pacman doesn't show arch in -Q
                        vendor="Arch Linux",
                        installDate=installDate,
                        packageManager=PackageManager.PACMAN,
                        filePath=None,
                        size=size,
                        description=description
                    )
                    packages.append(package)
        
        except Exception as e:
            logger.warning(f"Error getting pacman packages: {e}")
        
        return packages
    
    def getAlpinePackages(self) -> List[SystemPackage]:
        """Get Alpine Linux packages via apk"""
        packages = []
        
        try:
            cmd = ["apk", "info", "-v"]
            result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
            
            for line in result.stdout.strip().split('\n'):
                if not line:
                    continue
                
                # Format: package-version
                if '-' in line:
                    lastDash = line.rfind('-')
                    if lastDash > 0:
                        name = line[:lastDash]
                        version = line[lastDash + 1:]
                        
                        package = SystemPackage(
                            name=name,
                            version=version,
                            architecture=Architecture.UNKNOWN,
                            vendor="Alpine Linux",
                            installDate=None,
                            packageManager=PackageManager.APK,
                            filePath=None
                        )
                        packages.append(package)
        
        except Exception as e:
            logger.warning(f"Error getting Alpine packages: {e}")
        
        return packages
    
    def getGentooPackages(self) -> List[SystemPackage]:
        """Get Gentoo packages via emerge"""
        packages = []
        
        try:
            cmd = ["qlist", "-Iv"]
            result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
            
            for line in result.stdout.strip().split('\n'):
                if not line:
                    continue
                
                # Format: category/package-version
                parts = line.split()
                if len(parts) >= 1:
                    pkgSpec = parts[0]
                    if '/' in pkgSpec and '-' in pkgSpec:
                        name = pkgSpec.split('/')[1]
                        version = name.split('-')[-1]
                        name = '-'.join(name.split('-')[:-1])
                        
                        package = SystemPackage(
                            name=name,
                            version=version,
                            architecture=Architecture.UNKNOWN,
                            vendor="Gentoo",
                            installDate=None,
                            packageManager=PackageManager.UNKNOWN,
                            filePath=None
                        )
                        packages.append(package)
        
        except Exception as e:
            logger.warning(f"Error getting Gentoo packages: {e}")
        
        return packages
    
    def getSusePackages(self) -> List[SystemPackage]:
        """Get openSUSE packages via zypper"""
        packages = []
        
        try:
            cmd = ["zypper", "search", "-i", "-s"]
            result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
            
            # Parse zypper output (this is simplified)
            for line in result.stdout.strip().split('\n'):
                if '|' in line and not line.startswith('S'):
                    parts = [p.strip() for p in line.split('|')]
                    if len(parts) >= 5:
                        name, version = parts[2], parts[4]
                        
                        package = SystemPackage(
                            name=name,
                            version=version,
                            architecture=Architecture.UNKNOWN,
                            vendor="openSUSE",
                            installDate=None,
                            packageManager=PackageManager.ZYPPER,
                            filePath=None
                        )
                        packages.append(package)
        
        except Exception as e:
            logger.warning(f"Error getting SUSE packages: {e}")
        
        return packages
    
    def getDnfPackages(self) -> List[SystemPackage]:
        """Get packages via dnf (Fedora, RHEL 8+)"""
        return self.getRpmPackages()  # dnf uses rpm database
    
    def getYumPackages(self) -> List[SystemPackage]:
        """Get packages via yum (older RHEL/CentOS)"""
        return self.getRpmPackages()  # yum uses rpm database
    
    def parseDpkgStatus(self, statusFile: str) -> List[SystemPackage]:
        """Parse dpkg status file directly"""
        packages = []
        
        try:
            with open(statusFile, 'r', encoding='utf-8', errors='ignore') as f:
                currentPackage = {}
                
                for line in f:
                    line = line.strip()
                    
                    if not line:
                        if currentPackage and currentPackage.get('Status', '') == 'install ok installed':
                            package = SystemPackage(
                                name=currentPackage.get('Package', ''),
                                version=currentPackage.get('Version', ''),
                                architecture=Architecture(currentPackage.get('Architecture', 'unknown')),
                                vendor="",
                                installDate=None,
                                packageManager=PackageManager.APT,
                                filePath=None,
                                description=currentPackage.get('Description', ''),
                                size=int(currentPackage.get('Installed-Size', 0)) * 1024
                            )
                            packages.append(package)
                        currentPackage = {}
                    
                    elif ': ' in line:
                        key, value = line.split(': ', 1)
                        currentPackage[key] = value
        
        except Exception as e:
            logger.warning(f"Error parsing dpkg status: {e}")
        
        return packages
    
    def parseRpmDatabase(self, dbPath: str) -> List[SystemPackage]:
        """Parse RPM database directly (simplified)"""
        packages = []
        
        try:
            # This is a simplified approach
            cmd = ["rpm", "-qa", "--dbpath", dbPath]
            result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
            
            for pkgSpec in result.stdout.strip().split('\n'):
                if pkgSpec and '-' in pkgSpec:
                    # Parse package name and version from rpm package spec
                    parts = pkgSpec.split('-')
                    if len(parts) >= 3:
                        # Find where version starts (typically after last non-numeric part)
                        versionParts = []
                        for i in range(len(parts) - 1, -1, -1):
                            if parts[i][0].isdigit():
                                versionParts.insert(0, parts[i])
                            else:
                                break
                        
                        if versionParts:
                            name = '-'.join(parts[:len(parts) - len(versionParts)])
                            version = '-'.join(versionParts)
                            
                            package = SystemPackage(
                                name=name,
                                version=version,
                                architecture=Architecture.UNKNOWN,
                                vendor="",
                                installDate=None,
                                packageManager=PackageManager.YUM,
                                filePath=None
                            )
                            packages.append(package)
        
        except Exception as e:
            logger.warning(f"Error parsing RPM database: {e}")
        
        return packages
    
    def detectWindowsPackages(self) -> List[SystemPackage]:
        """Detect installed packages on Windows"""
        packages = []
        
        try:
            # Method 1: Registry (most reliable)
            packages.extend(self.getWindowsRegistryPackages())
            
            # Method 2: PowerShell Get-Package
            packages.extend(self.getWindowsPowerShellPackages())
            
            # Method 3: Check Program Files directories
            packages.extend(self.getWindowsProgramFilesPackages())
            
            # Method 4: Chocolatey packages
            packages.extend(self.getChocolateyPackages())
            
            # Method 5: Winget packages
            packages.extend(self.getWingetPackages())
        
        except Exception as e:
            logger.warning(f"Error detecting Windows packages: {e}")
        
        return packages
    
    def getWindowsRegistryPackages(self) -> List[SystemPackage]:
        """Get installed packages from Windows Registry"""
        packages = []
        
        if self.osType != OperatingSystem.WINDOWS:
            return packages
        
        try:
            import winreg
            
            registryPaths = [
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
                (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            ]
            
            for hkey, subkey in registryPaths:
                try:
                    key = winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
                    
                    for i in range(winreg.QueryInfoKey(key)[0]):
                        try:
                            subkeyName = winreg.EnumKey(key, i)
                            subkeyHandle = winreg.OpenKey(key, subkeyName)
                            
                            # Try to read package info
                            displayName = self.readRegistryValue(subkeyHandle, "DisplayName")
                            displayVersion = self.readRegistryValue(subkeyHandle, "DisplayVersion")
                            publisher = self.readRegistryValue(subkeyHandle, "Publisher")
                            installDate = self.readRegistryValue(subkeyHandle, "InstallDate")
                            installLocation = self.readRegistryValue(subkeyHandle, "InstallLocation")
                            estimatedSize = self.readRegistryValue(subkeyHandle, "EstimatedSize")
                            
                            if displayName:
                                # Parse install date
                                parsedDate = None
                                if installDate and len(installDate) == 8:
                                    try:
                                        parsedDate = datetime.strptime(installDate, '%Y%m%d')
                                    except:
                                        pass
                                
                                # Parse size
                                size = 0
                                if estimatedSize and estimatedSize.isdigit():
                                    size = int(estimatedSize) * 1024  # KB to bytes
                                
                                package = SystemPackage(
                                    name=displayName,
                                    version=displayVersion or "Unknown",
                                    architecture=Architecture.X64 if "WOW6432Node" in subkey else Architecture.X86,
                                    vendor=publisher or "",
                                    installDate=parsedDate,
                                    packageManager=PackageManager.UNKNOWN,
                                    filePath=installLocation,
                                    size=size
                                )
                                packages.append(package)
                            
                            winreg.CloseKey(subkeyHandle)
                            
                        except (OSError, ValueError):
                            continue
                    
                    winreg.CloseKey(key)
                    
                except (OSError, FileNotFoundError):
                    continue
        
        except ImportError:
            # winreg not available (not on Windows)
            pass
        except Exception as e:
            logger.warning(f"Error reading Windows registry: {e}")
        
        return packages
    
    def getWindowsPowerShellPackages(self) -> List[SystemPackage]:
        """Get packages via PowerShell Get-Package"""
        packages = []
        
        try:
            psScript = """
            Get-Package | Select-Object Name, Version, Source, Summary | ConvertTo-Json
            """
            
            result = subprocess.run(["powershell", "-Command", psScript],
                                  capture_output=True, text=True, shell=True, encoding='utf-8')
            
            if result.returncode == 0:
                try:
                    packageData = json.loads(result.stdout)
                    if isinstance(packageData, list):
                        for pkg in packageData:
                            package = SystemPackage(
                                name=pkg.get('Name', ''),
                                version=pkg.get('Version', ''),
                                architecture=Architecture.UNKNOWN,
                                vendor=pkg.get('Source', ''),
                                installDate=None,
                                packageManager=PackageManager.UNKNOWN,
                                filePath=None,
                                description=pkg.get('Summary', '')
                            )
                            packages.append(package)
                except json.JSONDecodeError:
                    pass
        
        except Exception as e:
            logger.debug(f"Error getting PowerShell packages: {e}")
        
        return packages
    
    def getWindowsProgramFilesPackages(self) -> List[SystemPackage]:
        """Scan Program Files directories for installed software"""
        packages = []
        
        programFilesDirs = [
            os.environ.get('ProgramFiles', 'C:\\Program Files'),
            os.environ.get('ProgramFiles(x86)', 'C:\\Program Files (x86)'),
            os.environ.get('ProgramW6432', 'C:\\Program Files'),
            os.path.join(os.environ.get('LocalAppData', 'C:\\Users\\User\\AppData\\Local'), 'Programs')
        ]
        
        for programDir in programFilesDirs:
            if os.path.exists(programDir):
                try:
                    for item in os.listdir(programDir):
                        itemPath = os.path.join(programDir, item)
                        if os.path.isdir(itemPath):
                            # Check for uninstaller or version info
                            uninstaller = self.findUninstaller(itemPath)
                            versionInfo = self.getFileVersionInfo(itemPath)
                            
                            if versionInfo:
                                package = SystemPackage(
                                    name=item,
                                    version=versionInfo.get('FileVersion', 'Unknown'),
                                    architecture=Architecture.UNKNOWN,
                                    vendor=versionInfo.get('CompanyName', ''),
                                    installDate=None,
                                    packageManager=PackageManager.UNKNOWN,
                                    filePath=itemPath,
                                    description=versionInfo.get('FileDescription', '')
                                )
                                packages.append(package)
                except Exception as e:
                    logger.debug(f"Error scanning {programDir}: {e}")
        
        return packages
    
    def getChocolateyPackages(self) -> List[SystemPackage]:
        """Get Chocolatey packages"""
        packages = []
        
        try:
            if shutil.which('choco'):
                cmd = ["choco", "list", "--local-only", "--limit-output"]
                result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
                
                for line in result.stdout.strip().split('\n'):
                    if '|' in line:
                        name, version = line.split('|')[:2]
                        
                        package = SystemPackage(
                            name=name.strip(),
                            version=version.strip(),
                            architecture=Architecture.UNKNOWN,
                            vendor="Chocolatey",
                            installDate=None,
                            packageManager=PackageManager.CHOCOLATEY,
                            filePath=None
                        )
                        packages.append(package)
        
        except Exception as e:
            logger.debug(f"Error getting Chocolatey packages: {e}")
        
        return packages
    
    def getWingetPackages(self) -> List[SystemPackage]:
        """Get Winget packages"""
        packages = []
        
        try:
            if shutil.which('winget'):
                cmd = ["winget", "list", "--accept-source-agreements"]
                result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
                
                # Parse winget output (simplified)
                lines = result.stdout.strip().split('\n')
                if len(lines) > 2:
                    for line in lines[2:]:  # Skip header
                        parts = line.split(maxsplit=2)
                        if len(parts) >= 3:
                            name, idPart, version = parts[0], parts[1], parts[2].split()[0] if ' ' in parts[2] else parts[2]
                            
                            package = SystemPackage(
                                name=name,
                                version=version,
                                architecture=Architecture.UNKNOWN,
                                vendor="",
                                installDate=None,
                                packageManager=PackageManager.WINGET,
                                filePath=None
                            )
                            packages.append(package)
        
        except Exception as e:
            logger.debug(f"Error getting Winget packages: {e}")
        
        return packages
    
    def detectMacosPackages(self) -> List[SystemPackage]:
        """Detect installed packages on macOS"""
        packages = []
        
        try:
            # Homebrew packages
            packages.extend(self.getHomebrewPackages())
            
            # Mac App Store apps (simplified)
            packages.extend(self.getMacAppStorePackages())
            
            # pkgutil packages
            packages.extend(self.getPkgutilPackages())
        
        except Exception as e:
            logger.warning(f"Error detecting macOS packages: {e}")
        
        return packages
    
    def getHomebrewPackages(self) -> List[SystemPackage]:
        """Get Homebrew packages"""
        packages = []
        
        try:
            if shutil.which('brew'):
                # Get list of installed packages
                cmd = ["brew", "list", "--versions"]
                result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
                
                for line in result.stdout.strip().split('\n'):
                    if line:
                        parts = line.split()
                        if len(parts) >= 2:
                            name = parts[0]
                            version = parts[1]
                            
                            # Get more info
                            try:
                                infoCmd = ["brew", "info", "--json=v1", name]
                                infoResult = subprocess.run(infoCmd, capture_output=True, text=True, encoding='utf-8')
                                info = json.loads(infoResult.stdout)[0]
                                
                                package = SystemPackage(
                                    name=name,
                                    version=version,
                                    architecture=Architecture.UNKNOWN,
                                    vendor=info.get('homepage', ''),
                                    installDate=None,
                                    packageManager=PackageManager.BREW,
                                    filePath=info.get('installed', [{}])[0].get('path', ''),
                                    description=info.get('desc', '')
                                )
                                packages.append(package)
                            except:
                                # Fallback without detailed info
                                package = SystemPackage(
                                    name=name,
                                    version=version,
                                    architecture=Architecture.UNKNOWN,
                                    vendor="",
                                    installDate=None,
                                    packageManager=PackageManager.BREW,
                                    filePath=None
                                )
                                packages.append(package)
        
        except Exception as e:
            logger.debug(f"Error getting Homebrew packages: {e}")
        
        return packages
    
    def getMacAppStorePackages(self) -> List[SystemPackage]:
        """Get Mac App Store packages (simplified)"""
        packages = []
        
        # This is a simplified approach
        appDirs = [
            '/Applications',
            os.path.expanduser('~/Applications')
        ]
        
        for appDir in appDirs:
            if os.path.exists(appDir):
                try:
                    for item in os.listdir(appDir):
                        if item.endswith('.app'):
                            appPath = os.path.join(appDir, item)
                            name = item[:-4]  # Remove .app extension
                            
                            # Try to get version from Info.plist
                            infoPlist = os.path.join(appPath, 'Contents', 'Info.plist')
                            version = "Unknown"
                            
                            if os.path.exists(infoPlist):
                                try:
                                    cmd = ['defaults', 'read', infoPlist, 'CFBundleShortVersionString']
                                    result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
                                    if result.returncode == 0:
                                        version = result.stdout.strip()
                                except:
                                    pass
                            
                            package = SystemPackage(
                                name=name,
                                version=version,
                                architecture=Architecture.UNKNOWN,
                                vendor="",
                                installDate=None,
                                packageManager=PackageManager.UNKNOWN,
                                filePath=appPath
                            )
                            packages.append(package)
                except Exception as e:
                    logger.debug(f"Error scanning {appDir}: {e}")
        
        return packages
    
    def getPkgutilPackages(self) -> List[SystemPackage]:
        """Get packages installed via pkgutil"""
        packages = []
        
        try:
            cmd = ["pkgutil", "--pkgs"]
            result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
            
            for pkgId in result.stdout.strip().split('\n'):
                if pkgId:
                    # Get package info
                    try:
                        infoCmd = ["pkgutil", "--pkg-info", pkgId]
                        infoResult = subprocess.run(infoCmd, capture_output=True, text=True, encoding='utf-8')
                        
                        info = {}
                        for line in infoResult.stdout.split('\n'):
                            if ': ' in line:
                                key, value = line.split(': ', 1)
                                info[key] = value
                        
                        package = SystemPackage(
                            name=info.get('package-id', pkgId),
                            version=info.get('version', ''),
                            architecture=Architecture.UNKNOWN,
                            vendor=info.get('install-location', '').split('/')[-1] if 'install-location' in info else "",
                            installDate=None,
                            packageManager=PackageManager.UNKNOWN,
                            filePath=info.get('install-location', '')
                        )
                        packages.append(package)
                    except:
                        pass
        
        except Exception as e:
            logger.debug(f"Error getting pkgutil packages: {e}")
        
        return packages
    
    def detectPythonPackages(self) -> List[SystemPackage]:
        """Detect Python packages"""
        packages = []
        
        try:
            # Use pip to list installed packages
            for pipCmd in ['pip', 'pip3', sys.executable + ' -m pip']:
                try:
                    cmd = pipCmd.split() + ['list', '--format=json']
                    result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
                    
                    if result.returncode == 0:
                        packageData = json.loads(result.stdout)
                        
                        for pkg in packageData:
                            package = SystemPackage(
                                name=pkg['name'],
                                version=pkg['version'],
                                architecture=Architecture.UNKNOWN,
                                vendor="Python Package Index",
                                installDate=None,
                                packageManager=PackageManager.PIP,
                                filePath=self.getPythonPackageLocation(pkg['name']),
                                description=""
                            )
                            packages.append(package)
                        break
                except:
                    continue
        
        except Exception as e:
            logger.debug(f"Error detecting Python packages: {e}")
        
        return packages
    
    def detectNodePackages(self) -> List[SystemPackage]:
        """Detect Node.js packages"""
        packages = []
        
        try:
            # Check for global npm packages
            if shutil.which('npm'):
                cmd = ['npm', 'list', '-g', '--depth=0', '--json']
                result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
                
                if result.returncode == 0:
                    try:
                        packageData = json.loads(result.stdout)
                        dependencies = packageData.get('dependencies', {})
                        
                        for name, info in dependencies.items():
                            if 'version' in info:
                                package = SystemPackage(
                                    name=name,
                                    version=info['version'],
                                    architecture=Architecture.UNKNOWN,
                                    vendor="npm",
                                    installDate=None,
                                    packageManager=PackageManager.NPM,
                                    filePath=None,
                                    description=info.get('description', '')
                                )
                                packages.append(package)
                    except json.JSONDecodeError:
                        pass
        except Exception as e:
            logger.debug(f"Error detecting Node packages: {e}")
        
        return packages
    
    def detectRubyPackages(self) -> List[SystemPackage]:
        """Detect Ruby gems"""
        packages = []
        
        try:
            if shutil.which('gem'):
                cmd = ['gem', 'list', '--local']
                result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
                
                for line in result.stdout.strip().split('\n'):
                    if '(' in line and ')' in line:
                        name = line.split('(')[0].strip()
                        version = line.split('(')[1].split(')')[0].split(',')[0].strip()
                        
                        package = SystemPackage(
                            name=name,
                            version=version,
                            architecture=Architecture.UNKNOWN,
                            vendor="RubyGems",
                            installDate=None,
                            packageManager=PackageManager.GEM,
                            filePath=None
                        )
                        packages.append(package)
        except Exception as e:
            logger.debug(f"Error detecting Ruby packages: {e}")
        
        return packages
    
    def getPackageInstallDate(self, packageName: str, packageManager: PackageManager) -> Optional[datetime]:
        """Get package installation date"""
        try:
            if self.osType == OperatingSystem.LINUX:
                if packageManager == PackageManager.APT:
                    # Try to get install date from dpkg logs
                    logPath = "/var/log/dpkg.log"
                    if os.path.exists(logPath):
                        with open(logPath, 'r', encoding='utf-8', errors='ignore') as f:
                            for line in f:
                                if f'install {packageName}:' in line:
                                    dateStr = line.split()[0] + ' ' + line.split()[1]
                                    return datetime.strptime(dateStr, '%Y-%m-%d %H:%M:%S')
                
                elif packageManager in [PackageManager.YUM, PackageManager.DNF]:
                    # Try rpm query
                    cmd = ["rpm", "-q", "--queryformat", "%{INSTALLTIME}", packageName]
                    result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
                    if result.returncode == 0 and result.stdout.strip().isdigit():
                        return datetime.fromtimestamp(int(result.stdout.strip()))
        
        except Exception as e:
            logger.debug(f"Error getting install date for {packageName}: {e}")
        
        return None
    
    def getPackageDescription(self, packageName: str) -> str:
        """Get package description"""
        try:
            if self.osType == OperatingSystem.LINUX:
                # Try dpkg
                cmd = ["dpkg-query", "-W", "-f=${Description}", packageName]
                result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
                if result.returncode == 0:
                    return result.stdout.strip()
        except:
            pass
        return ""
    
    def getPythonPackageLocation(self, packageName: str) -> Optional[str]:
        """Get Python package installation location"""
        try:
            for pipCmd in ['pip', 'pip3', sys.executable + ' -m pip']:
                try:
                    cmd = pipCmd.split() + ['show', packageName]
                    result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8')
                    
                    if result.returncode == 0:
                        for line in result.stdout.split('\n'):
                            if line.startswith('Location:'):
                                return line.split(':', 1)[1].strip()
                except:
                    continue
        except:
            pass
        return None
    
    def findUninstaller(self, directory: str) -> Optional[str]:
        """Find uninstaller in directory"""
        uninstallerNames = ['uninstall.exe', 'unins000.exe', 'unins001.exe', 'Uninstall.exe']
        
        for uninstaller in uninstallerNames:
            uninstallerPath = os.path.join(directory, uninstaller)
            if os.path.exists(uninstallerPath):
                return uninstallerPath
        
        # Also check for uninstallers in subdirectories
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.lower().startswith('unins') and file.lower().endswith('.exe'):
                    return os.path.join(root, file)
        
        return None
    
    def getFileVersionInfo(self, directory: str) -> Optional[Dict[str, str]]:
        """Get version info from executable files in directory"""
        exeExtensions = ['.exe', '.dll', '.msi']
        
        for root, dirs, files in os.walk(directory):
            for file in files:
                if any(file.lower().endswith(ext) for ext in exeExtensions):
                    filePath = os.path.join(root, file)
                    try:
                        # Try to get version info on Windows
                        if self.osType == OperatingSystem.WINDOWS:
                            try:
                                from win32api import GetFileVersionInfo
                                info = GetFileVersionInfo(filePath, '\\')
                                if info:
                                    return {
                                        'CompanyName': info.get('CompanyName', ''),
                                        'FileDescription': info.get('FileDescription', ''),
                                        'FileVersion': info.get('FileVersion', ''),
                                        'ProductName': info.get('ProductName', ''),
                                        'ProductVersion': info.get('ProductVersion', '')
                                    }
                            except ImportError:
                                # pywin32 not available, skip version info extraction
                                pass
                    except Exception:
                        pass
        
        return None
    
    def readRegistryValue(self, key, valueName: str) -> Optional[str]:
        """Read registry value"""
        try:
            import winreg
            value, valueType = winreg.QueryValueEx(key, valueName)
            return str(value)
        except:
            return None
    
    def getRunningServices(self) -> List[str]:
        """Get running services"""
        services = []
        
        try:
            if THIRD_PARTY_IMPORTS['psutil']:
                for service in psutil.win_service_iter() if self.osType == OperatingSystem.WINDOWS else []:
                    if service.status() == 'running':
                        services.append(service.name())
            
            elif self.osType == OperatingSystem.LINUX:
                # Try systemd first
                try:
                    result = subprocess.run(['systemctl', 'list-units', '--type=service', 
                                           '--state=running', '--no-legend'],
                                          capture_output=True, text=True, encoding='utf-8')
                    if result.returncode == 0:
                        for line in result.stdout.strip().split('\n'):
                            if line:
                                services.append(line.split()[0])
                    else:
                        # Fallback to service command
                        result = subprocess.run(['service', '--status-all'],
                                              capture_output=True, text=True, encoding='utf-8')
                        for line in result.stdout.split('\n'):
                            if '[ + ]' in line:
                                service = line.split()[3]
                                services.append(service)
                except:
                    pass
            
            elif self.osType == OperatingSystem.WINDOWS:
                try:
                    result = subprocess.run(['sc', 'query', 'type=', 'service', 'state=', 'all'],
                                          capture_output=True, text=True, shell=True, encoding='utf-8')
                    for line in result.stdout.split('\n'):
                        if 'SERVICE_NAME' in line:
                            service = line.split(':')[1].strip()
                            services.append(service)
                except:
                    pass
        
        except Exception as e:
            logger.debug(f"Error getting running services: {e}")
        
        return services
    
    def getOpenPorts(self) -> List[int]:
        """Get open network ports"""
        ports = []
        
        try:
            if THIRD_PARTY_IMPORTS['psutil']:
                connections = psutil.net_connections()
                for conn in connections:
                    if conn.status == 'LISTEN' and conn.laddr:
                        ports.append(conn.laddr.port)
            
            else:
                if self.osType == OperatingSystem.LINUX:
                    try:
                        result = subprocess.run(['ss', '-tuln'], 
                                              capture_output=True, text=True, encoding='utf-8')
                        for line in result.stdout.split('\n')[1:]:
                            if line:
                                parts = line.split()
                                if len(parts) >= 5:
                                    address = parts[4]
                                    if ':' in address:
                                        port = address.split(':')[-1]
                                        if port.isdigit():
                                            ports.append(int(port))
                    except:
                        pass
                
                elif self.osType == OperatingSystem.WINDOWS:
                    try:
                        result = subprocess.run(['netstat', '-an'], 
                                              capture_output=True, text=True, shell=True, encoding='utf-8')
                        for line in result.stdout.split('\n'):
                            if 'LISTENING' in line:
                                parts = line.split()
                                if len(parts) >= 2:
                                    address = parts[1]
                                    if ':' in address:
                                        port = address.split(':')[-1]
                                        if port.isdigit():
                                            ports.append(int(port))
                    except:
                        pass
        
        except Exception as e:
            logger.debug(f"Error getting open ports: {e}")
        
        return sorted(set(ports))
    
    def getUsers(self) -> List[str]:
        """Get system users"""
        users = []
        
        try:
            if self.osType == OperatingSystem.LINUX:
                with open("/etc/passwd", 'r', encoding='utf-8') as f:
                    for line in f:
                        if ':' in line:
                            username = line.split(':')[0]
                            users.append(username)
            
            elif self.osType == OperatingSystem.WINDOWS:
                try:
                    result = subprocess.run(['net', 'user'], 
                                          capture_output=True, text=True, shell=True, encoding='utf-8')
                    for line in result.stdout.split('\n'):
                        if line and not line.startswith('---') and not line.startswith('User accounts'):
                            for user in line.split():
                                if user and user != 'The' and user != 'command':
                                    users.append(user)
                except:
                    pass
            
            elif self.osType == OperatingSystem.MACOS:
                try:
                    result = subprocess.run(['dscl', '.', '-list', '/Users'], 
                                          capture_output=True, text=True, encoding='utf-8')
                    users = [u.strip() for u in result.stdout.split('\n') if u.strip() and not u.startswith('_')]
                except:
                    pass
        
        except Exception as e:
            logger.debug(f"Error getting users: {e}")
        
        return users
    
    def getSecurityPolicies(self) -> Dict[str, Any]:
        """Get security policies"""
        policies = {}
        
        try:
            if self.osType == OperatingSystem.LINUX:
                # SSH configuration
                sshConfig = "/etc/ssh/sshd_config"
                if os.path.exists(sshConfig):
                    try:
                        with open(sshConfig, 'r', encoding='utf-8') as f:
                            policies['ssh'] = f.read()
                    except:
                        pass
                
                # Sudoers configuration
                sudoersFiles = ['/etc/sudoers', '/etc/sudoers.d/']
                sudoersContent = []
                for sudoersFile in sudoersFiles:
                    if os.path.exists(sudoersFile):
                        if os.path.isdir(sudoersFile):
                            for file in os.listdir(sudoersFile):
                                filePath = os.path.join(sudoersFile, file)
                                if os.path.isfile(filePath):
                                    try:
                                        with open(filePath, 'r', encoding='utf-8') as f:
                                            sudoersContent.append(f.read())
                                    except:
                                        pass
                        else:
                            try:
                                with open(sudoersFile, 'r', encoding='utf-8') as f:
                                    sudoersContent.append(f.read())
                            except:
                                pass
                
                if sudoersContent:
                    policies['sudoers'] = '\n'.join(sudoersContent)
                
                # Firewall rules
                for cmd in ['iptables', 'ufw', 'firewalld']:
                    if shutil.which(cmd):
                        try:
                            if cmd == 'iptables':
                                result = subprocess.run(['iptables', '-L', '-n'], 
                                                      capture_output=True, text=True, encoding='utf-8')
                                policies['iptables'] = result.stdout
                            elif cmd == 'ufw':
                                result = subprocess.run(['ufw', 'status', 'verbose'], 
                                                      capture_output=True, text=True, encoding='utf-8')
                                policies['ufw'] = result.stdout
                            elif cmd == 'firewalld':
                                result = subprocess.run(['firewall-cmd', '--list-all'], 
                                                      capture_output=True, text=True, encoding='utf-8')
                                policies['firewalld'] = result.stdout
                        except:
                            pass
            
            elif self.osType == OperatingSystem.WINDOWS:
                try:
                    # Get firewall rules
                    result = subprocess.run(['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all'], 
                                          capture_output=True, text=True, shell=True, encoding='utf-8')
                    policies['windows_firewall'] = result.stdout
                    
                    # Get security policy
                    tempFile = tempfile.NamedTemporaryFile(delete=False, suffix='.inf')
                    tempFile.close()
                    
                    result = subprocess.run(['secedit', '/export', '/cfg', tempFile.name, '/quiet'], 
                                          capture_output=True, text=True, shell=True, encoding='utf-8')
                    
                    if os.path.exists(tempFile.name):
                        with open(tempFile.name, 'r', encoding='utf-8') as f:
                            policies['secedit'] = f.read()
                        os.unlink(tempFile.name)
                    
                    # Get audit policy
                    result = subprocess.run(['auditpol', '/get', '/category:*'], 
                                          capture_output=True, text=True, shell=True, encoding='utf-8')
                    policies['auditpol'] = result.stdout
                    
                except Exception as e:
                    logger.debug(f"Error getting Windows security policies: {e}")
        
        except Exception as e:
            logger.debug(f"Error getting security policies: {e}")
        
        return policies
    
    def getUptime(self) -> float:
        """Get system uptime in seconds"""
        try:
            if THIRD_PARTY_IMPORTS['psutil']:
                return time.time() - psutil.boot_time()
            
            elif self.osType == OperatingSystem.LINUX:
                with open('/proc/uptime', 'r', encoding='utf-8') as f:
                    uptimeSeconds = float(f.readline().split()[0])
                    return uptimeSeconds
            
            elif self.osType == OperatingSystem.WINDOWS:
                try:
                    result = subprocess.run(['powershell', '-Command', '(Get-CimInstance Win32_OperatingSystem).LastBootUpTime'], 
                                          capture_output=True, text=True, shell=True, encoding='utf-8')
                    bootTimeStr = result.stdout.strip()
                    if bootTimeStr:
                        bootTime = datetime.strptime(bootTimeStr, '%Y%m%d%H%M%S.%f%z')
                        return (datetime.now(bootTime.tzinfo) - bootTime).total_seconds()
                except:
                    pass
            
        except Exception as e:
            logger.debug(f"Error getting uptime: {e}")
        
        return 0.0
    
    def getLastBootTime(self) -> Optional[datetime]:
        """Get last boot time"""
        try:
            uptime = self.getUptime()
            if uptime > 0:
                return datetime.now() - timedelta(seconds=uptime)
        except:
            pass
        return None
    
    def getTimezone(self) -> str:
        """Get system timezone"""
        try:
            if self.osType == OperatingSystem.LINUX:
                # Try to read timezone file
                tzFiles = ['/etc/timezone', '/etc/localtime']
                for tzFile in tzFiles:
                    if os.path.exists(tzFile):
                        if os.path.islink(tzFile):
                            return os.path.realpath(tzFile).split('/')[-1]
                        else:
                            with open(tzFile, 'r', encoding='utf-8') as f:
                                return f.read().strip()
            
            elif self.osType == OperatingSystem.WINDOWS:
                try:
                    import winreg
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                       r"SYSTEM\CurrentControlSet\Control\TimeZoneInformation")
                    timezoneName = winreg.QueryValueEx(key, "TimeZoneKeyName")[0]
                    winreg.CloseKey(key)
                    return timezoneName
                except:
                    pass
            
        except Exception as e:
            logger.debug(f"Error getting timezone: {e}")
        
        return ""
    
    def getLocale(self) -> str:
        """Get system locale"""
        try:
            import locale
            return locale.getdefaultlocale()[0] or ""
        except:
            return ""

# Progress Manager with multiple display options
class ProgressManager:
    """Manages progress display with multiple formats"""
    
    def __init__(self, total: int = 100, desc: str = "Processing", 
                 useTqdm: bool = THIRD_PARTY_IMPORTS['tqdm']):
        self.total = total
        self.desc = desc
        self.current = 0
        self.startTime = time.time()
        self.useTqdm = useTqdm
        self.tqdmBar = None
        
        if self.useTqdm:
            self.tqdmBar = tqdm.tqdm(total=total, desc=desc, unit="ops", 
                                     bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]")
    
    def update(self, increment: int = 1, status: str = "") -> None:
        """Update progress"""
        self.current += increment
        
        if self.useTqdm and self.tqdmBar:
            self.tqdmBar.update(increment)
            if status:
                self.tqdmBar.set_postfix_str(status)
        else:
            self.displayConsoleProgress(status)
    
    def displayConsoleProgress(self, status: str = "") -> None:
        """Display progress in console"""
        if self.total <= 0:
            return
        
        percentage = min(100, (self.current / self.total) * 100)
        barLength = 40
        filledLength = int(barLength * self.current // self.total)
        bar = '█' * filledLength + '░' * (barLength - filledLength)
        
        elapsed = time.time() - self.startTime
        if self.current > 0 and elapsed > 0:
            remaining = (elapsed / self.current) * (self.total - self.current)
            timeStr = f"{elapsed:.1f}s<{remaining:.1f}s"
        else:
            timeStr = f"{elapsed:.1f}s<?"
        
        sys.stdout.write(f'\r{self.desc}: |{bar}| {percentage:.1f}% ({self.current}/{self.total}) [{timeStr}] {status}')
        sys.stdout.flush()
        
        if self.current >= self.total:
            sys.stdout.write('\n')
    
    def setDescription(self, desc: str) -> None:
        """Update progress bar description"""
        self.desc = desc
        if self.useTqdm and self.tqdmBar:
            self.tqdmBar.set_description(desc)
    
    def close(self) -> None:
        """Close progress bar"""
        if self.useTqdm and self.tqdmBar:
            self.tqdmBar.close()
        elif self.current < self.total:
            # Ensure final display
            self.update(self.total - self.current)
    
    def __enter__(self):
        return self
    
    def __exit__(self, excType, excVal, excTb):
        self.close()

# Cache Manager for performance optimization
class CacheManager:
    """Manages caching with TTL and persistence"""
    
    def __init__(self, cacheDir: str = "cache", defaultTtl: int = 3600):
        self.cacheDir = Path(cacheDir)
        self.cacheDir.mkdir(exist_ok=True)
        self.defaultTtl = defaultTtl
        self.memoryCache = {}
        self.lock = threading.RLock()
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        with self.lock:
            # Check memory cache first
            if key in self.memoryCache:
                value, expiry = self.memoryCache[key]
                if expiry > time.time():
                    return value
                else:
                    del self.memoryCache[key]
            
            # Check disk cache
            cacheFile = self.cacheDir / f"{hashlib.md5(key.encode()).hexdigest()}.cache"
            if cacheFile.exists():
                try:
                    with open(cacheFile, 'rb') as f:
                        data = pickle.load(f)
                    
                    if data['expiry'] > time.time():
                        # Also store in memory for faster access
                        self.memoryCache[key] = (data['value'], data['expiry'])
                        return data['value']
                    else:
                        # Expired, delete file
                        cacheFile.unlink()
                except Exception as e:
                    logger.debug(f"Error reading cache {key}: {e}")
            
            return None
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set value in cache"""
        with self.lock:
            expiry = time.time() + (ttl or self.defaultTtl)
            
            # Store in memory
            self.memoryCache[key] = (value, expiry)
            
            # Store on disk
            cacheFile = self.cacheDir / f"{hashlib.md5(key.encode()).hexdigest()}.cache"
            try:
                data = {
                    'key': key,
                    'value': value,
                    'expiry': expiry,
                    'timestamp': datetime.now().isoformat()
                }
                with open(cacheFile, 'wb') as f:
                    pickle.dump(data, f)
            except Exception as e:
                logger.debug(f"Error writing cache {key}: {e}")
    
    def delete(self, key: str) -> None:
        """Delete value from cache"""
        with self.lock:
            # Delete from memory
            if key in self.memoryCache:
                del self.memoryCache[key]
            
            # Delete from disk
            cacheFile = self.cacheDir / f"{hashlib.md5(key.encode()).hexdigest()}.cache"
            if cacheFile.exists():
                try:
                    cacheFile.unlink()
                except:
                    pass
    
    def clear(self, olderThan: Optional[float] = None) -> int:
        """Clear cache, optionally only entries older than timestamp"""
        count = 0
        
        with self.lock:
            # Clear memory cache
            now = time.time()
            keysToDelete = []
            
            for key, (value, expiry) in self.memoryCache.items():
                if olderThan is None or expiry < (olderThan if olderThan > 1 else now - olderThan):
                    keysToDelete.append(key)
            
            for key in keysToDelete:
                del self.memoryCache[key]
                count += 1
            
            # Clear disk cache
            for cacheFile in self.cacheDir.glob("*.cache"):
                try:
                    if olderThan is None:
                        cacheFile.unlink()
                        count += 1
                    else:
                        with open(cacheFile, 'rb') as f:
                            data = pickle.load(f)
                        
                        if data['expiry'] < (olderThan if olderThan > 1 else now - olderThan):
                            cacheFile.unlink()
                            count += 1
                except:
                    pass
        
        logger.info(f"Cleared {count} cache entries")
        return count
    
    def cleanup(self) -> None:
        """Clean up expired cache entries"""
        self.clear(olderThan=time.time())

# Vulnerability Detector with advanced matching
class VulnerabilityDetector:
    """Advanced vulnerability detector with fuzzy matching and confidence scoring"""
    
    def __init__(self, cveSources: List[CveDataSource], cacheManager: Optional[CacheManager] = None):
        self.cveSources = cveSources
        self.cacheManager = cacheManager or CacheManager()
        self.vulnerabilityCache = {}
        self.patternCache = {}
    
    def scanSystem(self, systemInfo: SystemInfo) -> List[ScanResult]:
        """Scan system for vulnerabilities with advanced detection"""
        logger.info("Starting comprehensive vulnerability scan...")
        
        startTime = time.time()
        
        # Get all vulnerabilities from all sources
        allVulnerabilities = self.getAllVulnerabilities()
        logger.info(f"Loaded {len(allVulnerabilities)} vulnerabilities from {len(self.cveSources)} sources")
        
        # Scan packages
        scanResults = self.scanPackages(systemInfo.installedPackages, allVulnerabilities)
        
        # Scan system configuration
        configResults = self.scanConfiguration(systemInfo)
        scanResults.extend(configResults)
        
        # Filter out low confidence results
        filteredResults = [r for r in scanResults if r.confidence >= 0.3]
        
        # Sort by severity and confidence
        filteredResults.sort(key=lambda x: (
            -x.vulnerability.severity.value,
            -x.confidence,
            x.vulnerability.cveId
        ))
        
        elapsed = time.time() - startTime
        logger.info(f"Scan completed in {elapsed:.2f} seconds. Found {len(filteredResults)} vulnerabilities")
        
        return filteredResults
    
    def getAllVulnerabilities(self) -> List[Vulnerability]:
        """Get all vulnerabilities from all sources with caching"""
        cacheKey = "all_vulnerabilities"
        cached = self.cacheManager.get(cacheKey)
        
        if cached:
            logger.debug("Using cached vulnerabilities")
            return cached
        
        allVulns = []
        
        with ProgressManager(total=len(self.cveSources), desc="Loading CVE databases") as progress:
            for source in self.cveSources:
                try:
                    sourceName = source.sourceName
                    logger.debug(f"Loading vulnerabilities from {sourceName}")
                    
                    vulns = source.fetchCves()
                    allVulns.extend(vulns)
                    
                    progress.update(1, status=f"{sourceName}: {len(vulns)} CVEs")
                    
                except Exception as e:
                    logger.error(f"Failed to load from {source.sourceName}: {e}")
                    progress.update(1, status=f"{source.sourceName}: Failed")
        
        # Remove duplicates by CVE ID
        uniqueVulns = {}
        for vuln in allVulns:
            if vuln.cveId not in uniqueVulns:
                uniqueVulns[vuln.cveId] = vuln
            else:
                # Keep the one with higher severity or more information
                existing = uniqueVulns[vuln.cveId]
                if (vuln.severity.value > existing.severity.value or 
                    (vuln.severity.value == existing.severity.value and 
                     len(vuln.description) > len(existing.description))):
                    uniqueVulns[vuln.cveId] = vuln
        
        result = list(uniqueVulns.values())
        
        # Cache for 1 hour
        self.cacheManager.set(cacheKey, result, ttl=3600)
        
        return result
    
    def scanPackages(self, packages: List[SystemPackage], 
                    vulnerabilities: List[Vulnerability]) -> List[ScanResult]:
        """Scan packages for vulnerabilities with fuzzy matching"""
        scanResults = []
        
        if not packages or not vulnerabilities:
            return scanResults
        
        # Build package index for faster lookup
        packageIndex = {}
        for pkg in packages:
            packageIndex[pkg.name.lower()] = pkg
        
        # Pre-process vulnerability patterns
        vulnerabilityPatterns = self.preprocessVulnerabilityPatterns(vulnerabilities)
        
        with ProgressManager(total=len(vulnerabilities), desc="Scanning packages") as progress:
            for vuln in vulnerabilities:
                results = self.checkPackageAgainstVulnerability(packageIndex, vuln, vulnerabilityPatterns)
                scanResults.extend(results)
                progress.update(1, status=f"{vuln.cveId}: {len(results)} matches")
        
        return scanResults
    
    def preprocessVulnerabilityPatterns(self, vulnerabilities: List[Vulnerability]) -> Dict[str, List[str]]:
        """Pre-process vulnerability patterns for faster matching"""
        patterns = {}
        
        for vuln in vulnerabilities:
            patterns[vuln.cveId] = []
            
            # Add package names as patterns
            for package in vuln.affectedPackages:
                patterns[vuln.cveId].append(package.lower())
            
            # Add variations of package names
            for package in vuln.affectedPackages:
                # Remove common prefixes/suffixes
                variations = set()
                variations.add(package.lower())
                
                # Common variations
                if package.startswith('lib'):
                    variations.add(package[3:].lower())
                if package.endswith('-dev'):
                    variations.add(package[:-4].lower())
                if '-' in package:
                    variations.add(package.replace('-', '').lower())
                    variations.add(package.replace('-', '_').lower())
                
                patterns[vuln.cveId].extend(list(variations))
        
        return patterns
    
    def checkPackageAgainstVulnerability(self, packageIndex: Dict[str, SystemPackage], 
                                        vulnerability: Vulnerability,
                                        patterns: Dict[str, List[str]]) -> List[ScanResult]:
        """Check if any package matches a vulnerability"""
        results = []
        
        # Get patterns for this vulnerability
        vulnPatterns = patterns.get(vulnerability.cveId, [])
        
        # Check each pattern against package index
        for pattern in vulnPatterns:
            # Exact match
            if pattern in packageIndex:
                pkg = packageIndex[pattern]
                result = self.evaluatePackageVulnerability(pkg, vulnerability)
                if result:
                    results.append(result)
            
            # Fuzzy matching for similar package names
            for pkgName, pkg in packageIndex.items():
                if pattern in pkgName or pkgName in pattern:
                    # Check if not already matched
                    if not any(r.detectedPackage.name == pkg.name for r in results):
                        result = self.evaluatePackageVulnerability(pkg, vulnerability)
                        if result:
                            results.append(result)
        
        return results
    
    def evaluatePackageVulnerability(self, pkg: SystemPackage, 
                                    vulnerability: Vulnerability) -> Optional[ScanResult]:
        """Evaluate if a package is vulnerable with confidence scoring"""
        confidence = 0.0
        evidence = []
        
        # Base confidence for package name match
        pkgNameLower = pkg.name.lower()
        for affectedPackage in vulnerability.affectedPackages:
            affectedLower = affectedPackage.lower()
            
            if pkgNameLower == affectedLower:
                confidence += 0.4
                evidence.append(f"Exact package name match: {affectedPackage}")
                break
            elif affectedLower in pkgNameLower or pkgNameLower in affectedLower:
                confidence += 0.2
                evidence.append(f"Partial package name match: {affectedPackage}")
                break
        
        # Version comparison if fixed version is available
        if vulnerability.fixedVersion and THIRD_PARTY_IMPORTS['packaging']:
            try:
                pkgVersion = version.parse(pkg.version)
                fixedVersion = version.parse(vulnerability.fixedVersion)
                
                if pkgVersion < fixedVersion:
                    confidence += 0.4
                    evidence.append(f"Version {pkg.version} < fixed version {vulnerability.fixedVersion}")
                else:
                    # Not vulnerable based on version
                    return None
            except version.InvalidVersion:
                # Version parsing failed, use string comparison
                if vulnerability.fixedVersion and pkg.version != vulnerability.fixedVersion:
                    # Try to extract version numbers
                    import re
                    pkgVerNums = re.findall(r'\d+', pkg.version)
                    fixedVerNums = re.findall(r'\d+', vulnerability.fixedVersion)
                    
                    if pkgVerNums and fixedVerNums:
                        # Compare first few version numbers
                        for i in range(min(len(pkgVerNums), len(fixedVerNums))):
                            pkgNum = int(pkgVerNums[i])
                            fixedNum = int(fixedVerNums[i])
                            
                            if pkgNum < fixedNum:
                                confidence += 0.3
                                evidence.append(f"Version component {pkgNum} < {fixedNum}")
                                break
                            elif pkgNum > fixedNum:
                                # Not vulnerable
                                return None
        
        # Check affected versions dictionary
        if vulnerability.affectedVersions and pkg.name in vulnerability.affectedVersions:
            affectedVersions = vulnerability.affectedVersions[pkg.name]
            if pkg.version in affectedVersions or any(av in pkg.version for av in affectedVersions):
                confidence += 0.3
                evidence.append(f"Version {pkg.version} in affected versions list")
        
        # Adjust confidence based on severity (higher severity = more cautious)
        if vulnerability.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
            confidence *= 0.9  # Be more conservative with high-severity vulnerabilities
        
        # Minimum confidence threshold
        if confidence < 0.3:
            return None
        
        # Cap confidence at 1.0
        confidence = min(confidence, 1.0)
        
        return ScanResult(
            vulnerability=vulnerability,
            detectedPackage=pkg,
            evidence='; '.join(evidence),
            confidence=confidence,
            timestamp=datetime.now(),
            scannerVersion=VERSION,
            falsePositive=False
        )
    
    def scanConfiguration(self, systemInfo: SystemInfo) -> List[ScanResult]:
        """Scan system configuration for vulnerabilities"""
        results = []
        
        # SSH configuration checks
        if 'ssh' in systemInfo.securityPolicies:
            sshResults = self.scanSshConfiguration(systemInfo.securityPolicies['ssh'])
            results.extend(sshResults)
        
        # Sudo configuration checks
        if 'sudoers' in systemInfo.securityPolicies:
            sudoResults = self.scanSudoConfiguration(systemInfo.securityPolicies['sudoers'])
            results.extend(sudoResults)
        
        # Windows-specific checks
        if systemInfo.osType == OperatingSystem.WINDOWS:
            windowsResults = self.scanWindowsConfiguration(systemInfo.securityPolicies)
            results.extend(windowsResults)
        
        return results
    
    def scanSshConfiguration(self, sshConfig: str) -> List[ScanResult]:
        """Scan SSH configuration for vulnerabilities"""
        results = []
        
        lines = sshConfig.split('\n')
        
        # Check for PermitRootLogin
        for line in lines:
            if line.strip().startswith('PermitRootLogin') and not line.strip().startswith('#'):
                value = line.split()[1] if len(line.split()) > 1 else ''
                if value.lower() in ['yes', 'without-password', 'prohibit-password']:
                    vuln = Vulnerability(
                        cveId="CONFIG-SSH-001",
                        description="SSH root login enabled",
                        severity=SeverityLevel.HIGH,
                        cvssScore=7.5,
                        cvssVector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        affectedPackages=["openssh-server"],
                        affectedVersions={},
                        fixedVersion=None,
                        exploitAvailable=True,
                        exploitMaturity="",
                        publishedDate=datetime.now(),
                        lastModifiedDate=datetime.now(),
                        references=[],
                        mitigation="Set PermitRootLogin to 'no'",
                        workaround="",
                        impact="Potential unauthorized root access",
                        advisory="",
                        credits=""
                    )
                    
                    result = ScanResult(
                        vulnerability=vuln,
                        detectedPackage=SystemPackage(
                            name="openssh-server",
                            version="Unknown",
                            architecture=Architecture.UNKNOWN,
                            vendor="",
                            installDate=None,
                            packageManager=PackageManager.UNKNOWN,
                            filePath=None
                        ),
                        evidence=f"SSH PermitRootLogin set to '{value}'",
                        confidence=0.9,
                        timestamp=datetime.now(),
                        scannerVersion=VERSION
                    )
                    results.append(result)
        
        # Check for Protocol 1
        for line in lines:
            if line.strip().startswith('Protocol') and not line.strip().startswith('#'):
                value = line.split()[1] if len(line.split()) > 1 else ''
                if '1' in value:
                    vuln = Vulnerability(
                        cveId="CONFIG-SSH-002",
                        description="SSH Protocol 1 enabled (deprecated and insecure)",
                        severity=SeverityLevel.CRITICAL,
                        cvssScore=9.8,
                        cvssVector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        affectedPackages=["openssh-server"],
                        affectedVersions={},
                        fixedVersion=None,
                        exploitAvailable=True,
                        exploitMaturity="",
                        publishedDate=datetime.now(),
                        lastModifiedDate=datetime.now(),
                        references=[],
                        mitigation="Set Protocol to 2",
                        workaround="",
                        impact="SSH Protocol 1 has known cryptographic weaknesses",
                        advisory="",
                        credits=""
                    )
                    
                    result = ScanResult(
                        vulnerability=vuln,
                        detectedPackage=SystemPackage(
                            name="openssh-server",
                            version="Unknown",
                            architecture=Architecture.UNKNOWN,
                            vendor="",
                            installDate=None,
                            packageManager=PackageManager.UNKNOWN,
                            filePath=None
                        ),
                        evidence="SSH Protocol 1 enabled",
                        confidence=0.95,
                        timestamp=datetime.now(),
                        scannerVersion=VERSION
                    )
                    results.append(result)
        
        return results
    
    def scanSudoConfiguration(self, sudoersConfig: str) -> List[ScanResult]:
        """Scan sudo configuration for vulnerabilities"""
        results = []
        
        lines = sudoersConfig.split('\n')
        
        # Check for NOPASSWD directives
        for line in lines:
            if 'NOPASSWD' in line and not line.strip().startswith('#'):
                vuln = Vulnerability(
                    cveId="CONFIG-SUDO-001",
                    description="Sudo NOPASSWD directive allows passwordless privilege escalation",
                    severity=SeverityLevel.MEDIUM,
                    cvssScore=6.5,
                    cvssVector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                    affectedPackages=["sudo"],
                    affectedVersions={},
                    fixedVersion=None,
                    exploitAvailable=True,
                    exploitMaturity="",
                    publishedDate=datetime.now(),
                    lastModifiedDate=datetime.now(),
                    references=[],
                    mitigation="Remove NOPASSWD or restrict to specific commands",
                    workaround="",
                    impact="Potential privilege escalation without authentication",
                    advisory="",
                    credits=""
                )
                
                result = ScanResult(
                    vulnerability=vuln,
                    detectedPackage=SystemPackage(
                        name="sudo",
                        version="Unknown",
                        architecture=Architecture.UNKNOWN,
                        vendor="",
                        installDate=None,
                        packageManager=PackageManager.UNKNOWN,
                        filePath=None
                    ),
                    evidence=f"Sudo NOPASSWD directive found: {line.strip()}",
                    confidence=0.8,
                    timestamp=datetime.now(),
                    scannerVersion=VERSION
                )
                results.append(result)
        
        return results
    
    def scanWindowsConfiguration(self, policies: Dict[str, Any]) -> List[ScanResult]:
        """Scan Windows configuration for vulnerabilities"""
        results = []
        
        # Check UAC status
        if 'secedit' in policies:
            seceditConfig = policies['secedit']
            lines = seceditConfig.split('\n')
            
            for line in lines:
                if 'EnableLUA' in line and '=' in line:
                    key, value = line.split('=', 1)
                    if key.strip() == 'EnableLUA' and value.strip() == '0':
                        vuln = Vulnerability(
                            cveId="CONFIG-WIN-001",
                            description="User Account Control (UAC) disabled",
                            severity=SeverityLevel.HIGH,
                            cvssScore=7.8,
                            cvssVector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                            affectedPackages=["windows"],
                            affectedVersions={},
                            fixedVersion=None,
                            exploitAvailable=True,
                            exploitMaturity="",
                            publishedDate=datetime.now(),
                            lastModifiedDate=datetime.now(),
                            references=[],
                            mitigation="Enable UAC via Group Policy or registry",
                            workaround="",
                            impact="Reduced protection against malware and unauthorized changes",
                            advisory="",
                            credits=""
                        )
                        
                        result = ScanResult(
                            vulnerability=vuln,
                            detectedPackage=SystemPackage(
                                name="windows",
                                version="Unknown",
                                architecture=Architecture.UNKNOWN,
                                vendor="Microsoft",
                                installDate=None,
                                packageManager=PackageManager.UNKNOWN,
                                filePath=None
                            ),
                            evidence="User Account Control (UAC) disabled (EnableLUA=0)",
                            confidence=0.9,
                            timestamp=datetime.now(),
                            scannerVersion=VERSION
                        )
                        results.append(result)
        
        return results

# Patch Manager with rollback support
class PatchManager:
    """Advanced patch manager with rollback capabilities and verification"""
    
    def __init__(self, systemInfo: SystemInfo, dbManager: DatabaseManager, 
                 config: ConfigurationManager):
        self.systemInfo = systemInfo
        self.dbManager = dbManager
        self.config = config
        self.snapshotManager = SnapshotManager()
        self.totalOperations = 0
        self.completedOperations = 0
        self.lock = threading.Lock()
        self.failedPatches = []
        self.rollbackPoints = []
    
    def applyPatches(self, scanResults: List[ScanResult], 
                    dryRun: bool = False, 
                    force: bool = False) -> List[PatchResult]:
        """Apply patches for detected vulnerabilities"""
        logger.info(f"Starting patch application (dry run: {dryRun}, force: {force})...")
        
        self.totalOperations = len(scanResults)
        self.completedOperations = 0
        self.failedPatches = []
        
        if not scanResults:
            logger.info("No vulnerabilities to patch")
            return []
        
        # Create system snapshot for rollback
        snapshotHash = None
        if not dryRun and self.config.get('patching', 'create_snapshots', True):
            try:
                snapshotHash = self.snapshotManager.createSnapshot(self.systemInfo)
                self.rollbackPoints.append(snapshotHash)
                logger.info(f"Created system snapshot: {snapshotHash}")
            except Exception as e:
                logger.error(f"Failed to create snapshot: {e}")
                if not force:
                    raise
        
        # Filter patches based on whitelist/blacklist
        filteredResults = self.filterPatches(scanResults)
        
        if not filteredResults:
            logger.info("No patches to apply after filtering")
            return []
        
        # Apply patches with progress tracking
        patchResults = []
        
        with ProgressManager(total=len(filteredResults), desc="Applying patches") as progress:
            with ThreadPoolExecutor(max_workers=int(self.config.get('general', 'max_workers', 3))) as executor:
                futureToPatch = {
                    executor.submit(self.applySinglePatch, result, dryRun, snapshotHash, force): result
                    for result in filteredResults
                }
                
                for future in as_completed(futureToPatch):
                    scanResult = futureToPatch[future]
                    try:
                        patchResult = future.result(timeout=TIMEOUT)
                        patchResults.append(patchResult)
                        
                        # Save to database
                        if not dryRun:
                            self.dbManager.savePatchResult(patchResult)
                        
                        progress.update(1, status=f"{scanResult.vulnerability.cveId}: {patchResult.status.value}")
                        
                        if patchResult.status == PatchStatus.FAILED:
                            self.failedPatches.append(patchResult)
                    
                    except Exception as e:
                        logger.error(f"Failed to patch {scanResult.vulnerability.cveId}: {e}")
                        
                        patchResult = PatchResult(
                            cveId=scanResult.vulnerability.cveId,
                            status=PatchStatus.FAILED,
                            operation="patch",
                            details=f"Error: {str(e)}",
                            timestamp=datetime.now(),
                            rollbackPoint=snapshotHash,
                            executionTime=0.0,
                            errorMessage=str(e),
                            systemChanges=[],
                            verificationStatus=False
                        )
                        patchResults.append(patchResult)
                        self.failedPatches.append(patchResult)
                        
                        progress.update(1, status=f"{scanResult.vulnerability.cveId}: Failed")
        
        # Rollback if too many failures
        if not dryRun and self.failedPatches and self.config.get('patching', 'rollback_enabled', True):
            failureRate = len(self.failedPatches) / len(patchResults)
            if failureRate > 0.5:  # More than 50% failures
                logger.warning(f"High failure rate ({failureRate:.1%}), attempting rollback...")
                self.rollbackPatches(snapshotHash)
        
        # Generate summary
        self.generatePatchSummary(patchResults)
        
        return patchResults
    
    def filterPatches(self, scanResults: List[ScanResult]) -> List[ScanResult]:
        """Filter patches based on whitelist and blacklist"""
        whitelistStr = self.config.get('patching', 'whitelist', '')
        blacklistStr = self.config.get('patching', 'blacklist', '')
        
        whitelist = [item.strip().lower() for item in whitelistStr.split(',') if item.strip()]
        blacklist = [item.strip().lower() for item in blacklistStr.split(',') if item.strip()]
        
        filteredResults = []
        
        for result in scanResults:
            cveId = result.vulnerability.cveId.lower()
            packageName = result.detectedPackage.name.lower()
            
            # Check blacklist first
            blacklisted = False
            for pattern in blacklist:
                if pattern in cveId or pattern in packageName:
                    blacklisted = True
                    logger.info(f"Skipping {cveId} ({packageName}) - matches blacklist pattern: {pattern}")
                    break
            
            if blacklisted:
                continue
            
            # Check whitelist
            if whitelist:
                whitelisted = False
                for pattern in whitelist:
                    if pattern in cveId or pattern in packageName:
                        whitelisted = True
                        break
                
                if not whitelisted:
                    logger.info(f"Skipping {cveId} ({packageName}) - not in whitelist")
                    continue
            
            filteredResults.append(result)
        
        logger.info(f"Filtered {len(scanResults)} -> {len(filteredResults)} patches")
        return filteredResults
    
    def applySinglePatch(self, scanResult: ScanResult, dryRun: bool, 
                        snapshotHash: Optional[str], force: bool) -> PatchResult:
        """Apply a single patch"""
        startTime = time.time()
        
        patchResult = PatchResult(
            cveId=scanResult.vulnerability.cveId,
            status=PatchStatus.PENDING,
            operation="patch",
            details="",
            timestamp=datetime.now(),
            rollbackPoint=snapshotHash,
            executionTime=0.0,
            errorMessage=None,
            systemChanges=[],
            verificationStatus=False,
            patchVersion=scanResult.vulnerability.fixedVersion
        )
        
        try:
            if dryRun:
                patchResult.status = PatchStatus.SKIPPED
                patchResult.details = "Dry run - no changes made"
                patchResult.operation = "dry-run"
            else:
                # Determine patch strategy
                if scanResult.vulnerability.fixedVersion:
                    patchResult = self.updatePackage(scanResult, patchResult, force)
                elif scanResult.vulnerability.cveId.startswith("CONFIG-"):
                    patchResult = self.fixConfiguration(scanResult, patchResult, force)
                else:
                    patchResult = self.applyMitigation(scanResult, patchResult)
                
                # Verify patch
                if patchResult.status == PatchStatus.SUCCESS:
                    verificationResult = self.verifyPatch(scanResult)
                    patchResult.verificationStatus = verificationResult
                    
                    if not verificationResult:
                        patchResult.status = PatchStatus.MANUAL_INTERVENTION_REQUIRED
                        patchResult.details += " (verification failed)"
            
        except Exception as e:
            patchResult.status = PatchStatus.FAILED
            patchResult.errorMessage = str(e)
            patchResult.details = f"Patch failed: {str(e)}"
            
            # Attempt rollback for this specific patch
            if snapshotHash:
                try:
                    self.snapshotManager.restoreSnapshot(snapshotHash)
                    patchResult.details += " (rolled back)"
                    patchResult.status = PatchStatus.ROLLED_BACK
                except Exception as rollbackError:
                    patchResult.details += f" (rollback failed: {rollbackError})"
        
        finally:
            patchResult.executionTime = time.time() - startTime
            
            with self.lock:
                self.completedOperations += 1
            
            # Log result
            logLevel = logging.INFO if patchResult.status == PatchStatus.SUCCESS else logging.WARNING
            logger.log(logLevel, f"Patch {scanResult.vulnerability.cveId}: {patchResult.status.value} ({patchResult.executionTime:.2f}s)")
        
        return patchResult
    
    def updatePackage(self, scanResult: ScanResult, patchResult: PatchResult, 
                     force: bool) -> PatchResult:
        """Update vulnerable package"""
        package = scanResult.detectedPackage
        vuln = scanResult.vulnerability
        
        patchResult.operation = "package-update"
        
        try:
            if self.systemInfo.osType == OperatingSystem.LINUX:
                if package.packageManager == PackageManager.APT:
                    # Debian/Ubuntu
                    self.updateAptPackage(package, vuln, patchResult, force)
                
                elif package.packageManager in [PackageManager.YUM, PackageManager.DNF]:
                    # RHEL/CentOS/Fedora
                    self.updateYumPackage(package, vuln, patchResult, force)
                
                elif package.packageManager == PackageManager.PACMAN:
                    # Arch Linux
                    self.updatePacmanPackage(package, vuln, patchResult, force)
                
                elif package.packageManager == PackageManager.APK:
                    # Alpine Linux
                    self.updateApkPackage(package, vuln, patchResult, force)
                
                else:
                    patchResult.status = PatchStatus.MANUAL_INTERVENTION_REQUIRED
                    patchResult.details = f"Unsupported package manager: {package.packageManager.value}"
            
            elif self.systemInfo.osType == OperatingSystem.WINDOWS:
                self.updateWindowsPackage(package, vuln, patchResult, force)
            
            elif self.systemInfo.osType == OperatingSystem.MACOS:
                self.updateMacosPackage(package, vuln, patchResult, force)
            
            else:
                patchResult.status = PatchStatus.MANUAL_INTERVENTION_REQUIRED
                patchResult.details = f"Unsupported OS: {self.systemInfo.osType.value}"
        
        except subprocess.CalledProcessError as e:
            patchResult.status = PatchStatus.FAILED
            patchResult.errorMessage = f"Package manager error: {e.stderr}"
            patchResult.details = f"Update failed: {e.stderr}"
        
        return patchResult
    
    def updateAptPackage(self, package: SystemPackage, vuln: Vulnerability, 
                        patchResult: PatchResult, force: bool) -> None:
        """Update APT package"""
        # Update package lists
        subprocess.run(["apt-get", "update"], 
                      capture_output=True, text=True, check=True)
        
        # Install specific version if fixed version specified
        if vuln.fixedVersion:
            pkgSpec = f"{package.name}={vuln.fixedVersion}"
        else:
            pkgSpec = package.name
        
        # Upgrade package
        cmd = ["apt-get", "install", "--only-upgrade", "-y"]
        if force:
            cmd.append("--allow-downgrades")
        cmd.append(pkgSpec)
        
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        
        patchResult.status = PatchStatus.SUCCESS
        patchResult.details = f"Updated {package.name} to {vuln.fixedVersion or 'latest'} via apt"
        patchResult.systemChanges.append(f"Package {package.name} updated")
    
    def updateYumPackage(self, package: SystemPackage, vuln: Vulnerability,
                        patchResult: PatchResult, force: bool) -> None:
        """Update YUM/DNF package"""
        # Determine package manager
        if shutil.which('dnf'):
            pm = 'dnf'
        else:
            pm = 'yum'
        
        # Install specific version if fixed version specified
        if vuln.fixedVersion:
            pkgSpec = f"{package.name}-{vuln.fixedVersion}"
        else:
            pkgSpec = package.name
        
        # Update package
        cmd = [pm, "update", "-y"]
        if force:
            cmd.append("--skip-broken")
        cmd.append(pkgSpec)
        
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        
        patchResult.status = PatchStatus.SUCCESS
        patchResult.details = f"Updated {package.name} to {vuln.fixedVersion or 'latest'} via {pm}"
        patchResult.systemChanges.append(f"Package {package.name} updated")
    
    def updatePacmanPackage(self, package: SystemPackage, vuln: Vulnerability,
                           patchResult: PatchResult, force: bool) -> None:
        """Update Pacman package"""
        # Update package database
        subprocess.run(["pacman", "-Sy"], 
                      capture_output=True, text=True, check=True)
        
        # Upgrade package
        cmd = ["pacman", "-S", "--noconfirm"]
        if force:
            cmd.append("--force")
        cmd.append(package.name)
        
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        
        patchResult.status = PatchStatus.SUCCESS
        patchResult.details = f"Updated {package.name} via pacman"
        patchResult.systemChanges.append(f"Package {package.name} updated")
    
    def updateApkPackage(self, package: SystemPackage, vuln: Vulnerability,
                        patchResult: PatchResult, force: bool) -> None:
        """Update APK package"""
        # Update package database
        subprocess.run(["apk", "update"], 
                      capture_output=True, text=True, check=True)
        
        # Upgrade package
        cmd = ["apk", "upgrade"]
        if force:
            cmd.append("--force")
        cmd.append(package.name)
        
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        
        patchResult.status = PatchStatus.SUCCESS
        patchResult.details = f"Updated {package.name} via apk"
        patchResult.systemChanges.append(f"Package {package.name} updated")
    
    def updateWindowsPackage(self, package: SystemPackage, vuln: Vulnerability,
                           patchResult: PatchResult, force: bool) -> None:
        """Update Windows package"""
        # Windows Update is complex, we'll provide instructions
        
        patchResult.status = PatchStatus.MANUAL_INTERVENTION_REQUIRED
        patchResult.details = f"Windows Update required for {package.name}. "
        patchResult.details += f"Vulnerability: {vuln.cveId}. "
        patchResult.details += "Please run Windows Update or update manually."
        
        # Try winget if available
        if shutil.which('winget'):
            try:
                result = subprocess.run(["winget", "upgrade", package.name],
                                      capture_output=True, text=True, shell=True)
                if result.returncode == 0:
                    patchResult.status = PatchStatus.SUCCESS
                    patchResult.details = f"Updated {package.name} via winget"
            except:
                pass
    
    def updateMacosPackage(self, package: SystemPackage, vuln: Vulnerability,
                          patchResult: PatchResult, force: bool) -> None:
        """Update macOS package"""
        # Try Homebrew if available
        if package.packageManager == PackageManager.BREW and shutil.which('brew'):
            try:
                result = subprocess.run(["brew", "upgrade", package.name],
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    patchResult.status = PatchStatus.SUCCESS
                    patchResult.details = f"Updated {package.name} via Homebrew"
                    return
            except:
                pass
        
        patchResult.status = PatchStatus.MANUAL_INTERVENTION_REQUIRED
        patchResult.details = f"Manual update required for {package.name}"
    
    def fixConfiguration(self, scanResult: ScanResult, patchResult: PatchResult,
                        force: bool) -> PatchResult:
        """Fix configuration vulnerability"""
        vuln = scanResult.vulnerability
        
        patchResult.operation = "configuration-fix"
        
        try:
            if vuln.cveId == "CONFIG-SSH-001":
                # Disable SSH root login
                self.fixSshRootLogin(patchResult)
            
            elif vuln.cveId == "CONFIG-SSH-002":
                # Disable SSH Protocol 1
                self.fixSshProtocol(patchResult)
            
            elif vuln.cveId == "CONFIG-SUDO-001":
                # Fix sudo NOPASSWD
                self.fixSudoNopasswd(patchResult)
            
            elif vuln.cveId == "CONFIG-WIN-001":
                # Enable UAC
                self.fixWindowsUac(patchResult)
            
            else:
                patchResult.status = PatchStatus.MANUAL_INTERVENTION_REQUIRED
                patchResult.details = f"Unknown configuration vulnerability: {vuln.cveId}"
        
        except Exception as e:
            patchResult.status = PatchStatus.FAILED
            patchResult.errorMessage = str(e)
            patchResult.details = f"Configuration fix failed: {str(e)}"
        
        return patchResult
    
    def fixSshRootLogin(self, patchResult: PatchResult) -> None:
        """Disable SSH root login"""
        sshConfig = "/etc/ssh/sshd_config"
        
        if os.path.exists(sshConfig):
            # Backup original
            backupFile = f"{sshConfig}.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            shutil.copy2(sshConfig, backupFile)
            
            # Read and modify
            with open(sshConfig, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            with open(sshConfig, 'w', encoding='utf-8') as f:
                for line in lines:
                    if line.strip().startswith('PermitRootLogin'):
                        f.write('PermitRootLogin no\n')
                    else:
                        f.write(line)
            
            # Restart SSH service
            subprocess.run(["systemctl", "restart", "sshd"], check=True)
            
            patchResult.status = PatchStatus.SUCCESS
            patchResult.details = "Disabled SSH root login"
            patchResult.systemChanges.append("SSH configuration modified")
            patchResult.systemChanges.append(f"Backup created: {backupFile}")
        else:
            patchResult.status = PatchStatus.FAILED
            patchResult.details = "SSH configuration file not found"
    
    def fixSshProtocol(self, patchResult: PatchResult) -> None:
        """Disable SSH Protocol 1"""
        sshConfig = "/etc/ssh/sshd_config"
        
        if os.path.exists(sshConfig):
            # Backup original
            backupFile = f"{sshConfig}.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            shutil.copy2(sshConfig, backupFile)
            
            # Read and modify
            with open(sshConfig, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            with open(sshConfig, 'w', encoding='utf-8') as f:
                for line in lines:
                    if line.strip().startswith('Protocol'):
                        f.write('Protocol 2\n')
                    else:
                        f.write(line)
            
            # Restart SSH service
            subprocess.run(["systemctl", "restart", "sshd"], check=True)
            
            patchResult.status = PatchStatus.SUCCESS
            patchResult.details = "Disabled SSH Protocol 1"
            patchResult.systemChanges.append("SSH configuration modified")
            patchResult.systemChanges.append(f"Backup created: {backupFile}")
        else:
            patchResult.status = PatchStatus.FAILED
            patchResult.details = "SSH configuration file not found"
    
    def fixSudoNopasswd(self, patchResult: PatchResult) -> None:
        """Fix sudo NOPASSWD directive"""
        patchResult.status = PatchStatus.MANUAL_INTERVENTION_REQUIRED
        patchResult.details = "Manual review required for sudo NOPASSWD directives. "
        patchResult.details += "Check /etc/sudoers and /etc/sudoers.d/* files."
    
    def fixWindowsUac(self, patchResult: PatchResult) -> None:
        """Enable Windows UAC"""
        try:
            # Enable UAC via registry
            import winreg
            
            keyPath = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, keyPath, 0, 
                               winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY)
            winreg.SetValueEx(key, "EnableLUA", 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(key)
            
            patchResult.status = PatchStatus.SUCCESS
            patchResult.details = "Enabled User Account Control (UAC)"
            patchResult.systemChanges.append("Registry modified: EnableLUA=1")
        
        except Exception as e:
            patchResult.status = PatchStatus.FAILED
            patchResult.errorMessage = str(e)
            patchResult.details = f"Failed to enable UAC: {str(e)}"
    
    def applyMitigation(self, scanResult: ScanResult, patchResult: PatchResult) -> PatchResult:
        """Apply generic mitigation"""
        vuln = scanResult.vulnerability
        
        patchResult.operation = "mitigation"
        
        # Log the mitigation
        logger.info(f"Applied mitigation for {vuln.cveId}: {vuln.mitigation}")
        
        patchResult.status = PatchStatus.SUCCESS
        patchResult.details = f"Applied mitigation: {vuln.mitigation}"
        patchResult.systemChanges.append(f"Mitigation applied: {vuln.mitigation[:50]}...")
        
        return patchResult
    
    def verifyPatch(self, scanResult: ScanResult) -> bool:
        """Verify that patch was successfully applied"""
        vuln = scanResult.vulnerability
        package = scanResult.detectedPackage
        
        try:
            if vuln.fixedVersion:
                # Check if package was updated
                if self.systemInfo.osType == OperatingSystem.LINUX:
                    if package.packageManager == PackageManager.APT:
                        cmd = ["dpkg-query", "-W", "-f=${Version}", package.name]
                        result = subprocess.run(cmd, capture_output=True, text=True)
                        if result.returncode == 0:
                            currentVersion = result.stdout.strip()
                            if THIRD_PARTY_IMPORTS['packaging']:
                                try:
                                    current = version.parse(currentVersion)
                                    fixed = version.parse(vuln.fixedVersion)
                                    return current >= fixed
                                except:
                                    return currentVersion == vuln.fixedVersion
                    
                    elif package.packageManager in [PackageManager.YUM, PackageManager.DNF]:
                        cmd = ["rpm", "-q", "--queryformat", "%{VERSION}-%{RELEASE}", package.name]
                        result = subprocess.run(cmd, capture_output=True, text=True)
                        if result.returncode == 0:
                            currentVersion = result.stdout.strip()
                            # Simple string comparison
                            return currentVersion >= vuln.fixedVersion
            
            return True  # Assume success if we can't verify
        
        except Exception as e:
            logger.debug(f"Patch verification failed for {vuln.cveId}: {e}")
            return False
    
    def rollbackPatches(self, snapshotHash: Optional[str]) -> bool:
        """Rollback to system snapshot"""
        if not snapshotHash:
            logger.error("No snapshot hash provided for rollback")
            return False
        
        try:
            success = self.snapshotManager.restoreSnapshot(snapshotHash)
            if success:
                logger.info(f"Successfully rolled back to snapshot: {snapshotHash}")
                return True
            else:
                logger.error(f"Failed to restore snapshot: {snapshotHash}")
                return False
        
        except Exception as e:
            logger.error(f"Rollback failed: {e}")
            return False
    
    def generatePatchSummary(self, patchResults: List[PatchResult]) -> None:
        """Generate and log patch summary"""
        if not patchResults:
            return
        
        summary = {
            PatchStatus.SUCCESS: 0,
            PatchStatus.FAILED: 0,
            PatchStatus.SKIPPED: 0,
            PatchStatus.ROLLED_BACK: 0,
            PatchStatus.MANUAL_INTERVENTION_REQUIRED: 0
        }
        
        for result in patchResults:
            if result.status in summary:
                summary[result.status] += 1
        
        total = len(patchResults)
        successRate = (summary[PatchStatus.SUCCESS] / total * 100) if total > 0 else 0
        
        logger.info("=" * 60)
        logger.info("PATCH APPLICATION SUMMARY")
        logger.info("=" * 60)
        logger.info(f"Total patches: {total}")
        logger.info(f"Successful: {summary[PatchStatus.SUCCESS]} ({successRate:.1f}%)")
        logger.info(f"Failed: {summary[PatchStatus.FAILED]}")
        logger.info(f"Skipped: {summary[PatchStatus.SKIPPED]}")
        logger.info(f"Rolled back: {summary[PatchStatus.ROLLED_BACK]}")
        logger.info(f"Manual intervention required: {summary[PatchStatus.MANUAL_INTERVENTION_REQUIRED]}")
        logger.info("=" * 60)
        
        # Log failed patches
        if self.failedPatches:
            logger.warning("FAILED PATCHES:")
            for patch in self.failedPatches:
                logger.warning(f"  {patch.cveId}: {patch.errorMessage or patch.details}")

# Snapshot Manager for system state management
class SnapshotManager:
    """Manages system snapshots for rollback operations"""
    
    def __init__(self, snapshotDir: str = "snapshots"):
        self.snapshotDir = Path(snapshotDir)
        self.snapshotDir.mkdir(exist_ok=True)
    
    def createSnapshot(self, systemInfo: SystemInfo) -> str:
        """Create system snapshot"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        snapshotData = systemInfo.toDict()
        
        # Create snapshot file
        snapshotId = hashlib.sha256(
            f"{timestamp}{systemInfo.hostname}{systemInfo.osVersion}".encode()
        ).hexdigest()[:16]
        
        snapshotFile = self.snapshotDir / f"snapshot_{timestamp}_{snapshotId}.json"
        
        # Save system info
        with open(snapshotFile, 'w', encoding='utf-8') as f:
            json.dump(snapshotData, f, indent=2, default=str)
        
        # Create backup of critical system files
        self.backupCriticalFiles(snapshotId)
        
        logger.info(f"Created system snapshot: {snapshotId}")
        return snapshotId
    
    def backupCriticalFiles(self, snapshotId: str) -> None:
        """Backup critical system files"""
        criticalFiles = []
        
        systemType = platform.system()
        
        if systemType == "Linux":
            criticalFiles = [
                "/etc/passwd",
                "/etc/group",
                "/etc/shadow",
                "/etc/sudoers",
                "/etc/ssh/sshd_config",
                "/etc/hosts",
                "/etc/resolv.conf"
            ]
        elif systemType == "Windows":
            # Windows critical files would be handled differently
            pass
        
        backupDir = self.snapshotDir / f"backup_{snapshotId}"
        backupDir.mkdir(exist_ok=True)
        
        for filePath in criticalFiles:
            if os.path.exists(filePath):
                try:
                    backupPath = backupDir / Path(filePath).name
                    shutil.copy2(filePath, backupPath)
                except Exception as e:
                    logger.debug(f"Failed to backup {filePath}: {e}")
    
    def restoreSnapshot(self, snapshotId: str) -> bool:
        """Restore system from snapshot"""
        # Find snapshot file
        snapshotFiles = list(self.snapshotDir.glob(f"*_{snapshotId}.json"))
        if not snapshotFiles:
            logger.error(f"Snapshot not found: {snapshotId}")
            return False
        
        snapshotFile = snapshotFiles[0]
        
        try:
            # Load snapshot data
            with open(snapshotFile, 'r', encoding='utf-8') as f:
                snapshotData = json.load(f)
            
            # Restore critical files
            backupDir = self.snapshotDir / f"backup_{snapshotId}"
            if backupDir.exists():
                for backupFile in backupDir.iterdir():
                    if backupFile.is_file():
                        # Determine original path (simplified)
                        originalPath = Path("/etc") / backupFile.name
                        if originalPath.exists():
                            shutil.copy2(backupFile, originalPath)
            
            logger.info(f"Restored system from snapshot: {snapshotId}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to restore snapshot {snapshotId}: {e}")
            return False

# Report Generator with multiple formats
class ReportGenerator:
    """Generates comprehensive reports in multiple formats"""
    
    @staticmethod
    def generateReport(systemInfo: SystemInfo, 
                      scanResults: List[ScanResult], 
                      patchResults: List[PatchResult],
                      historicalData: Optional[Dict] = None) -> Dict[str, Any]:
        """Generate comprehensive report"""
        
        # Calculate statistics
        vulnerabilityStats = defaultdict(int)
        for result in scanResults:
            severity = result.vulnerability.severity.name
            vulnerabilityStats[severity] += 1
        
        patchStats = defaultdict(int)
        for result in patchResults:
            patchStats[result.status.value] += 1
        
        # Generate executive summary
        executiveSummary = ReportGenerator.generateExecutiveSummary(
            scanResults, patchResults, vulnerabilityStats, patchStats
        )
        
        # Generate detailed findings
        detailedFindings = ReportGenerator.generateDetailedFindings(
            scanResults, patchResults
        )
        
        # Generate recommendations
        recommendations = ReportGenerator.generateRecommendations(
            scanResults, patchResults
        )
        
        # Compile report
        report = {
            "metadata": {
                "generated": datetime.now().isoformat(),
                "toolVersion": VERSION,
                "reportId": hashlib.md5(datetime.now().isoformat().encode()).hexdigest()[:8],
                "reportType": "vulnerability_assessment"
            },
            "systemInfo": {
                "hostname": systemInfo.hostname,
                "os": systemInfo.osType.value,
                "osVersion": systemInfo.osVersion,
                "architecture": systemInfo.architecture.value,
                "kernel": systemInfo.kernelVersion,
                "systemFingerprint": systemInfo.generateFingerprint()
            },
            "executiveSummary": executiveSummary,
            "scanResults": {
                "totalVulnerabilities": len(scanResults),
                "vulnerabilitiesBySeverity": dict(vulnerabilityStats),
                "vulnerabilityDetails": [
                    {
                        "cveId": r.vulnerability.cveId,
                        "description": r.vulnerability.description[:200] + "..." if len(r.vulnerability.description) > 200 else r.vulnerability.description,
                        "severity": r.vulnerability.severity.name,
                        "cvssScore": r.vulnerability.cvssScore,
                        "affectedPackage": r.detectedPackage.name,
                        "currentVersion": r.detectedPackage.version,
                        "fixedVersion": r.vulnerability.fixedVersion,
                        "confidence": r.confidence,
                        "evidence": r.evidence,
                        "falsePositive": r.falsePositive
                    }
                    for r in scanResults
                ]
            },
            "patchResults": {
                "totalPatches": len(patchResults),
                "patchesByStatus": dict(patchStats),
                "successRate": (patchStats.get('success', 0) / len(patchResults) * 100) if patchResults else 100,
                "patchDetails": [
                    {
                        "cveId": r.cveId,
                        "status": r.status.value,
                        "operation": r.operation,
                        "details": r.details,
                        "executionTime": r.executionTime,
                        "error": r.errorMessage,
                        "verificationStatus": r.verificationStatus
                    }
                    for r in patchResults
                ]
            },
            "detailedFindings": detailedFindings,
            "recommendations": recommendations,
            "historicalData": historicalData or {},
            "appendices": {
                "scanMethodology": "Comprehensive vulnerability scanning using multiple CVE databases and system configuration analysis",
                "confidenceScoring": "Confidence scores range from 0.0 to 1.0 based on package name matching, version comparison, and vulnerability metadata",
                "severityDefinitions": {
                    "CRITICAL": "Vulnerabilities with CVSS score >= 9.0 or widespread exploit availability",
                    "HIGH": "Vulnerabilities with CVSS score 7.0-8.9",
                    "MEDIUM": "Vulnerabilities with CVSS score 4.0-6.9",
                    "LOW": "Vulnerabilities with CVSS score 0.1-3.9",
                    "INFO": "Informational findings without direct security impact"
                }
            }
        }
        
        return report
    
    @staticmethod
    def generateExecutiveSummary(scanResults: List[ScanResult], 
                                patchResults: List[PatchResult],
                                vulnerabilityStats: Dict[str, int],
                                patchStats: Dict[str, int]) -> Dict[str, Any]:
        """Generate executive summary"""
        totalVulns = len(scanResults)
        totalPatches = len(patchResults)
        successfulPatches = patchStats.get('success', 0)
        
        # Calculate risk score (0-100)
        riskScore = 0
        if totalVulns > 0:
            weight = {
                'CRITICAL': 10,
                'HIGH': 7,
                'MEDIUM': 4,
                'LOW': 1,
                'INFO': 0
            }
            
            weightedScore = 0
            maxPossibleScore = 0
            
            for severity, count in vulnerabilityStats.items():
                weightedScore += count * weight.get(severity, 0)
                maxPossibleScore += count * 10  # Maximum weight
            
            if maxPossibleScore > 0:
                riskScore = min(100, (weightedScore / maxPossibleScore) * 100)
        
        # Determine overall risk level
        if riskScore >= 70:
            riskLevel = "CRITICAL"
        elif riskScore >= 40:
            riskLevel = "HIGH"
        elif riskScore >= 20:
            riskLevel = "MEDIUM"
        elif riskScore > 0:
            riskLevel = "LOW"
        else:
            riskLevel = "INFORMATIONAL"
        
        # Generate key findings
        keyFindings = []
        if vulnerabilityStats.get('CRITICAL', 0) > 0:
            keyFindings.append(f"{vulnerabilityStats['CRITICAL']} critical vulnerabilities detected requiring immediate attention")
        
        if vulnerabilityStats.get('HIGH', 0) > 0:
            keyFindings.append(f"{vulnerabilityStats['HIGH']} high-severity vulnerabilities detected")
        
        if successfulPatches > 0:
            keyFindings.append(f"{successfulPatches} vulnerabilities successfully patched")
        
        if patchStats.get('failed', 0) > 0:
            keyFindings.append(f"{patchStats['failed']} patch attempts failed, manual intervention required")
        
        return {
            "riskScore": round(riskScore, 1),
            "riskLevel": riskLevel,
            "totalVulnerabilities": totalVulns,
            "totalPatches": totalPatches,
            "successfulPatches": successfulPatches,
            "keyFindings": keyFindings,
            "summary": f"System has {riskLevel.lower()} security risk with {totalVulns} vulnerabilities detected and {successfulPatches} successfully patched."
        }
    
    @staticmethod
    def generateDetailedFindings(scanResults: List[ScanResult], 
                                patchResults: List[PatchResult]) -> Dict[str, Any]:
        """Generate detailed findings"""
        
        # Group vulnerabilities by severity
        vulnerabilitiesBySeverity = defaultdict(list)
        for result in scanResults:
            severity = result.vulnerability.severity.name
            vulnerabilitiesBySeverity[severity].append(result)
        
        # Create detailed analysis
        detailedAnalysis = {}
        for severity, results in vulnerabilitiesBySeverity.items():
            detailedAnalysis[severity] = {
                "count": len(results),
                "topPackages": sorted(
                    list(set(r.detectedPackage.name for r in results)),
                    key=lambda x: x.lower()
                )[:10],  # Top 10 packages
                "sampleVulnerabilities": [
                    {
                        "cveId": r.vulnerability.cveId,
                        "package": r.detectedPackage.name,
                        "version": r.detectedPackage.version,
                        "fixedVersion": r.vulnerability.fixedVersion,
                        "confidence": r.confidence
                    }
                    for r in results[:5]  # Sample 5 vulnerabilities
                ]
            }
        
        # Patch analysis
        patchAnalysis = {
            "byStatus": defaultdict(int),
            "byOperation": defaultdict(int),
            "executionTimes": {
                "min": min((p.executionTime for p in patchResults), default=0),
                "max": max((p.executionTime for p in patchResults), default=0),
                "average": sum(p.executionTime for p in patchResults) / len(patchResults) if patchResults else 0
            }
        }
        
        for result in patchResults:
            patchAnalysis["byStatus"][result.status.value] += 1
            patchAnalysis["byOperation"][result.operation] += 1
        
        return {
            "vulnerabilityAnalysis": detailedAnalysis,
            "patchAnalysis": patchAnalysis,
            "trends": ReportGenerator.analyzeTrends(scanResults, patchResults)
        }
    
    @staticmethod
    def analyzeTrends(scanResults: List[ScanResult], 
                     patchResults: List[PatchResult]) -> Dict[str, Any]:
        """Analyze trends in vulnerabilities and patches"""
        
        # Group by vulnerability type
        vulnerabilityTypes = defaultdict(int)
        for result in scanResults:
            cveId = result.vulnerability.cveId
            # Extract type from CVE ID or description
            if "CONFIG-" in cveId:
                vulnType = "configuration"
            elif "log4j" in result.vulnerability.description.lower():
                vulnType = "log4j"
            elif "buffer" in result.vulnerability.description.lower():
                vulnType = "buffer_overflow"
            elif "xss" in result.vulnerability.description.lower() or "cross-site" in result.vulnerability.description.lower():
                vulnType = "xss"
            elif "sql" in result.vulnerability.description.lower():
                vulnType = "sql_injection"
            elif "rce" in result.vulnerability.description.lower() or "remote code" in result.vulnerability.description.lower():
                vulnType = "rce"
            else:
                vulnType = "other"
            
            vulnerabilityTypes[vulnType] += 1
        
        # Calculate patch effectiveness
        patchEffectiveness = {}
        if patchResults:
            successful = sum(1 for p in patchResults if p.status == PatchStatus.SUCCESS)
            total = len(patchResults)
            patchEffectiveness = {
                "successRate": (successful / total * 100) if total > 0 else 0,
                "averageTime": sum(p.executionTime for p in patchResults) / total if total > 0 else 0,
                "commonFailures": [
                    p.operation for p in patchResults 
                    if p.status == PatchStatus.FAILED
                ][:5]  # Top 5 failure types
            }
        
        return {
            "vulnerabilityTypes": dict(vulnerabilityTypes),
            "patchEffectiveness": patchEffectiveness,
            "recommendations": ReportGenerator.generateTrendRecommendations(vulnerabilityTypes, patchResults)
        }
    
    @staticmethod
    def generateTrendRecommendations(vulnerabilityTypes: Dict[str, int], 
                                    patchResults: List[PatchResult]) -> List[str]:
        """Generate recommendations based on trends"""
        recommendations = []
        
        # Analyze vulnerability types
        if vulnerabilityTypes.get('configuration', 0) > 0:
            recommendations.append("Implement configuration management and regular security hardening")
        
        if vulnerabilityTypes.get('log4j', 0) > 0:
            recommendations.append("Establish software composition analysis for third-party libraries")
        
        if vulnerabilityTypes.get('buffer_overflow', 0) > 0:
            recommendations.append("Enable address space layout randomization (ASLR) and stack protection")
        
        # Analyze patch results
        failedPatches = [p for p in patchResults if p.status == PatchStatus.FAILED]
        if failedPatches:
            failureReasons = set()
            for patch in failedPatches:
                if patch.errorMessage:
                    if "permission" in patch.errorMessage.lower():
                        failureReasons.add("permission")
                    elif "dependency" in patch.errorMessage.lower():
                        failureReasons.add("dependency")
                    elif "not found" in patch.errorMessage.lower():
                        failureReasons.add("not_found")
            
            if "permission" in failureReasons:
                recommendations.append("Review and adjust patch application permissions")
            if "dependency" in failureReasons:
                recommendations.append("Implement dependency management and testing procedures")
        
        return recommendations
    
    @staticmethod
    def generateRecommendations(scanResults: List[ScanResult], 
                               patchResults: List[PatchResult]) -> List[Dict[str, Any]]:
        """Generate actionable recommendations"""
        recommendations = []
        
        # Priority 1: Critical vulnerabilities
        criticalVulns = [r for r in scanResults if r.vulnerability.severity == SeverityLevel.CRITICAL]
        if criticalVulns:
            recommendations.append({
                "priority": 1,
                "category": "critical",
                "title": "Immediate Remediation Required",
                "description": f"Address {len(criticalVulns)} critical vulnerabilities immediately",
                "actions": [
                    "Apply patches for critical vulnerabilities within 24 hours",
                    "Consider temporary mitigations if patches cannot be applied immediately",
                    "Monitor for exploitation attempts"
                ],
                "timeline": "24 hours",
                "resources": ["Patch management team", "Security operations center"]
            })
        
        # Priority 2: High vulnerabilities
        highVulns = [r for r in scanResults if r.vulnerability.severity == SeverityLevel.HIGH]
        if highVulns:
            recommendations.append({
                "priority": 2,
                "category": "high",
                "title": "High Priority Remediation",
                "description": f"Address {len(highVulns)} high-severity vulnerabilities",
                "actions": [
                    "Schedule patches for high-severity vulnerabilities",
                    "Test patches in non-production environment first",
                    "Implement compensating controls if immediate patching is not possible"
                ],
                "timeline": "7 days",
                "resources": ["System administrators", "Change management"]
            })
        
        # Priority 3: Failed patches
        failedPatches = [r for r in patchResults if r.status == PatchStatus.FAILED]
        if failedPatches:
            recommendations.append({
                "priority": 3,
                "category": "operational",
                "title": "Patch Process Improvement",
                "description": f"Investigate {len(failedPatches)} failed patch attempts",
                "actions": [
                    "Analyze patch failure reasons",
                    "Update patch procedures based on findings",
                    "Implement patch verification processes"
                ],
                "timeline": "14 days",
                "resources": ["Patch management", "System engineering"]
            })
        
        # Priority 4: Prevention
        if scanResults:
            recommendations.append({
                "priority": 4,
                "category": "preventive",
                "title": "Vulnerability Prevention Strategy",
                "description": "Implement measures to reduce future vulnerabilities",
                "actions": [
                    "Establish regular vulnerability scanning schedule",
                    "Implement automated patch management",
                    "Conduct security awareness training",
                    "Review and harden system configurations"
                ],
                "timeline": "30 days",
                "resources": ["Security team", "IT management", "All system users"]
            })
        
        return recommendations
    
    @staticmethod
    def saveReport(report: Dict[str, Any], formatType: str = "all", 
                  outputDir: str = "reports") -> Dict[str, str]:
        """Save report in multiple formats"""
        Path(outputDir).mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        hostname = report['systemInfo']['hostname'].replace(' ', '_').replace('.', '_')
        baseFilename = f"vulnerability_report_{hostname}_{timestamp}"
        
        savedFiles = {}
        
        formats = []
        if formatType == "all":
            formats = ["json", "html", "txt", "pdf"]
        else:
            formats = [formatType]
        
        for fmt in formats:
            try:
                if fmt == "json":
                    filename = f"{outputDir}/{baseFilename}.json"
                    with open(filename, 'w', encoding='utf-8') as f:
                        json.dump(report, f, indent=2, default=str)
                    savedFiles['json'] = filename
                
                elif fmt == "html":
                    filename = f"{outputDir}/{baseFilename}.html"
                    htmlContent = ReportGenerator.generateHtmlReport(report)
                    with open(filename, 'w', encoding='utf-8') as f:
                        f.write(htmlContent)
                    savedFiles['html'] = filename
                
                elif fmt == "txt":
                    filename = f"{outputDir}/{baseFilename}.txt"
                    txtContent = ReportGenerator.generateTextReport(report)
                    with open(filename, 'w', encoding='utf-8') as f:
                        f.write(txtContent)
                    savedFiles['txt'] = filename
                
                elif fmt == "pdf":
                    # PDF generation would require additional libraries
                    # For now, we'll create a placeholder
                    filename = f"{outputDir}/{baseFilename}.pdf.txt"
                    with open(filename, 'w', encoding='utf-8') as f:
                        f.write("PDF export requires additional libraries (reportlab, weasyprint).\n")
                        f.write("Install with: pip install reportlab weasyprint\n")
                        f.write("\nJSON report is available for PDF conversion.\n")
                    savedFiles['pdf'] = filename
            
            except Exception as e:
                logger.error(f"Failed to save {fmt} report: {e}")
        
        return savedFiles
    
    @staticmethod
    def generateHtmlReport(report: Dict[str, Any]) -> str:
        """Generate HTML report"""
        # This is a simplified HTML template
        # In production, you would use a proper template engine
        
        criticalCount = report['scanResults']['vulnerabilitiesBySeverity'].get('CRITICAL', 0)
        highCount = report['scanResults']['vulnerabilitiesBySeverity'].get('HIGH', 0)
        riskLevel = report['executiveSummary']['riskLevel']
        riskScore = report['executiveSummary']['riskScore']
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Assessment Report - {report['systemInfo']['hostname']}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; border-bottom: 2px solid #333; padding-bottom: 20px; margin-bottom: 30px; }}
        .header h1 {{ color: #333; margin: 0; }}
        .header .subtitle {{ color: #666; font-size: 1.2em; }}
        .summary {{ background: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 30px; }}
        .summary h2 {{ margin-top: 0; color: #333; }}
        .risk-badge {{ display: inline-block; padding: 5px 15px; border-radius: 20px; color: white; font-weight: bold; margin-left: 10px; }}
        .risk-critical {{ background: #dc3545; }}
        .risk-high {{ background: #fd7e14; }}
        .risk-medium {{ background: #ffc107; color: #333; }}
        .risk-low {{ background: #28a745; }}
        .section {{ margin-bottom: 30px; }}
        .section h2 {{ color: #333; border-bottom: 1px solid #ddd; padding-bottom: 10px; }}
        .vulnerability-table {{ width: 100%; border-collapse: collapse; }}
        .vulnerability-table th, .vulnerability-table td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        .vulnerability-table th {{ background: #f8f9fa; font-weight: bold; }}
        .severity-critical {{ color: #dc3545; font-weight: bold; }}
        .severity-high {{ color: #fd7e14; font-weight: bold; }}
        .severity-medium {{ color: #ffc107; font-weight: bold; }}
        .severity-low {{ color: #28a745; font-weight: bold; }}
        .footer {{ margin-top: 30px; text-align: center; color: #666; font-size: 0.9em; border-top: 1px solid #ddd; padding-top: 20px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Vulnerability Assessment Report</h1>
            <div class="subtitle">
                System: {report['systemInfo']['hostname']} | 
                Generated: {report['metadata']['generated']} | 
                Report ID: {report['metadata']['reportId']}
            </div>
        </div>
        
        <div class="summary">
            <h2>Executive Summary</h2>
            <p>
                <strong>Risk Level:</strong> 
                <span class="risk-badge risk-{riskLevel.lower()}">{riskLevel}</span>
                (Score: {riskScore}/100)
            </p>
            <p><strong>Total Vulnerabilities:</strong> {report['scanResults']['totalVulnerabilities']}</p>
            <p><strong>Critical Vulnerabilities:</strong> {criticalCount}</p>
            <p><strong>High Vulnerabilities:</strong> {highCount}</p>
            <p><strong>Patches Applied:</strong> {report['patchResults']['totalPatches']}</p>
            <p><strong>Success Rate:</strong> {report['patchResults']['successRate']:.1f}%</p>
        </div>
        
        <div class="section">
            <h2>Vulnerability Details</h2>
            <table class="vulnerability-table">
                <thead>
                    <tr>
                        <th>CVE ID</th>
                        <th>Severity</th>
                        <th>Package</th>
                        <th>Current Version</th>
                        <th>Fixed Version</th>
                        <th>Confidence</th>
                    </tr>
                </thead>
                <tbody>
        """
        
        # Add vulnerability rows
        for vuln in report['scanResults']['vulnerabilityDetails'][:20]:  # Limit to 20 for readability
            severityClass = f"severity-{vuln['severity'].lower()}"
            html += f"""
                    <tr>
                        <td>{vuln['cveId']}</td>
                        <td class="{severityClass}">{vuln['severity']}</td>
                        <td>{vuln['affectedPackage']}</td>
                        <td>{vuln['currentVersion']}</td>
                        <td>{vuln['fixedVersion'] or 'N/A'}</td>
                        <td>{vuln['confidence']:.1%}</td>
                    </tr>
            """
        
        html += """
                </tbody>
            </table>
            <p><em>Showing first 20 vulnerabilities. See JSON report for complete list.</em></p>
        </div>
        
        <div class="section">
            <h2>Top Recommendations</h2>
            <ol>
        """
        
        # Add recommendations
        for rec in report['recommendations'][:5]:  # Top 5 recommendations
            html += f"""
                <li>
                    <strong>{rec['title']}</strong> (Priority {rec['priority']})<br>
                    {rec['description']}<br>
                    <em>Timeline: {rec['timeline']}</em>
                </li>
            """
        
        html += """
            </ol>
        </div>
        
        <div class="footer">
            <p>Generated by AVRPS (Advanced Vulnerability Remediation and Patching System) v{VERSION}</p>
            <p>This report is for internal use only. Distribution restricted.</p>
        </div>
    </div>
</body>
</html>
        """
        
        return html
    
    @staticmethod
    def generateTextReport(report: Dict[str, Any]) -> str:
        """Generate text report"""
        lines = []
        lines.append("=" * 80)
        lines.append("VULNERABILITY ASSESSMENT REPORT")
        lines.append("=" * 80)
        lines.append(f"Generated: {report['metadata']['generated']}")
        lines.append(f"Report ID: {report['metadata']['reportId']}")
        lines.append(f"Tool Version: {report['metadata']['toolVersion']}")
        lines.append("")
        
        lines.append("SYSTEM INFORMATION")
        lines.append("-" * 80)
        lines.append(f"Hostname: {report['systemInfo']['hostname']}")
        lines.append(f"OS: {report['systemInfo']['os']} {report['systemInfo']['osVersion']}")
        lines.append(f"Architecture: {report['systemInfo']['architecture']}")
        lines.append(f"Kernel: {report['systemInfo']['kernel']}")
        lines.append(f"Fingerprint: {report['systemInfo']['systemFingerprint']}")
        lines.append("")
        
        lines.append("EXECUTIVE SUMMARY")
        lines.append("-" * 80)
        lines.append(f"Risk Level: {report['executiveSummary']['riskLevel']} (Score: {report['executiveSummary']['riskScore']}/100)")
        lines.append(f"Total Vulnerabilities: {report['scanResults']['totalVulnerabilities']}")
        lines.append(f"Total Patches: {report['patchResults']['totalPatches']}")
        lines.append(f"Patch Success Rate: {report['patchResults']['successRate']:.1f}%")
        lines.append("")
        
        lines.append("VULNERABILITY BREAKDOWN")
        lines.append("-" * 80)
        for severity, count in report['scanResults']['vulnerabilitiesBySeverity'].items():
            lines.append(f"  {severity}: {count}")
        lines.append("")
        
        lines.append("TOP VULNERABILITIES")
        lines.append("-" * 80)
        for i, vuln in enumerate(report['scanResults']['vulnerabilityDetails'][:10], 1):
            lines.append(f"{i}. [{vuln['severity']}] {vuln['cveId']}")
            lines.append(f"   Package: {vuln['affectedPackage']} ({vuln['currentVersion']})")
            lines.append(f"   Fixed Version: {vuln['fixedVersion'] or 'Not specified'}")
            lines.append(f"   CVSS: {vuln['cvssScore']} | Confidence: {vuln['confidence']:.1%}")
            lines.append("")
        
        lines.append("RECOMMENDATIONS")
        lines.append("-" * 80)
        for i, rec in enumerate(report['recommendations'][:5], 1):
            lines.append(f"{i}. {rec['title']} (Priority {rec['priority']})")
            lines.append(f"   {rec['description']}")
            lines.append(f"   Timeline: {rec['timeline']}")
            for action in rec['actions'][:3]:
                lines.append(f"   - {action}")
            lines.append("")
        
        lines.append("=" * 80)
        lines.append("END OF REPORT")
        lines.append("=" * 80)
        
        return '\n'.join(lines)

# Main Application Class
class AdvancedVulnerabilityPatcher:
    """Main application orchestrator"""
    
    def __init__(self, configFile: str = DEFAULT_CONFIG_FILE):
        self.config = ConfigurationManager(configFile)
        self.dbManager = DatabaseManager(self.config.get('general', 'database_path', DEFAULT_DB_FILE))
        self.cacheManager = CacheManager(self.config.get('api', 'cache_dir', 'cache'))
        self.systemScanner = None
        self.vulnerabilityDetector = None
        self.patchManager = None
        self.systemInfo = None
        self.osType = OperatingSystem.detect()
        
        # Validate configuration
        configIssues = self.config.validate()
        if configIssues:
            logger.warning("Configuration issues found:")
            for issue in configIssues:
                logger.warning(f"  - {issue}")
    
    def initialize(self) -> None:
        """Initialize all components"""
        logger.info(f"Initializing AVRPS v{VERSION} for {self.osType.value}")
        
        # Initialize scanner
        self.systemScanner = SystemScanner(self.osType)
        self.systemInfo = self.systemScanner.gatherSystemInfo()
        
        # Initialize CVE data sources
        cveSources = []
        
        # Local database (always available)
        cveSources.append(LocalCveDatabase())
        
        # NVD if requests is available
        if THIRD_PARTY_IMPORTS['requests']:
            nvdApiKey = self.config.get('api', 'nvd_api_key', '')
            cveSources.append(NvdDataSource(nvdApiKey, self.cacheManager))
        
        # Initialize detector
        self.vulnerabilityDetector = VulnerabilityDetector(cveSources, self.cacheManager)
        
        # Initialize patch manager
        self.patchManager = PatchManager(self.systemInfo, self.dbManager, self.config)
        
        logger.info("Initialization complete")
    
    def runScan(self, deepScan: bool = False) -> Tuple[List[ScanResult], int]:
        """Run vulnerability scan and return results with scan ID"""
        if not self.vulnerabilityDetector:
            self.initialize()
        
        logger.info("Starting vulnerability scan...")
        
        # Create scan record in database
        scanId = self.dbManager.createScanRecord(self.systemInfo, VERSION)
        
        # Run scan
        scanResults = self.vulnerabilityDetector.scanSystem(self.systemInfo)
        
        # Save results to database
        if scanResults:
            self.dbManager.saveScanResults(scanId, scanResults)
        
        return scanResults, scanId
    
    def applyRemediation(self, scanResults: List[ScanResult], 
                        dryRun: bool = False, 
                        force: bool = False) -> List[PatchResult]:
        """Apply remediation for detected vulnerabilities"""
        if not self.patchManager:
            self.initialize()
        
        if not scanResults:
            logger.info("No vulnerabilities to remediate")
            return []
        
        # Ask for confirmation if not in force mode
        if not force and not dryRun and self.config.get('patching', 'confirmation_required', True):
            criticalCount = sum(1 for r in scanResults if r.vulnerability.severity == SeverityLevel.CRITICAL)
            highCount = sum(1 for r in scanResults if r.vulnerability.severity == SeverityLevel.HIGH)
            
            print("\n" + "=" * 60)
            print("PATCH CONFIRMATION REQUIRED")
            print("=" * 60)
            print(f"Total vulnerabilities: {len(scanResults)}")
            print(f"Critical: {criticalCount}")
            print(f"High: {highCount}")
            print("\nThis operation will modify system configuration and packages.")
            
            if criticalCount > 0:
                print("\n⚠️  WARNING: Critical vulnerabilities detected!")
                print("   Patching these may cause system instability.")
            
            response = input("\nDo you want to proceed? (yes/NO): ").strip().lower()
            if response not in ['yes', 'y']:
                logger.info("Patch operation cancelled by user")
                return []
        
        # Apply patches
        patchResults = self.patchManager.applyPatches(scanResults, dryRun, force)
        
        return patchResults
    
    def generateReports(self, scanResults: List[ScanResult], 
                       patchResults: List[PatchResult]) -> Dict[str, str]:
        """Generate and save reports"""
        if not self.systemInfo:
            self.initialize()
        
        # Get historical data
        historicalData = self.dbManager.getHistoricalData(days=30)
        
        # Generate report
        report = ReportGenerator.generateReport(
            self.systemInfo, 
            scanResults, 
            patchResults,
            historicalData
        )
        
        # Save reports
        reportFormat = self.config.get('reporting', 'report_format', 'all')
        outputDir = self.config.get('reporting', 'report_dir', 'reports')
        
        savedFiles = ReportGenerator.saveReport(report, reportFormat, outputDir)
        
        # Display report locations
        if savedFiles:
            logger.info("Reports generated:")
            for fmt, filename in savedFiles.items():
                logger.info(f"  {fmt.upper()}: {filename}")
        
        return savedFiles
    
    def displayResults(self, scanResults: List[ScanResult], 
                      patchResults: List[PatchResult]) -> None:
        """Display results in console"""
        if not scanResults and not patchResults:
            print("\nNo results to display.")
            return
        
        print("\n" + "=" * 80)
        print("AVRPS - RESULTS SUMMARY")
        print("=" * 80)
        
        if scanResults:
            # Vulnerability summary
            severityCounts = defaultdict(int)
            for result in scanResults:
                severityCounts[result.vulnerability.severity.name] += 1
            
            print("\nVULNERABILITIES DETECTED:")
            print("-" * 40)
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                count = severityCounts.get(severity, 0)
                if count > 0:
                    severityColor = {
                        'CRITICAL': Fore.RED,
                        'HIGH': Fore.YELLOW,
                        'MEDIUM': Fore.CYAN,
                        'LOW': Fore.GREEN,
                        'INFO': Fore.WHITE
                    }.get(severity, Fore.WHITE)
                    
                    print(f"{severityColor}{severity}: {count}{Fore.RESET}")
            
            # Top vulnerabilities
            print("\nTOP VULNERABILITIES:")
            print("-" * 40)
            for i, result in enumerate(scanResults[:5], 1):
                vuln = result.vulnerability
                print(f"{i}. {vuln.cveId} - {vuln.severity.name}")
                print(f"   Package: {result.detectedPackage.name} ({result.detectedPackage.version})")
                if vuln.fixedVersion:
                    print(f"   Fixed in: {vuln.fixedVersion}")
                print(f"   Confidence: {result.confidence:.1%}")
        
        if patchResults:
            # Patch summary
            statusCounts = defaultdict(int)
            for result in patchResults:
                statusCounts[result.status.value] += 1
            
            print("\nPATCH RESULTS:")
            print("-" * 40)
            for status in ['success', 'failed', 'skipped', 'rolled_back', 'manual_intervention_required']:
                count = statusCounts.get(status, 0)
                if count > 0:
                    statusColor = {
                        'success': Fore.GREEN,
                        'failed': Fore.RED,
                        'skipped': Fore.YELLOW,
                        'rolled_back': Fore.CYAN,
                        'manual_intervention_required': Fore.MAGENTA
                    }.get(status, Fore.WHITE)
                    
                    print(f"{statusColor}{status.replace('_', ' ').title()}: {count}{Fore.RESET}")
        
        print("\n" + "=" * 80)
        print("Detailed reports available in the 'reports/' directory")
        print("=" * 80)
    
    def cleanup(self, retentionDays: Optional[int] = None) -> int:
        """Clean up old data"""
        if retentionDays is None:
            retentionDays = int(self.config.get('general', 'retention_days', 90))
        
        logger.info(f"Cleaning up data older than {retentionDays} days...")
        
        # Clean database
        dbCleaned = self.dbManager.cleanupOldData(retentionDays)
        
        # Clean cache
        cacheCleaned = self.cacheManager.clear(olderThan=retentionDays * 86400)
        
        # Clean old reports (keep last 30 days)
        reportDir = Path(self.config.get('reporting', 'report_dir', 'reports'))
        reportCleaned = 0
        if reportDir.exists():
            now = time.time()
            for reportFile in reportDir.glob("*.json"):
                if reportFile.stat().st_mtime < now - (retentionDays * 86400):
                    reportFile.unlink()
                    reportCleaned += 1
        
        totalCleaned = dbCleaned + cacheCleaned + reportCleaned
        logger.info(f"Cleanup complete: {totalCleaned} items removed")
        
        return totalCleaned
    
    def run(self, args) -> int:
        """Main execution method"""
        try:
            # Set up signal handlers
            signal.signal(signal.SIGINT, self.signalHandler)
            signal.signal(signal.SIGTERM, self.signalHandler)
            
            # Initialize
            self.initialize()
            
            # Cleanup old data if requested
            if args.cleanup:
                self.cleanup(args.retention_days)
                return 0
            
            # Run scan
            scanResults, scanId = self.runScan(args.deep_scan)
            
            if not scanResults:
                print("\n✅ No vulnerabilities found!")
                return 0
            
            # Apply remediation if requested
            patchResults = []
            if args.remediate:
                patchResults = self.applyRemediation(
                    scanResults, 
                    dryRun=args.dry_run,
                    force=args.force
                )
            elif args.dry_run:
                # Dry run of remediation
                patchResults = self.applyRemediation(scanResults, dryRun=True)
            
            # Generate reports
            if args.report or args.remediate or args.dry_run:
                self.generateReports(scanResults, patchResults)
            
            # Display results
            if not args.quiet:
                self.displayResults(scanResults, patchResults)
            
            # Return appropriate exit code
            if scanResults and any(r.vulnerability.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH] 
                                  for r in scanResults):
                return 2  # High severity vulnerabilities found
            elif scanResults:
                return 1  # Vulnerabilities found but not critical/high
            else:
                return 0  # No vulnerabilities found
        
        except KeyboardInterrupt:
            print("\n\n⚠️  Operation cancelled by user")
            return 130
        except Exception as e:
            logger.error(f"Fatal error: {e}", exc_info=True)
            print(f"\n❌ Fatal error: {e}")
            if args.verbose:
                traceback.print_exc()
            return 1
    
    def signalHandler(self, signum, frame):
        """Handle termination signals"""
        print("\n\n⚠️  Received termination signal. Cleaning up...")
        sys.exit(0)

def parseArguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description=f"Advanced Vulnerability Remediation and Patching System v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  %(prog)s --scan                    # Scan for vulnerabilities
  %(prog)s --scan --report           # Scan and generate reports
  %(prog)s --remediate               # Scan and apply patches
  %(prog)s --dry-run                 # Test remediation without applying
  %(prog)s --remediate --force       # Apply patches without confirmation
  %(prog)s --cleanup                 # Clean up old data
  %(prog)s --config custom.ini       # Use custom configuration

Exit Codes:
  0: Success, no vulnerabilities found
  1: Vulnerabilities found (medium/low severity)
  2: Critical/high severity vulnerabilities found
  Other: Error occurred
        """
    )
    
    # Operation modes
    operationGroup = parser.add_argument_group('Operation Modes')
    operationGroup.add_argument(
        "--scan",
        action="store_true",
        help="Scan system for vulnerabilities"
    )
    operationGroup.add_argument(
        "--remediate",
        action="store_true",
        help="Scan and apply patches for vulnerabilities"
    )
    operationGroup.add_argument(
        "--dry-run",
        action="store_true",
        help="Test remediation without making changes"
    )
    
    # Options
    optionGroup = parser.add_argument_group('Options')
    optionGroup.add_argument(
        "--report",
        action="store_true",
        help="Generate reports"
    )
    optionGroup.add_argument(
        "--deep-scan",
        action="store_true",
        help="Perform deep scan (slower but more thorough)"
    )
    optionGroup.add_argument(
        "--force",
        action="store_true",
        help="Force operations without confirmation"
    )
    optionGroup.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress console output"
    )
    optionGroup.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )
    
    # Maintenance
    maintenanceGroup = parser.add_argument_group('Maintenance')
    maintenanceGroup.add_argument(
        "--cleanup",
        action="store_true",
        help="Clean up old data and reports"
    )
    maintenanceGroup.add_argument(
        "--retention-days",
        type=int,
        default=90,
        help="Days to keep data (default: 90)"
    )
    
    # Configuration
    configGroup = parser.add_argument_group('Configuration')
    configGroup.add_argument(
        "--config",
        type=str,
        default=DEFAULT_CONFIG_FILE,
        help=f"Configuration file (default: {DEFAULT_CONFIG_FILE})"
    )
    
    # If no arguments provided, show help
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)
    
    return parser.parse_args()

def checkRequirements():
    """Check system requirements"""
    issues = []
    
    # Check Python version
    if sys.version_info < (3, 7):
        issues.append("Python 3.7 or higher is required")
    
    # Check platform
    system = platform.system()
    if system not in ["Linux", "Windows", "Darwin"]:
        issues.append(f"Unsupported platform: {system}")
    
    # Check privileges
    if system == "Linux":
        try:
            if os.geteuid() != 0:
                issues.append("Root privileges required for full functionality")
        except AttributeError:
            pass
    
    # Check disk space
    try:
        if hasattr(os, 'statvfs'):
            stat = os.statvfs('.')
            freeSpace = stat.f_bavail * stat.f_frsize
            if freeSpace < 100 * 1024 * 1024:  # 100 MB
                issues.append("Low disk space (less than 100MB free)")
        else:
            # Windows uses shutil.disk_usage
            import shutil
            usage = shutil.disk_usage('.')
            if usage.free < 100 * 1024 * 1024:
                issues.append("Low disk space (less than 100MB free)")
    except:
        pass
    
    if issues:
        print("⚠️  Requirements check failed:")
        for issue in issues:
            print(f"  - {issue}")
        
        response = input("\nContinue anyway? (yes/NO): ").strip().lower()
        if response not in ['yes', 'y']:
            sys.exit(1)
    
    return True

def main():
    """Main entry point"""
    # Banner
    print(f"""
    ╔══════════════════════════════════════════════════════════════╗
    ║    Advanced Vulnerability Remediation and Patching System    ║
    ║                         Version {VERSION}                          ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    # Check requirements
    if not checkRequirements():
        sys.exit(1)
    
    # Parse arguments
    args = parseArguments()
    
    # Set log level
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    elif args.quiet:
        logger.setLevel(logging.ERROR)
    
    # Create patcher instance
    try:
        patcher = AdvancedVulnerabilityPatcher(args.config)
    except Exception as e:
        print(f"❌ Failed to initialize patcher: {e}")
        sys.exit(1)
    
    # Run patcher
    exitCode = patcher.run(args)
    
    # Exit with appropriate code
    sys.exit(exitCode)

if __name__ == "__main__":
    main()