"""
Log Parser Script
Parses various log formats for forensic timeline analysis
"""

import re
from datetime import datetime
from typing import List, Dict
import json

class LogParser:
    """Parse common log formats for forensic analysis"""

    # Common log patterns
    PATTERNS = {
        'apache_access': r'(\S+) - - \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d+) (\d+)',
        'nginx_access': r'(\S+) - (\S+) \[([^\]]+)\] "(.*?)" (\d+) (\d+) "(.*?)" "(.*?)"',
        'windows_event': r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\s*(\w+),\s*(\d+),\s*(.*)',
        'syslog': r'(\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) (\S+) (\S+)\[(\d+)\]: (.*)'
    }

    def __init__(self, log_file: str, log_type: str = 'auto'):
        self.log_file = log_file
        self.log_type = log_type
        self.entries = []

    def detect_log_type(self, line: str) -> str:
        """Auto-detect log format"""
        for log_type, pattern in self.PATTERNS.items():
            if re.match(pattern, line):
                return log_type
        return 'unknown'

    def parse_apache_log(self, line: str) -> Dict:
        """Parse Apache access log entry"""
        match = re.match(self.PATTERNS['apache_access'], line)
        if match:
            return {
                'ip': match.group(1),
                'timestamp': match.group(2),
                'method': match.group(3),
                'url': match.group(4),
                'protocol': match.group(5),
                'status': int(match.group(6)),
                'bytes': int(match.group(7))
            }
        return {}

    def parse_windows_event(self, line: str) -> Dict:
        """Parse Windows Event Log entry"""
        match = re.match(self.PATTERNS['windows_event'], line)
        if match:
            return {
                'timestamp': match.group(1),
                'level': match.group(2),
                'event_id': int(match.group(3)),
                'message': match.group(4)
            }
        return {}

    def parse_syslog(self, line: str) -> Dict:
        """Parse syslog entry"""
        match = re.match(self.PATTERNS['syslog'], line)
        if match:
            return {
                'timestamp': match.group(1),
                'hostname': match.group(2),
                'process': match.group(3),
                'pid': int(match.group(4)),
                'message': match.group(5)
            }
        return {}

    def parse_file(self) -> List[Dict]:
        """Parse entire log file"""
        with open(self.log_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                # Auto-detect if needed
                if self.log_type == 'auto':
                    detected_type = self.detect_log_type(line)
                    if detected_type != 'unknown':
                        self.log_type = detected_type

                # Parse based on type
                if self.log_type == 'apache_access':
                    entry = self.parse_apache_log(line)
                elif self.log_type == 'windows_event':
                    entry = self.parse_windows_event(line)
                elif self.log_type == 'syslog':
                    entry = self.parse_syslog(line)
                else:
                    entry = {'raw': line}

                if entry:
                    self.entries.append(entry)

        return self.entries

    def filter_by_timerange(self, start_time: str, end_time: str) -> List[Dict]:
        """Filter entries by time range"""
        filtered = []
        for entry in self.entries:
            if 'timestamp' in entry:
                # Implement timestamp comparison logic
                filtered.append(entry)
        return filtered

    def search_keyword(self, keyword: str) -> List[Dict]:
        """Search for keyword in log entries"""
        results = []
        for entry in self.entries:
            entry_str = json.dumps(entry)
            if keyword.lower() in entry_str.lower():
                results.append(entry)
        return results

# Example usage
if __name__ == "__main__":
    parser = LogParser("/var/log/apache2/access.log", log_type='apache_access')
    entries = parser.parse_file()
    print(f"Parsed {len(entries)} log entries")

    # Search for specific IP
    suspicious_entries = parser.search_keyword("192.168.1.100")
    print(f"Found {len(suspicious_entries)} suspicious entries")
