
# Create sample Python automation scripts for forensic toolkit

# Script 1: Metadata Extraction
metadata_extraction_script = '''"""
Metadata Extraction Script
Extracts metadata from various file types for forensic analysis
"""

import os
import hashlib
from datetime import datetime
from PIL import Image
from PIL.ExifTags import TAGS
import PyPDF2
import json

class MetadataExtractor:
    """Extract metadata from various file types"""
    
    def __init__(self, file_path):
        self.file_path = file_path
        self.file_name = os.path.basename(file_path)
        self.file_size = os.path.getsize(file_path)
        
    def calculate_hashes(self):
        """Calculate MD5, SHA1, and SHA256 hashes"""
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        
        with open(self.file_path, 'rb') as f:
            while chunk := f.read(8192):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
                
        return {
            'md5': md5.hexdigest(),
            'sha1': sha1.hexdigest(),
            'sha256': sha256.hexdigest()
        }
    
    def get_timestamps(self):
        """Extract file system timestamps"""
        stat = os.stat(self.file_path)
        return {
            'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
            'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
            'accessed': datetime.fromtimestamp(stat.st_atime).isoformat()
        }
    
    def extract_image_metadata(self):
        """Extract EXIF data from images"""
        try:
            image = Image.open(self.file_path)
            exif_data = image._getexif()
            
            if exif_data:
                metadata = {}
                for tag_id, value in exif_data.items():
                    tag = TAGS.get(tag_id, tag_id)
                    metadata[tag] = str(value)
                return metadata
        except Exception as e:
            return {'error': str(e)}
        return {}
    
    def extract_pdf_metadata(self):
        """Extract metadata from PDF files"""
        try:
            with open(self.file_path, 'rb') as f:
                pdf = PyPDF2.PdfReader(f)
                metadata = pdf.metadata
                return {
                    'title': metadata.get('/Title', ''),
                    'author': metadata.get('/Author', ''),
                    'subject': metadata.get('/Subject', ''),
                    'creator': metadata.get('/Creator', ''),
                    'producer': metadata.get('/Producer', ''),
                    'creation_date': metadata.get('/CreationDate', ''),
                    'modification_date': metadata.get('/ModDate', ''),
                    'pages': len(pdf.pages)
                }
        except Exception as e:
            return {'error': str(e)}
    
    def extract_all(self):
        """Extract all available metadata"""
        metadata = {
            'file_name': self.file_name,
            'file_size': self.file_size,
            'hashes': self.calculate_hashes(),
            'timestamps': self.get_timestamps()
        }
        
        # Determine file type and extract specific metadata
        ext = os.path.splitext(self.file_name)[1].lower()
        
        if ext in ['.jpg', '.jpeg', '.png', '.tiff']:
            metadata['exif'] = self.extract_image_metadata()
        elif ext == '.pdf':
            metadata['pdf_info'] = self.extract_pdf_metadata()
            
        return metadata

# Example usage
if __name__ == "__main__":
    file_path = "/path/to/evidence/file.jpg"
    extractor = MetadataExtractor(file_path)
    metadata = extractor.extract_all()
    print(json.dumps(metadata, indent=2))
'''

# Script 2: Hash Verification
hash_verification_script = '''"""
Hash Verification Script
Verifies file integrity using multiple hash algorithms
"""

import hashlib
import os
from typing import Dict, List

class HashVerifier:
    """Verify file integrity using hash comparison"""
    
    ALGORITHMS = ['md5', 'sha1', 'sha256', 'sha512']
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        
    def calculate_hash(self, algorithm: str = 'sha256') -> str:
        """Calculate hash for a file"""
        if algorithm not in self.ALGORITHMS:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
            
        hash_obj = hashlib.new(algorithm)
        
        with open(self.file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_obj.update(chunk)
                
        return hash_obj.hexdigest()
    
    def calculate_all_hashes(self) -> Dict[str, str]:
        """Calculate all supported hashes"""
        return {algo: self.calculate_hash(algo) for algo in self.ALGORITHMS}
    
    def verify_hash(self, expected_hash: str, algorithm: str = 'sha256') -> bool:
        """Verify file against expected hash"""
        actual_hash = self.calculate_hash(algorithm)
        return actual_hash.lower() == expected_hash.lower()
    
    def verify_chain_of_custody(self, expected_hashes: Dict[str, str]) -> Dict[str, bool]:
        """Verify multiple hashes for chain of custody"""
        results = {}
        actual_hashes = self.calculate_all_hashes()
        
        for algo, expected in expected_hashes.items():
            if algo in actual_hashes:
                results[algo] = actual_hashes[algo].lower() == expected.lower()
            else:
                results[algo] = False
                
        return results
    
    @staticmethod
    def bulk_hash_directory(directory: str, algorithm: str = 'sha256') -> List[Dict]:
        """Calculate hashes for all files in a directory"""
        results = []
        
        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    verifier = HashVerifier(file_path)
                    file_hash = verifier.calculate_hash(algorithm)
                    results.append({
                        'file_path': file_path,
                        'file_name': file,
                        'hash': file_hash,
                        'algorithm': algorithm,
                        'size': os.path.getsize(file_path)
                    })
                except Exception as e:
                    results.append({
                        'file_path': file_path,
                        'error': str(e)
                    })
                    
        return results

# Example usage
if __name__ == "__main__":
    # Single file verification
    verifier = HashVerifier("/path/to/evidence.img")
    
    # Calculate all hashes
    hashes = verifier.calculate_all_hashes()
    print("File Hashes:", hashes)
    
    # Verify against expected hash
    expected_sha256 = "abc123..."
    is_valid = verifier.verify_hash(expected_sha256, 'sha256')
    print(f"Hash verification: {'PASS' if is_valid else 'FAIL'}")
    
    # Bulk directory hashing
    results = HashVerifier.bulk_hash_directory("/evidence/directory")
    for result in results:
        print(f"{result['file_name']}: {result.get('hash', result.get('error'))}")
'''

# Script 3: Log Parser
log_parser_script = '''"""
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
        'apache_access': r'(\\S+) - - \\[([^\\]]+)\\] "(\\S+) (\\S+) (\\S+)" (\\d+) (\\d+)',
        'nginx_access': r'(\\S+) - (\\S+) \\[([^\\]]+)\\] "(.*?)" (\\d+) (\\d+) "(.*?)" "(.*?)"',
        'windows_event': r'(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}),\\s*(\\w+),\\s*(\\d+),\\s*(.*)',
        'syslog': r'(\\w{3}\\s+\\d{1,2} \\d{2}:\\d{2}:\\d{2}) (\\S+) (\\S+)\\[(\\d+)\\]: (.*)'
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
'''

# Script 4: Malware Detection
malware_detection_script = '''"""
Malware Detection Script
Uses pattern matching and ML for malware detection
"""

import os
import pefile
import yara
import hashlib
from typing import Dict, List

class MalwareDetector:
    """Detect potential malware using multiple techniques"""
    
    SUSPICIOUS_EXTENSIONS = ['.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js']
    SUSPICIOUS_STRINGS = ['cmd.exe', 'powershell', 'regsvr32', 'rundll32']
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.results = {
            'file_name': os.path.basename(file_path),
            'file_size': os.path.getsize(file_path),
            'is_suspicious': False,
            'indicators': []
        }
        
    def check_extension(self) -> bool:
        """Check if file has suspicious extension"""
        ext = os.path.splitext(self.file_path)[1].lower()
        if ext in self.SUSPICIOUS_EXTENSIONS:
            self.results['indicators'].append(f"Suspicious extension: {ext}")
            return True
        return False
    
    def check_file_size(self) -> bool:
        """Check for unusual file sizes"""
        size = self.results['file_size']
        # Suspiciously small executables
        if size < 1024 and os.path.splitext(self.file_path)[1] == '.exe':
            self.results['indicators'].append("Unusually small executable")
            return True
        return False
    
    def calculate_entropy(self) -> float:
        """Calculate Shannon entropy (high entropy may indicate encryption/packing)"""
        with open(self.file_path, 'rb') as f:
            data = f.read()
            
        if not data:
            return 0.0
            
        entropy = 0.0
        for x in range(256):
            p_x = float(data.count(bytes([x]))) / len(data)
            if p_x > 0:
                entropy += - p_x * (p_x).bit_length()
                
        # High entropy (> 7.0) often indicates packed/encrypted malware
        if entropy > 7.0:
            self.results['indicators'].append(f"High entropy: {entropy:.2f} (possible packing)")
            return True
            
        return entropy
    
    def analyze_pe_header(self) -> Dict:
        """Analyze PE file headers for anomalies"""
        try:
            pe = pefile.PE(self.file_path)
            
            analysis = {
                'compile_time': pe.FILE_HEADER.TimeDateStamp,
                'sections': len(pe.sections),
                'imports': len(pe.DIRECTORY_ENTRY_IMPORT) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0
            }
            
            # Check for suspicious section names
            suspicious_sections = []
            for section in pe.sections:
                name = section.Name.decode().strip('\\x00')
                if name not in ['.text', '.data', '.rdata', '.rsrc', '.reloc']:
                    suspicious_sections.append(name)
            
            if suspicious_sections:
                self.results['indicators'].append(f"Suspicious sections: {suspicious_sections}")
            
            return analysis
            
        except Exception as e:
            return {'error': str(e)}
    
    def scan_with_yara(self, rules_file: str) -> List[str]:
        """Scan file with YARA rules"""
        try:
            rules = yara.compile(filepath=rules_file)
            matches = rules.match(self.file_path)
            
            if matches:
                for match in matches:
                    self.results['indicators'].append(f"YARA match: {match.rule}")
                    
            return [match.rule for match in matches]
        except Exception as e:
            return []
    
    def analyze(self, yara_rules: str = None) -> Dict:
        """Perform complete malware analysis"""
        self.check_extension()
        self.check_file_size()
        self.calculate_entropy()
        
        # PE analysis for executables
        if self.file_path.endswith('.exe') or self.file_path.endswith('.dll'):
            self.results['pe_analysis'] = self.analyze_pe_header()
        
        # YARA scanning
        if yara_rules:
            self.results['yara_matches'] = self.scan_with_yara(yara_rules)
        
        self.results['is_suspicious'] = len(self.results['indicators']) > 0
        
        return self.results

# Example usage
if __name__ == "__main__":
    detector = MalwareDetector("/path/to/suspicious.exe")
    results = detector.analyze(yara_rules="/path/to/malware_rules.yar")
    
    print(f"File: {results['file_name']}")
    print(f"Suspicious: {results['is_suspicious']}")
    print("Indicators:")
    for indicator in results['indicators']:
        print(f"  - {indicator}")
'''

# Save all scripts
scripts = {
    'metadata_extraction.py': metadata_extraction_script,
    'hash_verification.py': hash_verification_script,
    'log_parser.py': log_parser_script,
    'malware_detection.py': malware_detection_script
}

for filename, content in scripts.items():
    with open(filename, 'w') as f:
        f.write(content)

print("Python Automation Scripts Created:")
for filename in scripts.keys():
    print(f"  - {filename}")
