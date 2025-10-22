"""
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
