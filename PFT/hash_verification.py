"""
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
