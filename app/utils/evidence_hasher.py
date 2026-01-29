"""
Evidence Hasher Utility
CyberTrace OSINT Platform - Zambia Police Service

File hashing utilities for evidence integrity verification
"""

import hashlib
import os
import json
from datetime import datetime


def calculate_file_hash(file_path, algorithm='sha256'):
    """
    Calculate hash of a file

    Args:
        file_path (str): Path to file
        algorithm (str): Hash algorithm (sha256, sha512, md5)

    Returns:
        str: Hexadecimal hash string or None if error
    """
    if not os.path.exists(file_path):
        return None

    # Select hash algorithm
    if algorithm == 'sha256':
        hasher = hashlib.sha256()
    elif algorithm == 'sha512':
        hasher = hashlib.sha512()
    elif algorithm == 'md5':
        hasher = hashlib.md5()
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    try:
        with open(file_path, 'rb') as f:
            # Read file in chunks for memory efficiency
            for chunk in iter(lambda: f.read(4096), b''):
                hasher.update(chunk)

        return hasher.hexdigest()
    except Exception as e:
        print(f"Error calculating hash: {e}")
        return None


def calculate_string_hash(data, algorithm='sha256'):
    """
    Calculate hash of a string or bytes

    Args:
        data (str or bytes): Data to hash
        algorithm (str): Hash algorithm

    Returns:
        str: Hexadecimal hash string
    """
    if algorithm == 'sha256':
        hasher = hashlib.sha256()
    elif algorithm == 'sha512':
        hasher = hashlib.sha512()
    elif algorithm == 'md5':
        hasher = hashlib.md5()
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    # Convert string to bytes if necessary
    if isinstance(data, str):
        data = data.encode('utf-8')

    hasher.update(data)
    return hasher.hexdigest()


def calculate_json_hash(data, algorithm='sha256'):
    """
    Calculate hash of JSON data

    Args:
        data (dict): JSON-serializable data
        algorithm (str): Hash algorithm

    Returns:
        str: Hexadecimal hash string
    """
    # Convert to JSON string with sorted keys for consistency
    json_string = json.dumps(data, sort_keys=True)
    return calculate_string_hash(json_string, algorithm)


def verify_file_integrity(file_path, expected_hash, algorithm='sha256'):
    """
    Verify file integrity by comparing hash

    Args:
        file_path (str): Path to file
        expected_hash (str): Expected hash value
        algorithm (str): Hash algorithm

    Returns:
        tuple: (bool, str) - (is_valid, calculated_hash)
    """
    calculated_hash = calculate_file_hash(file_path, algorithm)

    if calculated_hash is None:
        return False, None

    is_valid = calculated_hash.lower() == expected_hash.lower()
    return is_valid, calculated_hash


def generate_evidence_manifest(file_paths, algorithm='sha256'):
    """
    Generate manifest with hashes for multiple files

    Args:
        file_paths (list): List of file paths
        algorithm (str): Hash algorithm

    Returns:
        dict: Manifest with file hashes and metadata
    """
    manifest = {
        'generated_at': datetime.utcnow().isoformat(),
        'algorithm': algorithm,
        'files': []
    }

    for file_path in file_paths:
        if os.path.exists(file_path):
            file_hash = calculate_file_hash(file_path, algorithm)
            file_size = os.path.getsize(file_path)
            file_modified = datetime.fromtimestamp(
                os.path.getmtime(file_path)
            ).isoformat()

            manifest['files'].append({
                'path': file_path,
                'filename': os.path.basename(file_path),
                'hash': file_hash,
                'size': file_size,
                'modified': file_modified
            })

    return manifest


def calculate_chain_of_custody_hash(custody_events):
    """
    Calculate hash of entire chain of custody

    Args:
        custody_events (list): List of custody event dictionaries

    Returns:
        str: Hash of chain of custody
    """
    # Sort events by timestamp for consistency
    sorted_events = sorted(custody_events, key=lambda x: x.get('timestamp', ''))
    return calculate_json_hash(sorted_events)


def verify_evidence_integrity_batch(evidence_list):
    """
    Verify integrity of multiple evidence files

    Args:
        evidence_list (list): List of evidence objects with file_path and file_hash

    Returns:
        dict: Verification results
    """
    results = {
        'total': len(evidence_list),
        'verified': 0,
        'failed': 0,
        'missing': 0,
        'details': []
    }

    for evidence in evidence_list:
        if not evidence.file_path or not evidence.file_hash:
            results['missing'] += 1
            results['details'].append({
                'id': evidence.id,
                'status': 'no_file',
                'message': 'No file path or hash recorded'
            })
            continue

        is_valid, calculated_hash = verify_file_integrity(
            evidence.file_path,
            evidence.file_hash
        )

        if is_valid:
            results['verified'] += 1
            results['details'].append({
                'id': evidence.id,
                'status': 'verified',
                'message': 'File integrity verified'
            })
        else:
            results['failed'] += 1
            results['details'].append({
                'id': evidence.id,
                'status': 'failed',
                'message': 'File integrity check failed',
                'expected_hash': evidence.file_hash,
                'calculated_hash': calculated_hash
            })

    return results


def get_file_metadata(file_path):
    """
    Get file metadata for evidence tracking

    Args:
        file_path (str): Path to file

    Returns:
        dict: File metadata
    """
    if not os.path.exists(file_path):
        return None

    stat_info = os.stat(file_path)

    return {
        'filename': os.path.basename(file_path),
        'size': stat_info.st_size,
        'created': datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
        'modified': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
        'sha256_hash': calculate_file_hash(file_path, 'sha256'),
        'md5_hash': calculate_file_hash(file_path, 'md5')
    }


def generate_integrity_report(evidence_list, output_format='dict'):
    """
    Generate comprehensive integrity report

    Args:
        evidence_list (list): List of evidence objects
        output_format (str): Output format (dict, json)

    Returns:
        dict or str: Integrity report
    """
    report = {
        'generated_at': datetime.utcnow().isoformat(),
        'total_evidence': len(evidence_list),
        'verification_results': verify_evidence_integrity_batch(evidence_list),
        'hash_algorithm': 'SHA-256',
        'report_hash': None  # Will be calculated after report is complete
    }

    # Calculate hash of report itself (excluding this field)
    report_copy = report.copy()
    del report_copy['report_hash']
    report['report_hash'] = calculate_json_hash(report_copy)

    if output_format == 'json':
        return json.dumps(report, indent=2)

    return report
