#! /usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (c) 2025, Env Open
# Copyright (c) 2025, Argo Nickerson

"""
Utility Module for CodeSign
Common utility functions and helpers.
"""

import os
import hashlib
import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Union

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID


class FileUtils:
    """File utility functions."""
    
    @staticmethod
    def get_file_info(file_path: Path) -> Dict[str, Any]:
        """Get comprehensive file information."""
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        stat = file_path.stat()
        
        return {
            'path': str(file_path.absolute()),
            'name': file_path.name,
            'size': stat.st_size,
            'created': datetime.datetime.fromtimestamp(stat.st_ctime),
            'modified': datetime.datetime.fromtimestamp(stat.st_mtime),
            'is_executable': os.access(file_path, os.X_OK),
            'permissions': oct(stat.st_mode)[-3:],
            'hash_sha256': FileUtils.calculate_hash(file_path, 'sha256'),
            'hash_md5': FileUtils.calculate_hash(file_path, 'md5')
        }
    
    @staticmethod
    def calculate_hash(file_path: Path, algorithm: str = 'sha256') -> str:
        """Calculate file hash."""
        hash_func = hashlib.new(algorithm)
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_func.update(chunk)
        
        return hash_func.hexdigest()
    
    @staticmethod
    def find_files(directory: Path, pattern: str = "*", recursive: bool = True) -> List[Path]:
        """Find files matching a pattern."""
        if recursive:
            return list(directory.rglob(pattern))
        else:
            return list(directory.glob(pattern))
    
    @staticmethod
    def safe_filename(name: str) -> str:
        """Create a safe filename from a string."""
        # Remove or replace unsafe characters
        unsafe_chars = '<>:"/\\|?*'
        safe_name = name
        for char in unsafe_chars:
            safe_name = safe_name.replace(char, '_')
        
        # Remove extra spaces and convert to lowercase
        safe_name = '_'.join(safe_name.split()).lower()
        
        return safe_name


class CertUtils:
    """Certificate utility functions."""
    
    @staticmethod
    def get_cert_info(cert_path: Path) -> Dict[str, Any]:
        """Get detailed certificate information."""
        with open(cert_path, 'rb') as f:
            cert_data = f.read()
        
        certificate = x509.load_pem_x509_certificate(cert_data, default_backend())
        
        # Extract subject information
        subject_dict = {}
        for attribute in certificate.subject:
            subject_dict[attribute.oid._name] = attribute.value
        
        # Extract issuer information
        issuer_dict = {}
        for attribute in certificate.issuer:
            issuer_dict[attribute.oid._name] = attribute.value
        
        # Get extensions
        extensions = {}
        for ext in certificate.extensions:
            extensions[ext.oid._name] = {
                'critical': ext.critical,
                'value': str(ext.value)
            }
        
        return {
            'subject': subject_dict,
            'issuer': issuer_dict,
            'serial_number': str(certificate.serial_number),
            'version': certificate.version.name,
            'not_valid_before': certificate.not_valid_before.isoformat(),
            'not_valid_after': certificate.not_valid_after.isoformat(),
            'signature_algorithm': certificate.signature_algorithm_oid._name,
            'is_self_signed': certificate.subject == certificate.issuer,
            'public_key_size': getattr(certificate.public_key(), 'key_size', 'N/A'),
            'extensions': extensions,
            'is_valid_now': CertUtils.is_cert_valid_now(certificate),
            'days_until_expiry': CertUtils.days_until_expiry(certificate)
        }
    
    @staticmethod
    def is_cert_valid_now(certificate: x509.Certificate) -> bool:
        """Check if certificate is currently valid."""
        now = datetime.datetime.utcnow()
        return certificate.not_valid_before <= now <= certificate.not_valid_after
    
    @staticmethod
    def days_until_expiry(certificate: x509.Certificate) -> int:
        """Get days until certificate expires."""
        now = datetime.datetime.utcnow()
        delta = certificate.not_valid_after - now
        return delta.days
    
    @staticmethod
    def is_code_signing_cert(cert_path: Path) -> bool:
        """Check if certificate is suitable for code signing."""
        try:
            with open(cert_path, 'rb') as f:
                cert_data = f.read()
            
            certificate = x509.load_pem_x509_certificate(cert_data, default_backend())
            
            # Check for Extended Key Usage extension
            try:
                extension = certificate.extensions.get_extension_for_oid(
                    ExtensionOID.EXTENDED_KEY_USAGE
                )
                ext_key_usage = extension.value
                # Check if code signing is enabled
                from cryptography.x509.oid import ExtendedKeyUsageOID
                # Cast to ExtendedKeyUsage and check if code signing is enabled
                if isinstance(ext_key_usage, x509.ExtendedKeyUsage):
                    return ExtendedKeyUsageOID.CODE_SIGNING in ext_key_usage
                return False
            except x509.ExtensionNotFound:
                return False

        except Exception:
            return False


class ValidationUtils:
    """Validation utility functions."""
    
    @staticmethod
    def validate_key_size(key_size: int, min_size: int = 2048) -> bool:
        """Validate RSA key size."""
        return key_size >= min_size and key_size % 1024 == 0
    
    @staticmethod
    def validate_algorithm(algorithm: str) -> bool:
        """Validate hash algorithm."""
        return algorithm.upper() in ['SHA256', 'SHA384', 'SHA512', 'MD5', 'SHA1']
    
    @staticmethod
    def validate_padding(padding: str) -> bool:
        """Validate padding scheme."""
        return padding.upper() in ['PSS', 'PKCS1V15']
    
    @staticmethod
    def validate_country_code(country: str) -> bool:
        """Validate country code (basic check)."""
        return len(country) == 2 and country.isalpha()
    
    @staticmethod
    def validate_common_name(common_name: str) -> bool:
        """Validate common name."""
        return len(common_name.strip()) > 0 and len(common_name) <= 64


class FormatUtils:
    """Formatting utility functions."""
    
    @staticmethod
    def format_bytes(size: int) -> str:
        """Format bytes in human readable format."""
        size_float = float(size)
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_float < 1024:
                return f"{size_float:.1f} {unit}"
            size_float /= 1024
        return f"{size_float:.1f} PB"
    
    @staticmethod
    def format_datetime(dt: datetime.datetime) -> str:
        """Format datetime in a readable format."""
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    
    @staticmethod
    def format_duration(seconds: float) -> str:
        """Format duration in human readable format."""
        if seconds < 1:
            return f"{seconds*1000:.0f}ms"
        elif seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            return f"{seconds/60:.1f}m"
        else:
            return f"{seconds/3600:.1f}h"
    
    @staticmethod
    def truncate_string(text: str, max_length: int = 50) -> str:
        """Truncate string with ellipsis."""
        if len(text) <= max_length:
            return text
        return text[:max_length-3] + "..."


class SecurityUtils:
    """Security utility functions."""
    
    @staticmethod
    def is_file_potentially_malicious(file_path: Path) -> Dict[str, Any]:
        """Basic security check for files."""
        warnings = []
        info = FileUtils.get_file_info(file_path)
        
        # Check file size (warn if very large)
        if info['size'] > 100 * 1024 * 1024:  # 100MB
            warnings.append("File is very large (>100MB)")
        
        # Check if executable
        if info['is_executable']:
            warnings.append("File is executable")
        
        # Check common malicious extensions
        malicious_extensions = ['.exe', '.scr', '.bat', '.cmd', '.com', '.pif']
        if file_path.suffix.lower() in malicious_extensions:
            warnings.append(f"File has potentially dangerous extension: {file_path.suffix}")
        
        return {
            'is_suspicious': len(warnings) > 0,
            'warnings': warnings,
            'file_info': info
        }
    
    @staticmethod
    def generate_secure_filename(base_name: str) -> str:
        """Generate a secure filename with timestamp."""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_base = FileUtils.safe_filename(base_name)
        return f"{safe_base}_{timestamp}"


def create_directory_structure(base_dir: Path) -> Dict[str, Path]:
    """Create standard CodeSign directory structure."""
    directories = {
        'certificates': base_dir / 'certificates',
        'signatures': base_dir / 'signatures',
        'temp': base_dir / 'temp',
        'logs': base_dir / 'logs',
        'backup': base_dir / 'backup'
    }
    
    for name, path in directories.items():
        path.mkdir(parents=True, exist_ok=True)
    
    return directories


def cleanup_temp_files(temp_dir: Path, max_age_hours: int = 24):
    """Clean up temporary files older than max_age_hours."""
    if not temp_dir.exists():
        return
    
    cutoff_time = datetime.datetime.now() - datetime.timedelta(hours=max_age_hours)
    
    for file_path in temp_dir.iterdir():
        if file_path.is_file():
            file_time = datetime.datetime.fromtimestamp(file_path.stat().st_mtime)
            if file_time < cutoff_time:
                try:
                    file_path.unlink()
                except OSError:
                    pass  # Ignore errors when deleting temp files
