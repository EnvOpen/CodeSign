#! /usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (c) 2025, Env Open
# Copyright (c) 2025, Argo Nickerson

"""
Digital Signature Module for CodeSign
Handles signing and verification of files using RSA-PSS and RSA-PKCS1v15.
"""

import hashlib
import json
import base64
from typing import Dict, Any, Optional, Union
from pathlib import Path
from datetime import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from Cryptodome.Hash import SHA256, SHA384, SHA512
from Cryptodome.Signature import pkcs1_15, pss
from Cryptodome.PublicKey import RSA


class DigitalSigner:
    """Handles digital signing and verification of files."""
    
    def __init__(self):
        self.backend = default_backend()
        self.supported_algorithms = {
            'SHA256': (hashes.SHA256(), SHA256),
            'SHA384': (hashes.SHA384(), SHA384),
            'SHA512': (hashes.SHA512(), SHA512)
        }
    
    def calculate_file_hash(self, file_path: Path, algorithm: str = 'SHA256') -> str:
        """
        Calculate hash of a file.
        
        Args:
            file_path: Path to the file
            algorithm: Hash algorithm (SHA256, SHA384, SHA512)
            
        Returns:
            Hexadecimal hash string
        """
        if algorithm not in self.supported_algorithms:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")
        
        hash_func = getattr(hashlib, algorithm.lower())()
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_func.update(chunk)
        
        return hash_func.hexdigest()
    
    def sign_file_cryptography(
        self,
        file_path: Path,
        private_key: rsa.RSAPrivateKey,
        certificate: x509.Certificate,
        algorithm: str = 'SHA256',
        use_pss: bool = True
    ) -> Dict[str, Any]:
        """
        Sign a file using cryptography library.
        
        Args:
            file_path: Path to the file to sign
            private_key: RSA private key for signing
            certificate: X.509 certificate
            algorithm: Hash algorithm to use
            use_pss: Whether to use PSS padding (True) or PKCS1v15 (False)
            
        Returns:
            Dictionary containing signature information
        """
        if algorithm not in self.supported_algorithms:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")
        
        # Calculate file hash
        file_hash = self.calculate_file_hash(file_path, algorithm)
        
        # Create hash object for signing
        hash_alg, _ = self.supported_algorithms[algorithm]
        
        # Read file content for signing
        with open(file_path, 'rb') as f:
            file_content = f.read()
        
        # Choose padding
        if use_pss:
            pad = padding.PSS(
                mgf=padding.MGF1(hash_alg),
                salt_length=padding.PSS.MAX_LENGTH
            )
        else:
            pad = padding.PKCS1v15()
        
        # Sign the file content
        signature = private_key.sign(file_content, pad, hash_alg)
        
        # Create signature metadata
        signature_info = {
            'file_path': str(file_path),
            'file_size': len(file_content),
            'file_hash': file_hash,
            'hash_algorithm': algorithm,
            'padding_scheme': 'PSS' if use_pss else 'PKCS1v15',
            'signature': base64.b64encode(signature).decode('utf-8'),
            'certificate': base64.b64encode(
                certificate.public_bytes(serialization.Encoding.PEM)
            ).decode('utf-8'),
            'timestamp': datetime.utcnow().isoformat(),
            'signer_info': {
                'common_name': certificate.subject.get_attributes_for_oid(
                    x509.NameOID.COMMON_NAME
                )[0].value,
                'organization': certificate.subject.get_attributes_for_oid(
                    x509.NameOID.ORGANIZATION_NAME
                )[0].value if certificate.subject.get_attributes_for_oid(
                    x509.NameOID.ORGANIZATION_NAME
                ) else None,
                'serial_number': str(certificate.serial_number),
                'not_valid_before': certificate.not_valid_before.isoformat(),
                'not_valid_after': certificate.not_valid_after.isoformat()
            }
        }
        
        return signature_info
    
    def sign_file_pycryptodome(
        self,
        file_path: Path,
        private_key_pem: bytes,
        certificate: x509.Certificate,
        algorithm: str = 'SHA256',
        use_pss: bool = True
    ) -> Dict[str, Any]:
        """
        Sign a file using pycryptodomex library.
        
        Args:
            file_path: Path to the file to sign
            private_key_pem: PEM encoded private key
            certificate: X.509 certificate
            algorithm: Hash algorithm to use
            use_pss: Whether to use PSS padding (True) or PKCS1v15 (False)
            
        Returns:
            Dictionary containing signature information
        """
        if algorithm not in self.supported_algorithms:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")
        
        # Calculate file hash
        file_hash = self.calculate_file_hash(file_path, algorithm)
        
        # Import private key
        rsa_key = RSA.import_key(private_key_pem)
        
        # Read file content
        with open(file_path, 'rb') as f:
            file_content = f.read()
        
        # Create hash
        _, hash_class = self.supported_algorithms[algorithm]
        hash_obj = hash_class.new(file_content)
        
        # Choose signer
        if use_pss:
            signer = pss.new(rsa_key)
        else:
            signer = pkcs1_15.new(rsa_key)
        
        # Sign
        signature = signer.sign(hash_obj)
        
        # Create signature metadata
        signature_info = {
            'file_path': str(file_path),
            'file_size': len(file_content),
            'file_hash': file_hash,
            'hash_algorithm': algorithm,
            'padding_scheme': 'PSS' if use_pss else 'PKCS1v15',
            'signature': base64.b64encode(signature).decode('utf-8'),
            'certificate': base64.b64encode(
                certificate.public_bytes(serialization.Encoding.PEM)
            ).decode('utf-8'),
            'timestamp': datetime.utcnow().isoformat(),
            'signer_info': {
                'common_name': certificate.subject.get_attributes_for_oid(
                    x509.NameOID.COMMON_NAME
                )[0].value,
                'organization': certificate.subject.get_attributes_for_oid(
                    x509.NameOID.ORGANIZATION_NAME
                )[0].value if certificate.subject.get_attributes_for_oid(
                    x509.NameOID.ORGANIZATION_NAME
                ) else None,
                'serial_number': str(certificate.serial_number),
                'not_valid_before': certificate.not_valid_before.isoformat(),
                'not_valid_after': certificate.not_valid_after.isoformat()
            }
        }
        
        return signature_info
    
    def verify_signature_cryptography(
        self,
        signature_info: Dict[str, Any],
        file_path: Optional[Path] = None
    ) -> bool:
        """
        Verify a signature using cryptography library.
        
        Args:
            signature_info: Signature information dictionary
            file_path: Optional path to verify against (uses original if None)
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            # Use provided file path or original from signature
            target_file = file_path or Path(signature_info['file_path'])
            
            if not target_file.exists():
                return False
            
            # Load certificate
            cert_pem = base64.b64decode(signature_info['certificate'])
            certificate = x509.load_pem_x509_certificate(cert_pem, self.backend)
            
            # Get public key
            public_key = certificate.public_key()
            
            # Decode signature
            signature = base64.b64decode(signature_info['signature'])
            
            # Read file content
            with open(target_file, 'rb') as f:
                file_content = f.read()
            
            # Verify file hasn't changed
            current_hash = self.calculate_file_hash(target_file, signature_info['hash_algorithm'])
            if current_hash != signature_info['file_hash']:
                return False
            
            # Choose padding and hash
            algorithm = signature_info['hash_algorithm']
            hash_alg, _ = self.supported_algorithms[algorithm]
            
            if signature_info['padding_scheme'] == 'PSS':
                pad = padding.PSS(
                    mgf=padding.MGF1(hash_alg),
                    salt_length=padding.PSS.MAX_LENGTH
                )
            else:
                pad = padding.PKCS1v15()
            
            # Verify signature
            public_key.verify(signature, file_content, pad, hash_alg)
            return True
            
        except Exception:
            return False
    
    def verify_signature_pycryptodome(
        self,
        signature_info: Dict[str, Any],
        file_path: Optional[Path] = None
    ) -> bool:
        """
        Verify a signature using pycryptodomex library.
        
        Args:
            signature_info: Signature information dictionary
            file_path: Optional path to verify against (uses original if None)
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            # Use provided file path or original from signature
            target_file = file_path or Path(signature_info['file_path'])
            
            if not target_file.exists():
                return False
            
            # Load certificate and extract public key
            cert_pem = base64.b64decode(signature_info['certificate'])
            certificate = x509.load_pem_x509_certificate(cert_pem, self.backend)
            
            # Extract public key in PEM format
            public_key_pem = certificate.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Import public key
            rsa_key = RSA.import_key(public_key_pem)
            
            # Decode signature
            signature = base64.b64decode(signature_info['signature'])
            
            # Read file content
            with open(target_file, 'rb') as f:
                file_content = f.read()
            
            # Verify file hasn't changed
            current_hash = self.calculate_file_hash(target_file, signature_info['hash_algorithm'])
            if current_hash != signature_info['file_hash']:
                return False
            
            # Create hash
            algorithm = signature_info['hash_algorithm']
            _, hash_class = self.supported_algorithms[algorithm]
            hash_obj = hash_class.new(file_content)
            
            # Choose verifier
            if signature_info['padding_scheme'] == 'PSS':
                verifier = pss.new(rsa_key)
            else:
                verifier = pkcs1_15.new(rsa_key)
            
            # Verify signature
            verifier.verify(hash_obj, signature)
            return True
            
        except Exception:
            return False
    
    def save_signature(self, signature_info: Dict[str, Any], output_path: Path):
        """
        Save signature information to a JSON file.
        
        Args:
            signature_info: Signature information dictionary
            output_path: Path to save the signature file
        """
        with open(output_path, 'w') as f:
            json.dump(signature_info, f, indent=2)
    
    def load_signature(self, signature_path: Path) -> Dict[str, Any]:
        """
        Load signature information from a JSON file.
        
        Args:
            signature_path: Path to the signature file
            
        Returns:
            Signature information dictionary
        """
        with open(signature_path, 'r') as f:
            return json.load(f)


def sign_file(
    file_path: Path,
    private_key_path: Path,
    certificate_path: Path,
    output_dir: Path,
    algorithm: str = 'SHA256',
    use_pss: bool = True,
    use_pycryptodome: bool = False,
    private_key_password: Optional[str] = None
) -> Path:
    """
    Convenience function to sign a file and save the signature.
    
    Args:
        file_path: Path to the file to sign
        private_key_path: Path to the private key file
        certificate_path: Path to the certificate file
        output_dir: Directory to save the signature file
        algorithm: Hash algorithm to use
        use_pss: Whether to use PSS padding
        use_pycryptodome: Whether to use pycryptodomex instead of cryptography
        private_key_password: Password for encrypted private key
        
    Returns:
        Path to the generated signature file
    """
    signer = DigitalSigner()
    
    # Load certificate
    with open(certificate_path, 'rb') as f:
        cert_pem = f.read()
    certificate = x509.load_pem_x509_certificate(cert_pem, default_backend())
    
    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)
    
    if use_pycryptodome:
        # Load private key as PEM for pycryptodomex
        with open(private_key_path, 'rb') as f:
            private_key_pem = f.read()
        
        signature_info = signer.sign_file_pycryptodome(
            file_path, private_key_pem, certificate, algorithm, use_pss
        )
    else:
        # Load private key for cryptography
        with open(private_key_path, 'rb') as f:
            key_data = f.read()
        
        password_bytes = private_key_password.encode() if private_key_password else None
        private_key = serialization.load_pem_private_key(
            key_data, password=password_bytes, backend=default_backend()
        )
        
        signature_info = signer.sign_file_cryptography(
            file_path, private_key, certificate, algorithm, use_pss
        )
    
    # Save signature
    signature_file = output_dir / f"{file_path.name}.sig"
    signer.save_signature(signature_info, signature_file)
    
    return signature_file


def verify_file(signature_path: Path, file_path: Optional[Path] = None, use_pycryptodome: bool = False) -> bool:
    """
    Convenience function to verify a file signature.
    
    Args:
        signature_path: Path to the signature file
        file_path: Optional path to the file (uses original if None)
        use_pycryptodome: Whether to use pycryptodomex for verification
        
    Returns:
        True if signature is valid, False otherwise
    """
    signer = DigitalSigner()
    signature_info = signer.load_signature(signature_path)
    
    if use_pycryptodome:
        return signer.verify_signature_pycryptodome(signature_info, file_path)
    else:
        return signer.verify_signature_cryptography(signature_info, file_path)
