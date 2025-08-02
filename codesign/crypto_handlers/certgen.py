#! /usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (c) 2025, Env Open
# Copyright (c) 2025, Argo Nickerson

"""
Certificate Generation Module for CodeSign
Handles X.509 certificate and key pair generation for code signing.
"""

import os
import datetime
from typing import Tuple, Optional
from pathlib import Path

from OpenSSL import crypto
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend


class CertificateGenerator:
    """Handles generation of X.509 certificates and RSA key pairs for code signing."""
    
    def __init__(self):
        self.backend = default_backend()
    
    def generate_key_pair(self, key_size: int = 2048) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """
        Generate an RSA key pair.
        
        Args:
            key_size: Size of the RSA key in bits (default: 2048)
            
        Returns:
            Tuple of (private_key, public_key)
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=self.backend
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    def create_self_signed_cert(
        self,
        private_key: rsa.RSAPrivateKey,
        common_name: str,
        organization: str = "CodeSign User",
        country: str = "US",
        validity_days: int = 365,
        is_ca: bool = False
    ) -> x509.Certificate:
        """
        Create a self-signed X.509 certificate.
        
        Args:
            private_key: The private key to sign the certificate
            common_name: Common name for the certificate subject
            organization: Organization name
            country: Country code (2 letters)
            validity_days: Certificate validity period in days
            is_ca: Whether this is a CA certificate
            
        Returns:
            X.509 Certificate object
        """
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        
        # Generate certificate
        cert_builder = x509.CertificateBuilder()
        cert_builder = cert_builder.subject_name(subject)
        cert_builder = cert_builder.issuer_name(issuer)
        cert_builder = cert_builder.public_key(private_key.public_key())
        cert_builder = cert_builder.serial_number(x509.random_serial_number())
        cert_builder = cert_builder.not_valid_before(datetime.datetime.utcnow())
        cert_builder = cert_builder.not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=validity_days)
        )
        
        # Add extensions
        if is_ca:
            cert_builder = cert_builder.add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            cert_builder = cert_builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                    content_commitment=False
                ),
                critical=True,
            )
        else:
            # Code signing certificate
            cert_builder = cert_builder.add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            cert_builder = cert_builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                    content_commitment=True
                ),
                critical=True,
            )
            # Extended Key Usage for code signing
            cert_builder = cert_builder.add_extension(
                x509.ExtendedKeyUsage([
                    ExtendedKeyUsageOID.CODE_SIGNING,
                ]),
                critical=True,
            )
        
        # Add Subject Key Identifier
        cert_builder = cert_builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        
        # Add Authority Key Identifier (same as subject for self-signed)
        cert_builder = cert_builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(private_key.public_key()),
            critical=False,
        )
        
        # Sign the certificate
        certificate = cert_builder.sign(private_key, hashes.SHA256(), self.backend)
        return certificate
    
    def save_private_key(self, private_key: rsa.RSAPrivateKey, file_path: Path, password: Optional[str] = None):
        """
        Save private key to file.
        
        Args:
            private_key: The private key to save
            file_path: Path to save the key file
            password: Optional password to encrypt the key
        """
        encryption_algorithm = serialization.NoEncryption()
        if password:
            encryption_algorithm = serialization.BestAvailableEncryption(password.encode())
        
        pem_data = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        )
        
        with open(file_path, 'wb') as f:
            f.write(pem_data)
    
    def save_certificate(self, certificate: x509.Certificate, file_path: Path):
        """
        Save certificate to file in PEM format.
        
        Args:
            certificate: The certificate to save
            file_path: Path to save the certificate file
        """
        pem_data = certificate.public_bytes(serialization.Encoding.PEM)
        with open(file_path, 'wb') as f:
            f.write(pem_data)
    
    def load_private_key(self, file_path: Path, password: Optional[str] = None) -> rsa.RSAPrivateKey:
        """
        Load private key from file.
        
        Args:
            file_path: Path to the private key file
            password: Optional password to decrypt the key
            
        Returns:
            RSA private key object
        """
        with open(file_path, 'rb') as f:
            key_data = f.read()
        
        password_bytes = password.encode() if password else None
        private_key = serialization.load_pem_private_key(
            key_data, password=password_bytes, backend=self.backend
        )
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise ValueError("Expected RSA private key")
        return private_key
    
    def load_certificate(self, file_path: Path) -> x509.Certificate:
        """
        Load certificate from file.
        
        Args:
            file_path: Path to the certificate file
            
        Returns:
            X.509 certificate object
        """
        with open(file_path, 'rb') as f:
            cert_data = f.read()
        
        certificate = x509.load_pem_x509_certificate(cert_data, self.backend)
        return certificate
    
    def generate_csr(
        self,
        private_key: rsa.RSAPrivateKey,
        common_name: str,
        organization: str = "CodeSign User",
        country: str = "US"
    ) -> x509.CertificateSigningRequest:
        """
        Generate a Certificate Signing Request (CSR).
        
        Args:
            private_key: The private key for the CSR
            common_name: Common name for the certificate subject
            organization: Organization name
            country: Country code (2 letters)
            
        Returns:
            Certificate Signing Request object
        """
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        
        csr_builder = x509.CertificateSigningRequestBuilder()
        csr_builder = csr_builder.subject_name(subject)
        
        # Add code signing extension
        csr_builder = csr_builder.add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.CODE_SIGNING,
            ]),
            critical=True,
        )
        
        csr = csr_builder.sign(private_key, hashes.SHA256(), self.backend)
        return csr
    
    def save_csr(self, csr: x509.CertificateSigningRequest, file_path: Path):
        """
        Save CSR to file in PEM format.
        
        Args:
            csr: The certificate signing request to save
            file_path: Path to save the CSR file
        """
        pem_data = csr.public_bytes(serialization.Encoding.PEM)
        with open(file_path, 'wb') as f:
            f.write(pem_data)


def create_code_signing_certificate(
    output_dir: Path,
    common_name: str,
    organization: str = "CodeSign User",
    country: str = "US",
    key_size: int = 2048,
    validity_days: int = 365,
    password: Optional[str] = None
) -> Tuple[Path, Path]:
    """
    Convenience function to create a complete code signing certificate and key pair.
    
    Args:
        output_dir: Directory to save the certificate and key files
        common_name: Common name for the certificate
        organization: Organization name
        country: Country code
        key_size: RSA key size in bits
        validity_days: Certificate validity period in days
        password: Optional password to encrypt the private key
        
    Returns:
        Tuple of (certificate_path, private_key_path)
    """
    cert_gen = CertificateGenerator()
    
    # Generate key pair
    private_key, _ = cert_gen.generate_key_pair(key_size)
    
    # Create self-signed certificate
    certificate = cert_gen.create_self_signed_cert(
        private_key, common_name, organization, country, validity_days
    )
    
    # Create output directory if it doesn't exist
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Save certificate and key
    cert_path = output_dir / f"{common_name.replace(' ', '_').lower()}.crt"
    key_path = output_dir / f"{common_name.replace(' ', '_').lower()}.key"
    
    cert_gen.save_certificate(certificate, cert_path)
    cert_gen.save_private_key(private_key, key_path, password)
    
    return cert_path, key_path