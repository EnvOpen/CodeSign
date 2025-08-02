#! /usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (c) 2025, Env Open
# Copyright (c) 2025, Argo Nickerson

"""
Crypto Handlers Package for CodeSign
Contains modules for certificate generation and digital signing.
"""

from .certgen import CertificateGenerator, create_code_signing_certificate
from .signer import DigitalSigner, sign_file, verify_file

__all__ = [
    'CertificateGenerator',
    'create_code_signing_certificate',
    'DigitalSigner',
    'sign_file',
    'verify_file'
]