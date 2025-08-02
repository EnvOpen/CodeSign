#! /usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (c) 2025, Env Open
# Copyright (c) 2025, Argo Nickerson

"""
CodeSign Package
A comprehensive code signing platform using pycryptodomex and pyOpenSSL.
"""

__version__ = "1.0.0-alpha"
__author__ = "Argo Nickerson, Env Open"
__license__ = "MIT"
__description__ = "Digital Code Signing Utility"

from .crypto_handlers import (
    CertificateGenerator,
    create_code_signing_certificate,
    DigitalSigner,
    sign_file,
    verify_file
)

from .config import CodeSignConfig, get_config, create_default_config_file
from .utils import FileUtils, CertUtils, ValidationUtils, FormatUtils, SecurityUtils

__all__ = [
    # Core functionality
    'CertificateGenerator',
    'create_code_signing_certificate',
    'DigitalSigner',
    'sign_file',
    'verify_file',
    
    # Configuration
    'CodeSignConfig',
    'get_config',
    'create_default_config_file',
    
    # Utilities
    'FileUtils',
    'CertUtils',
    'ValidationUtils',
    'FormatUtils',
    'SecurityUtils',
    
    # Metadata
    '__version__',
    '__author__',
    '__license__',
    '__description__'
]
