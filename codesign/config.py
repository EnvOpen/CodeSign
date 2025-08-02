#! /usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (c) 2025, Env Open
# Copyright (c) 2025, Argo Nickerson

"""
Configuration Module for CodeSign
Handles configuration settings and defaults.
"""

import os
import json
from pathlib import Path
from typing import Dict, Any, Optional


class CodeSignConfig:
    """Configuration manager for CodeSign."""
    
    def __init__(self, config_file: Optional[Path] = None):
        self.config_file = config_file or Path.home() / '.codesign' / 'config.json'
        self.config = self._load_default_config()
        self._load_config()
    
    def _load_default_config(self) -> Dict[str, Any]:
        """Load default configuration."""
        return {
            'certificates': {
                'default_key_size': 2048,
                'default_validity_days': 365,
                'default_country': 'US',
                'default_organization': 'CodeSign User',
                'default_algorithm': 'SHA256'
            },
            'signing': {
                'default_padding': 'PSS',
                'default_engine': 'cryptography',
                'default_algorithm': 'SHA256'
            },
            'paths': {
                'certificates_dir': str(Path.cwd() / 'certificates'),
                'signatures_dir': str(Path.cwd() / 'signatures'),
                'temp_dir': str(Path.cwd() / 'temp')
            },
            'output': {
                'verbose': False,
                'use_colors': True,
                'timestamp_format': '%Y-%m-%d %H:%M:%S UTC'
            },
            'security': {
                'require_password_for_keys': False,
                'min_key_size': 2048,
                'allowed_algorithms': ['SHA256', 'SHA384', 'SHA512'],
                'allowed_padding': ['PSS', 'PKCS1v15']
            }
        }
    
    def _load_config(self):
        """Load configuration from file if it exists."""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    user_config = json.load(f)
                self._merge_config(user_config)
            except Exception as e:
                print(f"Warning: Failed to load config file {self.config_file}: {e}")
    
    def _merge_config(self, user_config: Dict[str, Any]):
        """Merge user configuration with defaults."""
        for section, values in user_config.items():
            if section in self.config:
                if isinstance(values, dict):
                    self.config[section].update(values)
                else:
                    self.config[section] = values
            else:
                self.config[section] = values
    
    def save_config(self):
        """Save current configuration to file."""
        self.config_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_file, 'w') as f:
            json.dump(self.config, f, indent=2)
    
    def get(self, section: str, key: str, default: Any = None) -> Any:
        """Get a configuration value."""
        return self.config.get(section, {}).get(key, default)
    
    def set(self, section: str, key: str, value: Any):
        """Set a configuration value."""
        if section not in self.config:
            self.config[section] = {}
        self.config[section][key] = value
    
    def get_certificates_dir(self) -> Path:
        """Get the certificates directory."""
        return Path(self.get('paths', 'certificates_dir', 'certificates'))
    
    def get_signatures_dir(self) -> Path:
        """Get the signatures directory."""
        return Path(self.get('paths', 'signatures_dir', 'signatures'))
    
    def get_temp_dir(self) -> Path:
        """Get the temporary directory."""
        return Path(self.get('paths', 'temp_dir', 'temp'))


# Global configuration instance
config = CodeSignConfig()


def get_config() -> CodeSignConfig:
    """Get the global configuration instance."""
    return config


def create_default_config_file():
    """Create a default configuration file for the user."""
    config_file = Path.home() / '.codesign' / 'config.json'
    config_file.parent.mkdir(parents=True, exist_ok=True)
    
    default_config = CodeSignConfig()._load_default_config()
    
    with open(config_file, 'w') as f:
        json.dump(default_config, f, indent=2)
    
    return config_file
