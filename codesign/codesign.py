#! /usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (c) 2025, Env Open
# Copyright (c) 2025, Argo Nickerson

"""
CodeSign - Digital Code Signing Utility
A comprehensive code signing platform using pycryptodomex and pyOpenSSL.
"""

import os
import sys
import json
from pathlib import Path
from typing import Optional

import click
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID
try:
    from colorama import init, Fore, Style
    # Initialize colorama for cross-platform colored output
    init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    # Fallback if colorama is not available
    class DummyStyle:
        RESET_ALL = ""
    class DummyColor:
        CYAN = ""
        GREEN = ""
        RED = ""
        YELLOW = ""
        BLUE = ""
    Fore = DummyColor()
    Style = DummyStyle()
    COLORAMA_AVAILABLE = False

# Add the parent directory to sys.path to import our modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from codesign.crypto_handlers import (
    CertificateGenerator,
    create_code_signing_certificate,
    DigitalSigner,
    sign_file,
    verify_file
)

# Version information
__version__ = "1.0.0-alpha"


def print_banner():
    """Print the CodeSign banner."""
    banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════════╗
║                         CodeSign v{__version__}                     ║
║                  Digital Code Signing Utility                ║
║                                                               ║
║          Copyright (c) 2025 Env Open & Argo Nickerson       ║
╚═══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    click.echo(banner)


def print_success(message: str):
    """Print a success message."""
    click.echo(f"{Fore.GREEN}✓ {message}{Style.RESET_ALL}")


def print_error(message: str):
    """Print an error message."""
    click.echo(f"{Fore.RED}✗ {message}{Style.RESET_ALL}")


def print_warning(message: str):
    """Print a warning message."""
    click.echo(f"{Fore.YELLOW}⚠ {message}{Style.RESET_ALL}")


def print_info(message: str):
    """Print an info message."""
    click.echo(f"{Fore.BLUE}ℹ {message}{Style.RESET_ALL}")


@click.group()
@click.version_option(version=__version__)
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.pass_context
def cli(ctx, verbose):
    """CodeSign - Digital Code Signing Utility"""
    if ctx.invoked_subcommand is None:
        print_banner()
        ctx.get_help()
    ctx.ensure_object(dict)
    ctx.obj['verbose'] = verbose


@cli.group()
def cert():
    """Certificate management commands"""
    pass


@cert.command('generate')
@click.option('--common-name', '-cn', required=True, help='Common name for the certificate')
@click.option('--organization', '-o', default='CodeSign User', help='Organization name')
@click.option('--country', '-c', default='US', help='Country code (2 letters)')
@click.option('--key-size', '-k', default=2048, type=int, help='RSA key size in bits')
@click.option('--validity-days', '-d', default=365, type=int, help='Certificate validity in days')
@click.option('--output-dir', '-out', type=click.Path(), help='Output directory')
@click.option('--password', '-p', help='Password to encrypt the private key')
@click.pass_context
def cert_generate(ctx, common_name, organization, country, key_size, validity_days, output_dir, password):
    """Generate a new code signing certificate and private key"""
    try:
        print_info("Generating code signing certificate...")
        
        output_path = Path(output_dir) if output_dir else Path.cwd() / 'certificates'
        
        cert_path, key_path = create_code_signing_certificate(
            output_dir=output_path,
            common_name=common_name,
            organization=organization,
            country=country,
            key_size=key_size,
            validity_days=validity_days,
            password=password
        )
        
        print_success(f"Certificate generated successfully!")
        print_info(f"Certificate: {cert_path}")
        print_info(f"Private Key: {key_path}")
        
        if password:
            print_warning("Private key is encrypted. Keep the password safe!")
        else:
            print_warning("Private key is not encrypted. Consider using --password for better security.")
            
    except Exception as e:
        print_error(f"Failed to generate certificate: {e}")
        sys.exit(1)


@cert.command('info')
@click.argument('certificate_path', type=click.Path(exists=True))
def cert_info(certificate_path):
    """Display information about a certificate"""
    try:
        cert_gen = CertificateGenerator()
        certificate = cert_gen.load_certificate(Path(certificate_path))
        
        print_info("Certificate Information:")
        print(f"  Subject: {certificate.subject.rfc4514_string()}")
        print(f"  Issuer: {certificate.issuer.rfc4514_string()}")
        print(f"  Serial Number: {certificate.serial_number}")
        print(f"  Not Valid Before: {certificate.not_valid_before}")
        print(f"  Not Valid After: {certificate.not_valid_after}")
        print(f"  Algorithm: {certificate.signature_algorithm_oid._name}")
        
        # Check if certificate is for code signing
        try:
            ext_key_usage = certificate.extensions.get_extension_for_oid(
                ExtensionOID.EXTENDED_KEY_USAGE
            ).value
            # Check if it's an ExtendedKeyUsage extension and contains CODE_SIGNING
            if isinstance(ext_key_usage, x509.ExtendedKeyUsage) and ExtendedKeyUsageOID.CODE_SIGNING in ext_key_usage:
                print_success("  ✓ Code Signing: Enabled")
            else:
                print_warning("  ⚠ Code Signing: Not enabled")
        except:
            print_warning("  ⚠ Extended Key Usage: Not found")
            
    except Exception as e:
        print_error(f"Failed to read certificate: {e}")
        sys.exit(1)


@cli.group()
def sign():
    """File signing commands"""
    pass


@sign.command('file')
@click.argument('file_path', type=click.Path(exists=True))
@click.option('--private-key', '-k', required=True, type=click.Path(exists=True), help='Path to private key file')
@click.option('--certificate', '-c', required=True, type=click.Path(exists=True), help='Path to certificate file')
@click.option('--output-dir', '-out', type=click.Path(), help='Output directory for signature')
@click.option('--algorithm', '-a', default='SHA256', type=click.Choice(['SHA256', 'SHA384', 'SHA512']), help='Hash algorithm')
@click.option('--padding', '-pad', default='PSS', type=click.Choice(['PSS', 'PKCS1v15']), help='Padding scheme')
@click.option('--engine', '-e', default='cryptography', type=click.Choice(['cryptography', 'pycryptodome']), help='Crypto engine to use')
@click.option('--password', '-p', help='Password for encrypted private key')
@click.pass_context
def sign_file_cmd(ctx, file_path, private_key, certificate, output_dir, algorithm, padding, engine, password):
    """Sign a file with a digital signature"""
    try:
        print_info(f"Signing file: {file_path}")
        print_info(f"Using {engine} engine with {algorithm} hash and {padding} padding")
        
        output_path = Path(output_dir) if output_dir else Path(file_path).parent / 'signatures'
        use_pss = padding == 'PSS'
        use_pycryptodome = engine == 'pycryptodome'
        
        signature_file = sign_file(
            file_path=Path(file_path),
            private_key_path=Path(private_key),
            certificate_path=Path(certificate),
            output_dir=output_path,
            algorithm=algorithm,
            use_pss=use_pss,
            use_pycryptodome=use_pycryptodome,
            private_key_password=password
        )
        
        print_success(f"File signed successfully!")
        print_info(f"Signature file: {signature_file}")
        
        if ctx.obj.get('verbose'):
            # Display signature details
            signer = DigitalSigner()
            sig_info = signer.load_signature(signature_file)
            print_info("Signature Details:")
            print(f"  File Hash ({algorithm}): {sig_info['file_hash']}")
            print(f"  Signer: {sig_info['signer_info']['common_name']}")
            print(f"  Timestamp: {sig_info['timestamp']}")
            
    except Exception as e:
        print_error(f"Failed to sign file: {e}")
        sys.exit(1)


@cli.group()
def verify():
    """File verification commands"""
    pass


@verify.command('signature')
@click.argument('signature_path', type=click.Path(exists=True))
@click.option('--file-path', '-f', type=click.Path(), help='Path to file to verify (optional if unchanged)')
@click.option('--engine', '-e', default='cryptography', type=click.Choice(['cryptography', 'pycryptodome']), help='Crypto engine to use')
@click.pass_context
def verify_signature_cmd(ctx, signature_path, file_path, engine):
    """Verify a file signature"""
    try:
        print_info(f"Verifying signature: {signature_path}")
        
        use_pycryptodome = engine == 'pycryptodome'
        target_file = Path(file_path) if file_path else None
        
        is_valid = verify_file(
            signature_path=Path(signature_path),
            file_path=target_file,
            use_pycryptodome=use_pycryptodome
        )
        
        if is_valid:
            print_success("Signature is VALID ✓")
            
            if ctx.obj.get('verbose'):
                # Display signature details
                signer = DigitalSigner()
                sig_info = signer.load_signature(Path(signature_path))
                print_info("Signature Details:")
                print(f"  Original File: {sig_info['file_path']}")
                print(f"  Signer: {sig_info['signer_info']['common_name']}")
                print(f"  Organization: {sig_info['signer_info']['organization']}")
                print(f"  Algorithm: {sig_info['hash_algorithm']} with {sig_info['padding_scheme']}")
                print(f"  Signed: {sig_info['timestamp']}")
                print(f"  Certificate Valid: {sig_info['signer_info']['not_valid_before']} to {sig_info['signer_info']['not_valid_after']}")
        else:
            print_error("Signature is INVALID ✗")
            sys.exit(1)
            
    except Exception as e:
        print_error(f"Failed to verify signature: {e}")
        sys.exit(1)


@cli.command()
@click.argument('signature_path', type=click.Path(exists=True))
def info(signature_path):
    """Display detailed information about a signature file"""
    try:
        signer = DigitalSigner()
        sig_info = signer.load_signature(Path(signature_path))
        
        print_info("Signature File Information:")
        print(f"  Original File: {sig_info['file_path']}")
        print(f"  File Size: {sig_info['file_size']} bytes")
        print(f"  File Hash ({sig_info['hash_algorithm']}): {sig_info['file_hash']}")
        print(f"  Padding Scheme: {sig_info['padding_scheme']}")
        print(f"  Timestamp: {sig_info['timestamp']}")
        
        print_info("\nSigner Information:")
        print(f"  Common Name: {sig_info['signer_info']['common_name']}")
        if sig_info['signer_info']['organization']:
            print(f"  Organization: {sig_info['signer_info']['organization']}")
        print(f"  Certificate Serial: {sig_info['signer_info']['serial_number']}")
        print(f"  Valid From: {sig_info['signer_info']['not_valid_before']}")
        print(f"  Valid To: {sig_info['signer_info']['not_valid_after']}")
        
    except Exception as e:
        print_error(f"Failed to read signature file: {e}")
        sys.exit(1)


@cli.command()
def examples():
    """Show usage examples"""
    examples_text = f"""
{Fore.CYAN}CodeSign Usage Examples:{Style.RESET_ALL}

{Fore.YELLOW}1. Generate a code signing certificate:{Style.RESET_ALL}
   codesign cert generate --common-name "My Code Signing Cert" --organization "My Company"

{Fore.YELLOW}2. Generate with custom parameters:{Style.RESET_ALL}
   codesign cert generate -cn "Developer Cert" -o "Acme Corp" -c "US" -k 4096 -d 730 --password mypassword

{Fore.YELLOW}3. View certificate information:{Style.RESET_ALL}
   codesign cert info certificates/my_code_signing_cert.crt

{Fore.YELLOW}4. Sign a file:{Style.RESET_ALL}
   codesign sign file myapp.exe -k certificates/my_cert.key -c certificates/my_cert.crt

{Fore.YELLOW}5. Sign with specific options:{Style.RESET_ALL}
   codesign sign file myapp.exe -k my.key -c my.crt -a SHA384 -pad PKCS1v15 -e pycryptodome

{Fore.YELLOW}6. Verify a signature:{Style.RESET_ALL}
   codesign verify signature signatures/myapp.exe.sig

{Fore.YELLOW}7. Verify with different file location:{Style.RESET_ALL}
   codesign verify signature myapp.exe.sig --file-path /new/location/myapp.exe

{Fore.YELLOW}8. View signature details:{Style.RESET_ALL}
   codesign info signatures/myapp.exe.sig

{Fore.YELLOW}9. Verbose output:{Style.RESET_ALL}
   codesign -v sign file myapp.exe -k my.key -c my.crt
   codesign -v verify signature myapp.exe.sig

{Fore.GREEN}Note: Use --help with any command for more detailed options{Style.RESET_ALL}
"""
    click.echo(examples_text)


if __name__ == '__main__':
    # Print banner when run directly
    if len(sys.argv) == 1:
        print_banner()
    cli()