#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (c) 2025, Env Open
# Copyright (c) 2025, Argo Nickerson

"""
Setup script for CodeSign
Install dependencies and set up the environment.
"""

import subprocess
import sys
import os
from pathlib import Path


def run_command(command, description):
    """Run a command and handle errors."""
    print(f"🔄 {description}...")
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ {description} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed:")
        print(f"   Command: {command}")
        print(f"   Error: {e.stderr}")
        return False


def check_python_version():
    """Check if Python version is compatible."""
    if sys.version_info < (3, 7):
        print("❌ Python 3.7 or higher is required")
        print(f"   Current version: {sys.version}")
        return False
    print(f"✅ Python version: {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
    return True


def install_dependencies():
    """Install required dependencies."""
    requirements_file = Path(__file__).parent / "requirements.txt"
    
    if not requirements_file.exists():
        print("❌ requirements.txt not found")
        return False
    
    # Upgrade pip first
    if not run_command(f"{sys.executable} -m pip install --upgrade pip", "Upgrading pip"):
        return False
    
    # Install requirements
    if not run_command(f"{sys.executable} -m pip install -r {requirements_file}", "Installing dependencies"):
        return False
    
    return True


def create_directories():
    """Create necessary directories."""
    base_dir = Path(__file__).parent
    directories = [
        base_dir / "certificates",
        base_dir / "signatures",
        base_dir / "examples"
    ]
    
    for directory in directories:
        directory.mkdir(exist_ok=True)
        print(f"📁 Created directory: {directory}")
    
    return True


def create_example_script():
    """Create an example usage script."""
    example_script = Path(__file__).parent / "examples" / "example_usage.py"
    
    content = '''#!/usr/bin/env python3
"""
Example usage of CodeSign library
This script demonstrates how to use CodeSign programmatically.
"""

import sys
from pathlib import Path

# Add codesign to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from codesign.crypto_handlers import create_code_signing_certificate, sign_file, verify_file


def main():
    """Example usage of CodeSign."""
    print("CodeSign Library Example")
    print("=" * 40)
    
    # Create directories
    cert_dir = Path("certificates")
    sig_dir = Path("signatures")
    cert_dir.mkdir(exist_ok=True)
    sig_dir.mkdir(exist_ok=True)
    
    # 1. Generate a certificate
    print("\\n1. Generating certificate...")
    cert_path, key_path = create_code_signing_certificate(
        output_dir=cert_dir,
        common_name="Example Code Signer",
        organization="Example Corp",
        country="US",
        validity_days=365
    )
    print(f"   Certificate: {cert_path}")
    print(f"   Private Key: {key_path}")
    
    # 2. Create a sample file to sign
    sample_file = Path("sample_file.txt")
    sample_file.write_text("This is a sample file for code signing.")
    print(f"\\n2. Created sample file: {sample_file}")
    
    # 3. Sign the file
    print("\\n3. Signing file...")
    signature_file = sign_file(
        file_path=sample_file,
        private_key_path=key_path,
        certificate_path=cert_path,
        output_dir=sig_dir,
        algorithm="SHA256",
        use_pss=True,
        use_pycryptodome=False
    )
    print(f"   Signature: {signature_file}")
    
    # 4. Verify the signature
    print("\\n4. Verifying signature...")
    is_valid = verify_file(signature_file, use_pycryptodome=False)
    if is_valid:
        print("   ✅ Signature is VALID")
    else:
        print("   ❌ Signature is INVALID")
    
    # 5. Test with modified file
    print("\\n5. Testing with modified file...")
    sample_file.write_text("This file has been modified!")
    is_valid_modified = verify_file(signature_file, use_pycryptodome=False)
    if not is_valid_modified:
        print("   ✅ Correctly detected file modification")
    else:
        print("   ❌ Failed to detect file modification")
    
    print("\\n" + "=" * 40)
    print("Example completed successfully!")


if __name__ == "__main__":
    main()
'''
    
    example_script.write_text(content)
    print(f"📝 Created example script: {example_script}")
    return True


def make_executable():
    """Make the main script executable on Unix systems."""
    if os.name != 'nt':  # Not Windows
        main_script = Path(__file__).parent / "codesign" / "codesign.py"
        if main_script.exists():
            os.chmod(main_script, 0o755)
            print(f"🔧 Made executable: {main_script}")
    return True


def test_installation():
    """Test the installation by importing modules."""
    print("🧪 Testing installation...")
    try:
        # Test imports
        from codesign.crypto_handlers import CertificateGenerator, DigitalSigner
        print("   ✅ Successfully imported CertificateGenerator")
        print("   ✅ Successfully imported DigitalSigner")
        
        # Test basic functionality
        cert_gen = CertificateGenerator()
        private_key, public_key = cert_gen.generate_key_pair(key_size=1024)  # Small key for test
        print("   ✅ Successfully generated test key pair")
        
        signer = DigitalSigner()
        print("   ✅ Successfully created DigitalSigner instance")
        
        return True
    except Exception as e:
        print(f"   ❌ Import test failed: {e}")
        return False


def main():
    """Main setup function."""
    print("CodeSign Setup Script")
    print("=" * 50)
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Install dependencies
    if not install_dependencies():
        print("\\n❌ Setup failed during dependency installation")
        sys.exit(1)
    
    # Create directories
    if not create_directories():
        print("\\n❌ Setup failed during directory creation")
        sys.exit(1)
    
    # Create example script
    if not create_example_script():
        print("\\n❌ Setup failed during example script creation")
        sys.exit(1)
    
    # Make executable
    if not make_executable():
        print("\\n❌ Setup failed during executable setup")
        sys.exit(1)
    
    # Test installation
    if not test_installation():
        print("\\n❌ Setup failed during installation test")
        sys.exit(1)
    
    print("\\n" + "=" * 50)
    print("🎉 CodeSign setup completed successfully!")
    print()
    print("Quick start:")
    print("  1. Generate certificate: python codesign/codesign.py cert generate --common-name 'My Cert'")
    print("  2. Sign a file: python codesign/codesign.py sign file myfile.txt -k my.key -c my.crt")
    print("  3. Verify signature: python codesign/codesign.py verify signature myfile.txt.sig")
    print("  4. See examples: python codesign/codesign.py examples")
    print("  5. Run example: python examples/example_usage.py")


if __name__ == "__main__":
    main()
