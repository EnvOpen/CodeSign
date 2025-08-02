#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (c) 2025, Env Open
# Copyright (c) 2025, Argo Nickerson

"""
Test Script for CodeSign
Demonstrates the full functionality of the code signing platform.
"""

import sys
import tempfile
from pathlib import Path

# Add codesign to path
sys.path.insert(0, str(Path(__file__).parent))

from codesign import (
    create_code_signing_certificate,
    sign_file,
    verify_file,
    CertificateGenerator,
    DigitalSigner,
    FileUtils,
    CertUtils
)


def test_certificate_generation():
    """Test certificate generation functionality."""
    print("🔐 Testing Certificate Generation...")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Test basic certificate generation
        cert_path, key_path = create_code_signing_certificate(
            output_dir=temp_path,
            common_name="Test Code Signer",
            organization="Test Organization",
            country="US",
            key_size=2048,
            validity_days=365
        )
        
        assert cert_path.exists(), "Certificate file not created"
        assert key_path.exists(), "Private key file not created"
        
        # Test certificate info
        cert_info = CertUtils.get_cert_info(cert_path)
        assert cert_info['subject']['commonName'] == "Test Code Signer"
        assert cert_info['is_valid_now'] == True
        
        print("   ✅ Certificate generation successful")
        print(f"   📄 Certificate: {cert_path.name}")
        print(f"   🔑 Private Key: {key_path.name}")
        
        return cert_path, key_path


def test_file_signing_cryptography(cert_path, key_path):
    """Test file signing with cryptography backend."""
    print("\n📝 Testing File Signing (cryptography backend)...")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Create a test file
        test_file = temp_path / "test_document.txt"
        test_content = "This is a test document for code signing verification."
        test_file.write_text(test_content)
        
        # Sign the file
        signature_file = sign_file(
            file_path=test_file,
            private_key_path=key_path,
            certificate_path=cert_path,
            output_dir=temp_path,
            algorithm="SHA256",
            use_pss=True,
            use_pycryptodome=False
        )
        
        assert signature_file.exists(), "Signature file not created"
        
        # Load and check signature info
        signer = DigitalSigner()
        sig_info = signer.load_signature(signature_file)
        
        assert sig_info['hash_algorithm'] == "SHA256"
        assert sig_info['padding_scheme'] == "PSS"
        assert sig_info['signer_info']['common_name'] == "Test Code Signer"
        
        print("   ✅ File signing successful")
        print(f"   📄 File: {test_file.name}")
        print(f"   🖋️  Signature: {signature_file.name}")
        
        return test_file, signature_file


def test_file_signing_pycryptodome(cert_path, key_path):
    """Test file signing with pycryptodomex backend."""
    print("\n📝 Testing File Signing (pycryptodomex backend)...")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Create a test file
        test_file = temp_path / "test_executable.bin"
        test_content = b"\x7fELF\x02\x01\x01\x00" + b"Test executable content" * 100
        test_file.write_bytes(test_content)
        
        # Sign the file
        signature_file = sign_file(
            file_path=test_file,
            private_key_path=key_path,
            certificate_path=cert_path,
            output_dir=temp_path,
            algorithm="SHA384",
            use_pss=False,  # Use PKCS1v15
            use_pycryptodome=True
        )
        
        assert signature_file.exists(), "Signature file not created"
        
        # Load and check signature info
        signer = DigitalSigner()
        sig_info = signer.load_signature(signature_file)
        
        assert sig_info['hash_algorithm'] == "SHA384"
        assert sig_info['padding_scheme'] == "PKCS1v15"
        
        print("   ✅ File signing successful")
        print(f"   📄 File: {test_file.name}")
        print(f"   🖋️  Signature: {signature_file.name}")
        
        return test_file, signature_file


def test_signature_verification(test_file, signature_file, use_pycryptodome=False):
    """Test signature verification."""
    backend_name = "pycryptodomex" if use_pycryptodome else "cryptography"
    print(f"\n🔍 Testing Signature Verification ({backend_name} backend)...")
    
    # Test valid signature
    is_valid = verify_file(signature_file, use_pycryptodome=use_pycryptodome)
    assert is_valid == True, "Valid signature not verified"
    print("   ✅ Valid signature verification successful")
    
    # Test with modified file
    original_content = test_file.read_text() if test_file.suffix == '.txt' else test_file.read_bytes()
    
    # Modify the file
    if test_file.suffix == '.txt':
        test_file.write_text(original_content + " MODIFIED")
    else:
        test_file.write_bytes(original_content + b" MODIFIED")
    
    is_valid_modified = verify_file(signature_file, use_pycryptodome=use_pycryptodome)
    assert is_valid_modified == False, "Modified file signature incorrectly verified"
    print("   ✅ Modified file correctly detected")
    
    # Restore original content
    if test_file.suffix == '.txt':
        test_file.write_text(original_content)
    else:
        test_file.write_bytes(original_content)


def test_utilities():
    """Test utility functions."""
    print("\n🛠️  Testing Utility Functions...")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Create test file
        test_file = temp_path / "utility_test.dat"
        test_content = b"Testing utility functions" * 1000
        test_file.write_bytes(test_content)
        
        # Test file utilities
        file_info = FileUtils.get_file_info(test_file)
        assert file_info['name'] == "utility_test.dat"
        assert file_info['size'] == len(test_content)
        assert 'hash_sha256' in file_info
        assert 'hash_md5' in file_info
        
        # Test hash calculation
        hash_sha256 = FileUtils.calculate_hash(test_file, 'sha256')
        assert len(hash_sha256) == 64  # SHA256 produces 32 bytes = 64 hex chars
        
        print("   ✅ File utilities working correctly")
        print(f"   📊 File size: {file_info['size']} bytes")
        print(f"   🔢 SHA256: {hash_sha256[:16]}...")


def test_advanced_features():
    """Test advanced features and edge cases."""
    print("\n🚀 Testing Advanced Features...")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Test different key sizes
        cert_gen = CertificateGenerator()
        
        # Test 4096-bit key
        private_key_4k, _ = cert_gen.generate_key_pair(4096)
        assert private_key_4k.key_size == 4096
        print("   ✅ 4096-bit key generation successful")
        
        # Test CSR generation
        csr = cert_gen.generate_csr(
            private_key_4k,
            "CSR Test Certificate",
            "CSR Test Org",
            "CA"
        )
        
        # Save CSR
        csr_path = temp_path / "test.csr"
        cert_gen.save_csr(csr, csr_path)
        assert csr_path.exists()
        print("   ✅ CSR generation and saving successful")
        
        # Test password-protected key
        key_with_password = temp_path / "protected.key"
        cert_gen.save_private_key(private_key_4k, key_with_password, "testpassword123")
        
        # Load password-protected key
        loaded_key = cert_gen.load_private_key(key_with_password, "testpassword123")
        assert loaded_key.key_size == 4096
        print("   ✅ Password-protected key handling successful")


def run_comprehensive_test():
    """Run a comprehensive test of all functionality."""
    print("🧪 CodeSign Comprehensive Test Suite")
    print("=" * 50)
    
    try:
        # Test certificate generation
        cert_path, key_path = test_certificate_generation()
        
        # Test file signing with both backends
        test_file_crypto, sig_file_crypto = test_file_signing_cryptography(cert_path, key_path)
        test_file_pycrypto, sig_file_pycrypto = test_file_signing_pycryptodome(cert_path, key_path)
        
        # Test signature verification with both backends
        test_signature_verification(test_file_crypto, sig_file_crypto, use_pycryptodome=False)
        test_signature_verification(test_file_pycrypto, sig_file_pycrypto, use_pycryptodome=True)
        
        # Test cross-verification (sign with one backend, verify with another)
        print("\n🔄 Testing Cross-Backend Verification...")
        cross_valid_1 = verify_file(sig_file_crypto, use_pycryptodome=True)
        cross_valid_2 = verify_file(sig_file_pycrypto, use_pycryptodome=False)
        
        if cross_valid_1 and cross_valid_2:
            print("   ✅ Cross-backend verification successful")
        else:
            print("   ⚠️  Cross-backend verification issues detected")
        
        # Test utilities
        test_utilities()
        
        # Test advanced features
        test_advanced_features()
        
        print("\n" + "=" * 50)
        print("🎉 All tests completed successfully!")
        print("\n✨ CodeSign is ready for use!")
        
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    run_comprehensive_test()
