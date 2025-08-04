# CodeSign v1.0.0
Open source code signing utility using Python, pycryptodomex, and pyOpenSSL

## Overview

CodeSign is a comprehensive digital code signing platform that provides:

- **Certificate Generation**: Create X.509 certificates for code signing
- **Digital Signing**: Sign files using RSA-PSS or PKCS#1 v1.5 padding
- **Signature Verification**: Verify digital signatures and file integrity
- **Dual Crypto Backend**: Support for both `cryptography` and `pycryptodomex` libraries
- **CLI Interface**: Easy-to-use command-line interface
- **GUI Interface**: User-friendly graphical interface for all operations
- **Interactive Mode**: Guided CLI experience for beginners
- **Programmatic API**: Use as a Python library in your applications

## Features

### Certificate Management
- Generate self-signed code signing certificates
- Create Certificate Signing Requests (CSR)
- Support for RSA keys from 2048 to 4096 bits
- Configurable validity periods and certificate metadata
- Certificate information display and validation

### Digital Signing
- Sign any file type with digital signatures
- Support for SHA256, SHA384, and SHA512 hash algorithms
- RSA-PSS and PKCS#1 v1.5 padding schemes
- Timestamped signatures with signer information
- JSON-based signature files for portability

### User Interfaces
- **Command Line Interface (CLI)**: Full-featured CLI with extensive options
- **Interactive CLI Mode**: Guided experience for new users
- **Graphical User Interface (GUI)**: Easy-to-use tkinter-based interface
- **Programmatic API**: Python library for integration

### Security Features
- Encrypted private key storage with password protection
- File integrity verification through hash comparison
- Certificate-based identity verification
- Secure random number generation for keys and certificates

### Flexibility
- Choose between `cryptography` and `pycryptodomex` backends
- Cross-platform compatibility (Windows, Linux, macOS)
- Configurable defaults and settings
- Comprehensive logging and verbose output options

## Quick Start

### Installation

1. Clone the repository:
```bash
git clone https://github.com/your-repo/CodeSign.git
cd CodeSign
```

2. Run the setup script:
```bash
python setup.py
```

This will install all dependencies and set up the environment.

### Basic Usage

**Option 1: Graphical User Interface (Recommended for beginners)**
```bash
python codesign/gui_launcher.py
```
This launches a user-friendly GUI that provides:
- Certificate generation with forms and validation
- File signing with drag-and-drop support
- Signature verification with detailed results
- Certificate and signature information viewing
- File utilities and tools

**Option 2: Interactive Command Line**
```bash
python codesign/codesign.py
```
This starts an interactive mode with guided menus for all operations.

**Option 3: Direct Command Line**

1. **Generate a certificate:**
```bash
python codesign/codesign.py cert generate --common-name "My Code Signing Cert"
```

2. **Sign a file:**
```bash
python codesign/codesign.py sign file myapp.exe -k certificates/my_cert.key -c certificates/my_cert.crt
```

3. **Verify a signature:**
```bash
python codesign/codesign.py verify signature signatures/myapp.exe.sig
```

## Graphical User Interface

CodeSign includes a comprehensive GUI built with tkinter that provides an intuitive interface for all operations.

### Launching the GUI

```bash
python codesign/gui_launcher.py
```

### GUI Features

The GUI is organized into four main tabs:

#### 1. Certificate Management
- **Generate Certificates**: Create new self-signed certificates with customizable parameters
- **Certificate Information**: View detailed information about existing certificates
- **Form Validation**: Real-time validation of certificate parameters
- **Auto-population**: Generated certificates automatically populate signing fields

#### 2. File Signing
- **File Selection**: Browse and select files to sign
- **Certificate/Key Selection**: Browse for certificates and private keys
- **Signing Options**: Choose algorithms (SHA256/384/512), padding (PSS/PKCS1v15), and crypto engines
- **Progress Tracking**: Visual progress indicators for signing operations
- **Results Display**: Detailed signing results and signature information

#### 3. Signature Verification
- **Signature File Selection**: Browse and select signature files to verify
- **File Verification**: Optionally specify alternate file locations
- **Verification Results**: Comprehensive verification results with signature details
- **Signer Information**: Display certificate information and validity

#### 4. Tools & Information
- **Signature Information**: Load and view detailed signature file contents
- **File Utilities**: Calculate file hashes and view file information
- **Folder Access**: Quick access to certificates and signatures folders
- **File Hash Calculator**: Generate SHA256 and MD5 hashes for any file

### GUI Benefits
- **User-Friendly**: No command-line knowledge required
- **Visual Feedback**: Progress bars, status messages, and color-coded results
- **Error Handling**: Clear error messages and validation
- **File Management**: Easy browsing and folder access
- **Comprehensive**: All CLI features available through the GUI

## Detailed Usage

### Certificate Generation

Generate a basic certificate:
```bash
python codesign/codesign.py cert generate --common-name "Developer Certificate"
```

Generate with custom parameters:
```bash
python codesign/codesign.py cert generate \
  --common-name "My Company Code Cert" \
  --organization "My Company Inc" \
  --country "US" \
  --key-size 4096 \
  --validity-days 730 \
  --password mypassword \
  --output-dir ./my-certificates
```

View certificate information:
```bash
python codesign/codesign.py cert info certificates/my_cert.crt
```

### File Signing

Basic file signing:
```bash
python codesign/codesign.py sign file document.pdf \
  --private-key certificates/my_cert.key \
  --certificate certificates/my_cert.crt
```

Advanced signing options:
```bash
python codesign/codesign.py sign file myapp.exe \
  --private-key my.key \
  --certificate my.crt \
  --algorithm SHA384 \
  --padding PKCS1v15 \
  --engine pycryptodome \
  --password keypassword \
  --output-dir ./signatures
```

### Signature Verification

Verify a signature:
```bash
python codesign/codesign.py verify signature signatures/document.pdf.sig
```

Verify with a different file location:
```bash
python codesign/codesign.py verify signature document.pdf.sig \
  --file-path /new/location/document.pdf
```

Verify with verbose output:
```bash
python codesign/codesign.py -v verify signature signatures/myapp.exe.sig
```

### Signature Information

View detailed signature information:
```bash
python codesign/codesign.py info signatures/document.pdf.sig
```

## Programmatic Usage

CodeSign can also be used as a Python library:

```python
from codesign import create_code_signing_certificate, sign_file, verify_file
from pathlib import Path

# Generate certificate
cert_path, key_path = create_code_signing_certificate(
    output_dir=Path("certificates"),
    common_name="My Application",
    organization="My Company",
    validity_days=365
)

# Sign a file
signature_file = sign_file(
    file_path=Path("myapp.exe"),
    private_key_path=key_path,
    certificate_path=cert_path,
    output_dir=Path("signatures"),
    algorithm="SHA256",
    use_pss=True
)

# Verify signature
is_valid = verify_file(signature_file)
print(f"Signature valid: {is_valid}")
```

## Configuration

CodeSign supports configuration files for default settings. Create a config file at `~/.codesign/config.json`:

```json
{
  "certificates": {
    "default_key_size": 2048,
    "default_validity_days": 365,
    "default_country": "US",
    "default_organization": "My Company"
  },
  "signing": {
    "default_padding": "PSS",
    "default_engine": "cryptography",
    "default_algorithm": "SHA256"
  },
  "paths": {
    "certificates_dir": "./certificates",
    "signatures_dir": "./signatures"
  }
}
```

## Command Reference

### Certificate Commands

- `cert generate` - Generate a new code signing certificate
- `cert info` - Display certificate information

### Signing Commands

- `sign file` - Sign a file with digital signature

### Verification Commands

- `verify signature` - Verify a file signature

### Utility Commands

- `info` - Display signature file information
- `examples` - Show usage examples
- `--help` - Show help for any command

## Security Considerations

### Private Key Protection
- Always use strong passwords for private key encryption
- Store private keys in secure locations with restricted access
- Consider using hardware security modules (HSMs) for production use

### Certificate Validation
- Verify certificate validity periods before signing
- Ensure certificates have proper Extended Key Usage for code signing
- Consider using certificates from trusted Certificate Authorities for distribution

### File Integrity
- Always verify signatures before trusting signed files
- Be aware that signature verification only confirms file integrity, not safety
- Implement additional security scanning for malicious content

## Architecture

### Core Components

1. **Certificate Generator** (`certgen.py`)
   - X.509 certificate creation and management
   - RSA key pair generation
   - CSR (Certificate Signing Request) creation

2. **Digital Signer** (`signer.py`)
   - File signing with RSA-PSS and PKCS#1 v1.5
   - Signature verification
   - Support for multiple hash algorithms

3. **CLI Interface** (`codesign.py`)
   - Command-line interface with Click framework
   - Colored output and progress indicators
   - Comprehensive help and examples

4. **Configuration** (`config.py`)
   - User configuration management
   - Default settings and preferences
   - Environment-specific settings

5. **Utilities** (`utils.py`)
   - File operations and validation
   - Certificate utilities
   - Security checks and formatting

### Supported Algorithms

**Hash Algorithms:**
- SHA256 (default, recommended)
- SHA384
- SHA512

**Padding Schemes:**
- RSA-PSS (default, recommended)
- PKCS#1 v1.5

**Key Sizes:**
- 2048 bits (minimum, default)
- 3072 bits
- 4096 bits

## Dependencies

- **Python 3.7+** - Required runtime
- **pycryptodomex** - Primary cryptographic library
- **pyOpenSSL** - X.509 certificate handling
- **cryptography** - Alternative crypto backend
- **click** - Command-line interface framework
- **colorama** - Cross-platform colored terminal output

## Statement from Developer

While this is intended to be run directly from the file, I (Argo Nickerson) have taken the liberty to lay it out *somewhat* like a python package, so with some configuration you could run it as its own system command. This is an untested feature so be careful!

## Copyright Information

**Copyright (c) 2025 Argo Nickerson**  
**Copyright (c) 2025 Env Open**

This project is licensed under the MIT License. This means you have the following rights:

### Your Rights Under the MIT License

- **Use** - You can use this software for any purpose, including commercial applications (Though we appreciate donations from commercial users)
- **Modify** - You can modify the source code to suit your needs  
- **Distribute** - You can share copies of the software with others  
- **Sublicense** - You can include this software in your own projects with different licenses  
- **Sell** - You can sell copies or use it in commercial products (Preferably with an optional donation to us, as it keeps our mission alive!) 

### Requirements

When using this software, you must:
- Include the original copyright notice and license text in all copies or substantial portions
- Provide attribution to the original authors and copyright holders

### Disclaimer

This software is provided "as is" without warranty of any kind. The authors are not liable for any damages arising from its use.

For the complete license text, see the [LICENSE](LICENSE) file in this repository.

### Env Open's Preferences
While not legally required, we appreciate if commercial users could:
- Donate to Env Open (Even if its just once!)
- Link to our original repository
- If your software is heavily based off of ours, shout us out somewhere within the software (Even if it's just in the --version information)

Again these are completely optional but any support from the community helps us maintain our mission of providing free and open source software

## External Packages

CodeSign uses external packages, you can find all associated copyright here

### pycryptodomex (Cryptodome)
- License: Public Domain [unlicense] (partial) | BSD (Partial)
- [Github](https://github.com/Legrandin/pycryptodome)
- [pypi link](https://pypi.org/project/pycryptodomex/)
- [Homepage](http://www.pycryptodome.org/)
- [Online License Text](https://github.com/Legrandin/pycryptodome/blob/master/LICENSE.rst)

### pyOpenSSL
- License: Apache License 2.0
- [Github](https://github.com/pyca/pyopenssl)
- [pypi link](https://pypi.org/project/pyOpenSSL/)

### cryptography
- License: Apache License 2.0 / BSD License
- [Github](https://github.com/pyca/cryptography)
- [pypi link](https://pypi.org/project/cryptography/)

### Click
- License: BSD-3-Clause
- [Github](https://github.com/pallets/click)
- [pypi link](https://pypi.org/project/click/)

### Colorama
- License: BSD License
- [Github](https://github.com/tartley/colorama)
- [pypi link](https://pypi.org/project/colorama/)

## Contributing

We welcome contributions! Please feel free to submit pull requests, report bugs, or suggest features.

## Support

For support, please open an issue on the GitHub repository or contact the maintainers.

---

**CodeSign - Secure, Simple, Reliable Code Signing**
- [Included License Text](external_licenses/pycryptodomex)
- Version: 3.23.0
- Cloned: 02/08/2025 (DD/MM/YYYY)