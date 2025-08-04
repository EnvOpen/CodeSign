#!/usr/bin/env python3
"""
Build script for CodeSign applications using PyInstaller
"""

import sys
import os
import shutil
from pathlib import Path
from PyInstaller.__main__ import run
import json

def load_info():
    """Load version information from JSON file."""
    with open('codesign/versioninfo.json', 'r') as f:
        return json.load(f)

def get_build_options():
    """Get platform-specific build options."""
    options = []
    
    # Add hidden imports that PyInstaller might miss
    hidden_imports = [
        'codesign',
        'codesign.crypto_handlers',
        'codesign.crypto_handlers.certgen',
        'codesign.crypto_handlers.signer',
        'codesign.utils',
        'codesign.config',
        'codesign.gui',
        'codesign.gui.codesigngui',
        'tkinter',
        'tkinter.ttk',
        'tkinter.filedialog',
        'tkinter.messagebox',
        'tkinter.scrolledtext',
        'OpenSSL',
        'cryptography',
        'cryptography.hazmat',
        'cryptography.hazmat.primitives',
        'cryptography.hazmat.backends',
        'cryptography.hazmat.primitives.asymmetric',
        'cryptography.hazmat.primitives.serialization',
        'cryptography.x509',
        'click',
        'colorama'
    ]
    
    for import_name in hidden_imports:
        options.extend(['--hidden-import', import_name])
    
    # Add data files
    options.extend([
        '--add-data', 'codesign/versioninfo.json:codesign',
        '--add-data', 'codesign/__init__.py:codesign',
    ])
    
    # Platform-specific options
    if sys.platform.startswith('linux'):
        # Linux-specific fixes for the shared library issue
        options.extend([
            '--collect-all', 'cryptography',
            '--collect-all', 'OpenSSL',
            '--exclude-module', 'tkinter.test',
            '--exclude-module', 'test',
            '--strip',  # Strip debug symbols to reduce size
            '--noupx',  # Disable UPX compression which can cause issues
        ])
    elif sys.platform == 'win32':
        # Windows-specific options
        options.extend([
            '--collect-all', 'cryptography',
            '--collect-all', 'OpenSSL'
        ])
    elif sys.platform == 'darwin':
        # macOS-specific options
        options.extend([
            '--collect-all', 'cryptography',
            '--collect-all', 'OpenSSL'
        ])
    
    return options

def build_gui():
    """Build the CodeSign GUI application."""
    print("Building CodeSign GUI...")
    
    # Base command
    cmd = [
        f'--name=CodeSignGUI-v{load_info()["version"]}',
        '--onefile',
        '--windowed',
        '--clean',  # Clean build directory
        '--noconfirm',  # Overwrite without asking
    ]
    
    # Add platform-specific options
    cmd.extend(get_build_options())
    
    # Add the main script
    cmd.append('./codesign/gui_launcher.py')
    
    print(f"PyInstaller command: pyinstaller {' '.join(cmd)}")
    
    try:
        # Run PyInstaller
        run(cmd)
        print("✅ CodeSign GUI build completed successfully.")
        
        # Check if the executable was created
        exe_name = f"CodeSignGUI-v{load_info()['version']}"
        if sys.platform == 'win32':
            exe_name += '.exe'
        
        exe_path = Path('dist') / exe_name
        if exe_path.exists():
            print(f"📦 Executable created: {exe_path}")
            print(f"📏 Size: {exe_path.stat().st_size / (1024*1024):.1f} MB")
        else:
            print("⚠️ Warning: Executable not found in expected location")
            
    except Exception as e:
        print(f"❌ GUI build failed: {e}")
        return False
    
    return True

def build_cli():
    """Build the CodeSign CLI application."""
    print("Building CodeSign CLI...")
    
    # Base command
    cmd = [
        f'--name=CodeSignCLI-v{load_info()["version"]}',
        '--onefile',
        '--clean',
        '--noconfirm',
    ]
    
    # Add platform-specific options
    cmd.extend(get_build_options())
    
    # Add the main script
    cmd.append('./codesign/codesign.py')
    
    print(f"PyInstaller command: pyinstaller {' '.join(cmd)}")
    
    try:
        # Run PyInstaller
        run(cmd)
        print("✅ CodeSign CLI build completed successfully.")
        
        # Check if the executable was created
        exe_name = f"CodeSignCLI-v{load_info()['version']}"
        if sys.platform == 'win32':
            exe_name += '.exe'
        
        exe_path = Path('dist') / exe_name
        if exe_path.exists():
            print(f"📦 Executable created: {exe_path}")
            print(f"📏 Size: {exe_path.stat().st_size / (1024*1024):.1f} MB")
        else:
            print("⚠️ Warning: Executable not found in expected location")
            
    except Exception as e:
        print(f"❌ CLI build failed: {e}")
        return False
    
    return True


def clean_build():
    """Clean build artifacts."""
    print("Cleaning build artifacts...")
    
    dirs_to_clean = ['build', '__pycache__']
    files_to_clean = ['*.spec']
    
    for dir_name in dirs_to_clean:
        if Path(dir_name).exists():
            shutil.rmtree(dir_name)
            print(f"🗑️ Removed {dir_name}/")
    
    # Remove .spec files
    for spec_file in Path('.').glob('*.spec'):
        spec_file.unlink()
        print(f"🗑️ Removed {spec_file}")
    
    print("✅ Build cleanup completed")


def main():
    """Main build function."""
    from argparse import ArgumentParser
    
    parser = ArgumentParser(description="Build CodeSign applications with PyInstaller")
    parser.add_argument('--gui', action='store_true', help="Build the CodeSign GUI application")
    parser.add_argument('--cli', action='store_true', help="Build the CodeSign CLI application")
    parser.add_argument('--all', action='store_true', help="Build both GUI and CLI applications")
    parser.add_argument('--clean', action='store_true', help="Clean build artifacts before building")
    parser.add_argument('--clean-only', action='store_true', help="Only clean build artifacts")
    
    args = parser.parse_args()
    
    print(f"🔨 CodeSign Build Script v{load_info()['version']}")
    print(f"🐍 Python: {sys.version}")
    print(f"💻 Platform: {sys.platform}")
    print("=" * 50)
    
    # Clean only
    if args.clean_only:
        clean_build()
        return
    
    # Clean before build if requested
    if args.clean:
        clean_build()
    
    # Ensure dist directory exists
    Path('dist').mkdir(exist_ok=True)
    
    built_apps = []
    
    # Build applications
    if args.gui or args.all:
        if build_gui():
            exe_name = f"CodeSignGUI-v{load_info()['version']}"
            if sys.platform == 'win32':
                exe_name += '.exe'
            built_apps.append(Path('dist') / exe_name)
    
    if args.cli or args.all:
        if build_cli():
            exe_name = f"CodeSignCLI-v{load_info()['version']}"
            if sys.platform == 'win32':
                exe_name += '.exe'
            built_apps.append(Path('dist') / exe_name)
    
    # No build option specified
    if not (args.gui or args.cli or args.all):
        print("❌ No build option specified. Use --gui, --cli, or --all to build applications.")
        parser.print_help()
        return 1
    
    print("\n" + "=" * 50)
    print("🎉 Build process completed!")
    
    if built_apps:
        print("📦 Built applications:")
        for exe_path in built_apps:
            if exe_path.exists():
                size_mb = exe_path.stat().st_size / (1024*1024)
                print(f"  ✅ {exe_path} ({size_mb:.1f} MB)")
            else:
                print(f"  ❌ {exe_path} (not found)")
    
    print(f"\n💡 Check the 'dist' directory for output files")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())