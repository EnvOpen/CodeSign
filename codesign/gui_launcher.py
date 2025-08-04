#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (c) 2025, Env Open
# Copyright (c) 2025, Argo Nickerson

"""
CodeSign GUI Launcher
Enhanced launcher for the CodeSign graphical user interface with better error handling.
"""

import sys
import os
from pathlib import Path

# Add the parent directory to sys.path to import our modules
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

def check_dependencies():
    """Check if all required dependencies are available."""
    missing_deps = []
    
    try:
        import tkinter
    except ImportError:
        missing_deps.append("tkinter (python3-tk)")
    
    try:
        import cryptography
    except ImportError:
        missing_deps.append("cryptography")
    
    try:
        import OpenSSL
    except ImportError:
        missing_deps.append("pyOpenSSL")
    
    try:
        import click
    except ImportError:
        missing_deps.append("click")
    
    try:
        import colorama
    except ImportError:
        missing_deps.append("colorama")
    
    return missing_deps

def main():
    """Launch the CodeSign GUI with comprehensive error handling."""
    print("🚀 CodeSign GUI v1.0.0")
    print("======================")
    
    # Check dependencies first
    missing_deps = check_dependencies()
    if missing_deps:
        print("❌ Missing dependencies:")
        for dep in missing_deps:
            print(f"   - {dep}")
        print("\nPlease install missing dependencies:")
        print("   pip3 install cryptography pyOpenSSL click colorama")
        if "tkinter" in str(missing_deps):
            print("   For tkinter on Ubuntu/Debian: sudo apt install python3-tk")
        sys.exit(1)
    
    print("✅ All dependencies found")
    
    try:
        # Import and run the GUI
        from codesign.gui.codesigngui import main as gui_main
        print("🎨 Starting GUI...")
        gui_main()
        
    except ImportError as e:
        print(f"❌ Error importing CodeSign GUI: {e}")
        print("Please ensure CodeSign is properly installed in your environment.")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error starting CodeSign GUI: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
