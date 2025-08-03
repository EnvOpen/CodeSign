#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (c) 2025, Env Open
# Copyright (c) 2025, Argo Nickerson

"""
CodeSign GUI Launcher
Standalone launcher for the CodeSign graphical user interface.
"""

import sys
from pathlib import Path

# Add the parent directory to sys.path to import our modules
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from codesign.gui import main
    
    if __name__ == "__main__":
        print("Starting CodeSign GUI...")
        main()
        
except ImportError as e:
    print(f"Error: Could not import CodeSign GUI modules: {e}")
    print("Please ensure all dependencies are installed and CodeSign is properly set up.")
    sys.exit(1)
except Exception as e:
    print(f"Error: Failed to start CodeSign GUI: {e}")
    sys.exit(1)
