#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (c) 2025, Env Open
# Copyright (c) 2025, Argo Nickerson

# This script shall always be under the MIT license, even after any changes to the overall codebase, as this is seen as a useful and adaptable utility. 
# While this is not legally binding (we think) we promise to uphold this statement.
"""
Version Update Script for CodeSign
Automatically updates version references across the entire codebase.
"""

import os
import re
import json
import argparse
from pathlib import Path
from typing import List, Tuple, Dict


class VersionUpdater:
    """Handles updating version references across the codebase."""
    def __init__(self, root_dir: Path | None = None):
        self.root_dir = root_dir or Path(__file__).parent
        self.version_files = []  # Files that contain version references
        self.backup_files = []   # Files to backup before changes
        
        # Define patterns to search for version references
        self.version_patterns = [
            (r'__version__\s*=\s*["\']([^"\']+)["\']', '__version__ = "{}"'),
            (r'version\s*=\s*["\']([^"\']+)["\']', 'version = "{}"'),
            (r'# CodeSign v([0-9\.]+(?:-[a-zA-Z0-9]+)?)', '# CodeSign v{}'),
            (r'CodeSign v([0-9\.]+(?:-[a-zA-Z0-9]+)?)', 'CodeSign v{}'),
            (r'CodeSign GUI v([0-9\.]+(?:-[a-zA-Z0-9]+)?)', 'CodeSign GUI v{}'),
            (r'"version"\s*:\s*"v?([^"]+)"', '"version": "v{}"'),
        ]
        
        # Files to process (relative to root_dir)
        self.target_files = [
            'codesign/__init__.py',
            'codesign/codesign.py',
            'codesign/codesign_old.py',
            'codesign/codesign_new.py',
            'codesign/gui/codesigngui.py',
            'codesign/versioninfo.json',
            'README.md',
            'setup.py',
        ]
    
    def get_current_version(self) -> str:
        """Get the current version from the main __init__.py file."""
        init_file = self.root_dir / 'codesign' / '__init__.py'
        if not init_file.exists():
            raise FileNotFoundError(f"Cannot find {init_file}")
        
        content = init_file.read_text()
        match = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', content)
        if match:
            return match.group(1)
        
        raise ValueError("Could not find version in __init__.py")
    
    def find_version_references(self) -> List[Tuple[Path, str, List[str]]]:
        """Find all version references in the codebase."""
        references = []
        
        for file_pattern in self.target_files:
            file_path = self.root_dir / file_pattern
            
            if not file_path.exists():
                print(f"⚠️  File not found: {file_path}")
                continue
            
            try:
                content = file_path.read_text()
                found_versions = []
                
                for pattern, _ in self.version_patterns:
                    matches = re.finditer(pattern, content)
                    for match in matches:
                        found_versions.append(match.group(1))
                
                if found_versions:
                    # Remove duplicates while preserving order
                    unique_versions = list(dict.fromkeys(found_versions))
                    references.append((file_path, file_pattern, unique_versions))
                    
            except Exception as e:
                print(f"❌ Error reading {file_path}: {e}")
        
        return references
    
    def update_version_in_file(self, file_path: Path, new_version: str, dry_run: bool = False) -> bool:
        """Update version references in a single file."""
        try:
            content = file_path.read_text()
            original_content = content
            updated = False
            
            for pattern, replacement_template in self.version_patterns:
                def replace_version(match):
                    nonlocal updated
                    old_version = match.group(1)
                    if old_version != new_version:
                        updated = True
                        print(f"  📝 {old_version} → {new_version}")
                        
                        # Special handling for JSON files
                        if file_path.suffix == '.json':
                            if new_version.startswith('v'):
                                return replacement_template.format(new_version)
                            else:
                                return replacement_template.format(f"v{new_version}")
                        else:
                            # Remove 'v' prefix for Python files
                            clean_version = new_version.lstrip('v')
                            return replacement_template.format(clean_version)
                    return match.group(0)
                
                content = re.sub(pattern, replace_version, content)
            
            if updated and not dry_run:
                # Create backup
                backup_path = file_path.with_suffix(file_path.suffix + '.bak')
                backup_path.write_text(original_content)
                print(f"  💾 Backup created: {backup_path}")
                
                # Write updated content
                file_path.write_text(content)
                print(f"  ✅ Updated: {file_path}")
            elif updated and dry_run:
                print(f"  🔍 Would update: {file_path}")
            
            return updated
            
        except Exception as e:
            print(f"❌ Error updating {file_path}: {e}")
            return False
    
    def update_all_versions(self, new_version: str, dry_run: bool = False) -> bool:
        """Update version references in all target files."""
        print(f"🔄 {'Dry run: ' if dry_run else ''}Updating all version references to: {new_version}")
        print("=" * 60)
        
        success = True
        updated_files = 0
        
        for file_pattern in self.target_files:
            file_path = self.root_dir / file_pattern
            
            if not file_path.exists():
                print(f"⚠️  Skipping missing file: {file_path}")
                continue
            
            print(f"🔍 Processing: {file_pattern}")
            
            if self.update_version_in_file(file_path, new_version, dry_run):
                updated_files += 1
            else:
                print(f"  ℹ️  No changes needed")
            
            print()
        
        print("=" * 60)
        if dry_run:
            print(f"🔍 Dry run complete. {updated_files} files would be updated.")
        else:
            print(f"✅ Update complete. {updated_files} files updated.")
            print("💡 Backup files (.bak) created for modified files.")
        
        return success
    
    def cleanup_backups(self):
        """Remove all backup files created during updates."""
        backup_files = list(self.root_dir.rglob("*.bak"))
        
        if not backup_files:
            print("ℹ️  No backup files found.")
            return
        
        print(f"🧹 Found {len(backup_files)} backup files:")
        for backup_file in backup_files:
            print(f"  🗑️  {backup_file}")
            backup_file.unlink()
        
        print("✅ All backup files removed.")
    
    def validate_version_format(self, version: str) -> bool:
        """Validate version format."""
        # Remove 'v' prefix if present
        clean_version = version.lstrip('v')
        
        # Check if it matches semantic versioning pattern
        pattern = r'^(\d+)\.(\d+)\.(\d+)(?:-([a-zA-Z0-9\-]+))?$'
        return bool(re.match(pattern, clean_version))
    
    def report_current_versions(self):
        """Report all current version references found in the codebase."""
        print("📊 Current Version References Report")
        print("=" * 60)
        
        references = self.find_version_references()
        
        if not references:
            print("ℹ️  No version references found.")
            return
        
        all_versions = set()
        for file_path, file_pattern, versions in references:
            print(f"📄 {file_pattern}:")
            for version in versions:
                print(f"  • {version}")
                all_versions.add(version)
            print()
        
        print("📋 Summary:")
        print(f"  • Files with versions: {len(references)}")
        print(f"  • Unique versions found: {sorted(all_versions)}")
        
        if len(all_versions) > 1:
            print("⚠️  Warning: Multiple different versions found!")
        else:
            print("✅ All version references are consistent.")


def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description="Update version references across the CodeSign codebase",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python update_version.py --report                    # Show current versions
  python update_version.py --set 1.1.0                # Update to version 1.1.0
  python update_version.py --set 1.1.0 --dry-run      # Preview changes
  python update_version.py --cleanup                   # Remove backup files
  python update_version.py --set 2.0.0-beta           # Update to beta version
        """
    )
    
    parser.add_argument(
        '--set', 
        type=str, 
        help='Set new version (e.g., 1.1.0, 2.0.0-alpha, v1.2.3)'
    )
    parser.add_argument(
        '--report', 
        action='store_true', 
        help='Report current version references'
    )
    parser.add_argument(
        '--dry-run', 
        action='store_true', 
        help='Preview changes without modifying files'
    )
    parser.add_argument(
        '--cleanup', 
        action='store_true', 
        help='Remove backup files created during updates'
    )
    parser.add_argument(
        '--root-dir',
        type=Path,
        help='Root directory of the project (default: script directory)'
    )
    
    args = parser.parse_args()
    
    # Initialize updater
    updater = VersionUpdater(args.root_dir)
    
    # Handle different operations
    if args.cleanup:
        updater.cleanup_backups()
        return
    
    if args.report:
        updater.report_current_versions()
        return
    
    if args.set:
        new_version = args.set
        
        # Validate version format
        if not updater.validate_version_format(new_version):
            print(f"❌ Invalid version format: {new_version}")
            print("   Expected format: X.Y.Z or X.Y.Z-suffix (e.g., 1.0.0, 2.1.3-alpha)")
            return 1
        
        # Perform update
        success = updater.update_all_versions(new_version, args.dry_run)
        return 0 if success else 1
    
    # No action specified
    parser.print_help()
    return 1


if __name__ == "__main__":
    exit(main())
