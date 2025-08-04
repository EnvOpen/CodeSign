# Version Management

This document explains how to manage version numbers across the CodeSign codebase using the automated version update script.

## Version Update Script

The `update_version.py` script automatically updates version references across all files in the codebase, ensuring consistency.

### Usage

```bash
# Show current version references across all files
python3 update_version.py --report

# Preview changes for a new version (dry run)
python3 update_version.py --set 1.1.0 --dry-run

# Actually update to a new version
python3 update_version.py --set 1.1.0

# Update to a beta/alpha version
python3 update_version.py --set 2.0.0-alpha

# Clean up backup files after updates
python3 update_version.py --cleanup

# Show help
python3 update_version.py --help
```

### Files Updated

The script automatically updates version references in:

- `codesign/__init__.py` - Main package version
- `codesign/codesign.py` - CLI version
- `codesign/gui/codesigngui.py` - GUI version  
- `codesign/versioninfo.json` - Version info file
- `README.md` - Documentation version
- All backup files (`codesign_old.py`, `codesign_new.py`)

### Version Format

Versions should follow semantic versioning format:
- `X.Y.Z` (e.g., `1.0.0`, `2.1.3`)
- `X.Y.Z-suffix` (e.g., `1.0.0-alpha`, `2.0.0-beta`, `1.5.0-rc1`)

### Safety Features

- **Dry Run**: Preview changes before applying them
- **Automatic Backups**: Creates `.bak` files for all modified files
- **Validation**: Ensures version format is valid before proceeding
- **Consistency Check**: Reports if multiple versions are found

### Examples

```bash
# Release version 1.1.0
python3 update_version.py --set 1.1.0

# Create beta version
python3 update_version.py --set 1.2.0-beta

# Check what would change (safe)
python3 update_version.py --set 2.0.0 --dry-run

# After confirming changes look good
python3 update_version.py --set 2.0.0

# Clean up backup files when satisfied
python3 update_version.py --cleanup
```

### Integration with Build Process

The version from `codesign/versioninfo.json` is automatically used by:
- `build.py` for PyInstaller executable names
- Package imports for runtime version checking
- CLI `--version` command output
- GUI title bar and about dialogs

This ensures all version references stay synchronized across the entire codebase.
