from PyInstaller.__main__ import run
import json

def load_info():
    with open('codesign/versioninfo.json', 'r') as f:
        return json.load(f)

def build_gui():
    """Build the CodeSign GUI application."""
    print("Building CodeSign GUI...")
    
    # Define the PyInstaller command
    cmd = [
        f'--name=CodeSignGUI-v{load_info()["version"]}',
        '--onefile',
        '--windowed',
        './codesign/gui_launcher.py'
    ]
    
    # Run PyInstaller
    run(cmd)
    
    print("CodeSign GUI build completed successfully.")

def build_cli():
    """Build the CodeSign CLI application."""
    print("Building CodeSign CLI...")
    
    # Define the PyInstaller command
    cmd = [
        f'--name=CodeSignCLI-v{load_info()["version"]}',
        '--onefile',
        './codesign/codesign.py'
    ]
    
    # Run PyInstaller
    run(cmd)
    
    print("CodeSign CLI build completed successfully.")


if __name__ == "__main__":
    from argparse import ArgumentParser
    parser = ArgumentParser(description="Build CodeSign applications")
    parser.add_argument('--gui', action='store_true', help="Build the CodeSign GUI application")
    parser.add_argument('--cli', action='store_true', help="Build the CodeSign CLI application")
    parser.add_argument('--all', action='store_true', help="Build both GUI and CLI applications")
    args = parser.parse_args()

    if args.gui:
        build_gui()
    if args.cli:
        build_cli()
    if args.all:
        build_gui()
        build_cli()
    if not (args.gui or args.cli or args.all):
        print("No build option specified. Use --gui, --cli, or --all to build the applications.")
        parser.print_help()
        exit(1)

    print("Build process completed. Check the 'dist' directory for the output files.")