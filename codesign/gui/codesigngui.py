#! /usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (c) 2025, Env Open
# Copyright (c) 2025, Argo Nickerson

"""
CodeSign GUI - Graphical User Interface for CodeSign
A user-friendly GUI for the CodeSign digital signing platform.
"""

import os
import sys
import threading
import webbrowser
from pathlib import Path
from typing import Optional, Dict, Any
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

# Add the parent directories to sys.path to import our modules
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

try:
    from codesign.crypto_handlers import (
        CertificateGenerator,
        create_code_signing_certificate,
        DigitalSigner,
        sign_file,
        verify_file
    )
    from codesign.utils import FileUtils, CertUtils, FormatUtils
    from codesign.config import get_config
except ImportError as e:
    print(f"Error importing CodeSign modules: {e}")
    print("Please ensure all dependencies are installed and CodeSign is properly set up.")
    sys.exit(1)

# Version information
__version__ = "1.0.0-alpha"


class CodeSignGUI:
    """Main GUI application for CodeSign."""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title(f"CodeSign GUI v{__version__}")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)
        
        # Configure the style
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Application state
        self.config = get_config()
        self.current_cert_path = None
        self.current_key_path = None
        self.current_signature_path = None
        
        # Create the GUI
        self.create_widgets()
        self.center_window()
        
        # Set up icon (if available)
        try:
            # You can add an icon file here
            pass
        except:
            pass
    
    def center_window(self):
        """Center the window on the screen."""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
    
    def create_widgets(self):
        """Create and layout all GUI widgets."""
        # Create main banner
        self.create_banner()
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create tabs
        self.create_certificate_tab()
        self.create_signing_tab()
        self.create_verification_tab()
        self.create_tools_tab()
        
        # Create status bar
        self.create_status_bar()
    
    def create_banner(self):
        """Create the application banner."""
        banner_frame = ttk.Frame(self.root)
        banner_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Title
        title_label = ttk.Label(
            banner_frame,
            text=f"CodeSign v{__version__}",
            font=("Arial", 16, "bold")
        )
        title_label.pack(side=tk.LEFT)
        
        # Subtitle
        subtitle_label = ttk.Label(
            banner_frame,
            text="Digital Code Signing Utility",
            font=("Arial", 10)
        )
        subtitle_label.pack(side=tk.LEFT, padx=(10, 0))
        
        # Help button
        help_button = ttk.Button(
            banner_frame,
            text="Help",
            command=self.show_help
        )
        help_button.pack(side=tk.RIGHT)
        
        # About button
        about_button = ttk.Button(
            banner_frame,
            text="About",
            command=self.show_about
        )
        about_button.pack(side=tk.RIGHT, padx=(0, 5))
    
    def create_certificate_tab(self):
        """Create the certificate management tab."""
        cert_frame = ttk.Frame(self.notebook)
        self.notebook.add(cert_frame, text="Certificate Management")
        
        # Certificate generation section
        gen_group = ttk.LabelFrame(cert_frame, text="Generate New Certificate")
        gen_group.pack(fill=tk.X, padx=10, pady=5)
        
        # Common Name
        ttk.Label(gen_group, text="Common Name *:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.cert_common_name = ttk.Entry(gen_group, width=40)
        self.cert_common_name.grid(row=0, column=1, columnspan=2, sticky=tk.W+tk.E, padx=5, pady=2)
        
        # Organization
        ttk.Label(gen_group, text="Organization:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        self.cert_organization = ttk.Entry(gen_group, width=40)
        self.cert_organization.insert(0, "CodeSign User")
        self.cert_organization.grid(row=1, column=1, columnspan=2, sticky=tk.W+tk.E, padx=5, pady=2)
        
        # Country
        ttk.Label(gen_group, text="Country:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=2)
        self.cert_country = ttk.Entry(gen_group, width=10)
        self.cert_country.insert(0, "US")
        self.cert_country.grid(row=2, column=1, sticky=tk.W, padx=5, pady=2)
        
        # Key Size
        ttk.Label(gen_group, text="Key Size:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=2)
        self.cert_key_size = ttk.Combobox(gen_group, values=["2048", "3072", "4096"], state="readonly", width=10)
        self.cert_key_size.set("2048")
        self.cert_key_size.grid(row=3, column=1, sticky=tk.W, padx=5, pady=2)
        
        # Validity Days
        ttk.Label(gen_group, text="Validity (days):").grid(row=4, column=0, sticky=tk.W, padx=5, pady=2)
        self.cert_validity = ttk.Entry(gen_group, width=10)
        self.cert_validity.insert(0, "365")
        self.cert_validity.grid(row=4, column=1, sticky=tk.W, padx=5, pady=2)
        
        # Output Directory
        ttk.Label(gen_group, text="Output Directory:").grid(row=5, column=0, sticky=tk.W, padx=5, pady=2)
        self.cert_output_dir = ttk.Entry(gen_group, width=30)
        self.cert_output_dir.insert(0, str(Path.cwd() / "certificates"))
        self.cert_output_dir.grid(row=5, column=1, sticky=tk.W+tk.E, padx=5, pady=2)
        ttk.Button(gen_group, text="Browse", command=self.browse_cert_output_dir).grid(row=5, column=2, padx=5, pady=2)
        
        # Password
        ttk.Label(gen_group, text="Password (optional):").grid(row=6, column=0, sticky=tk.W, padx=5, pady=2)
        self.cert_password = ttk.Entry(gen_group, show="*", width=30)
        self.cert_password.grid(row=6, column=1, sticky=tk.W+tk.E, padx=5, pady=2)
        
        # Generate button
        ttk.Button(gen_group, text="Generate Certificate", command=self.generate_certificate).grid(
            row=7, column=0, columnspan=3, pady=10
        )
        
        # Configure grid weights
        gen_group.columnconfigure(1, weight=1)
        
        # Certificate info section
        info_group = ttk.LabelFrame(cert_frame, text="Certificate Information")
        info_group.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Certificate file selection
        cert_file_frame = ttk.Frame(info_group)
        cert_file_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(cert_file_frame, text="Certificate File:").pack(side=tk.LEFT)
        self.cert_info_path = ttk.Entry(cert_file_frame, width=50)
        self.cert_info_path.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Button(cert_file_frame, text="Browse", command=self.browse_cert_info_file).pack(side=tk.RIGHT)
        ttk.Button(cert_file_frame, text="Load Info", command=self.load_cert_info).pack(side=tk.RIGHT, padx=(0, 5))
        
        # Certificate info display
        self.cert_info_text = scrolledtext.ScrolledText(info_group, height=10, state=tk.DISABLED)
        self.cert_info_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def create_signing_tab(self):
        """Create the file signing tab."""
        sign_frame = ttk.Frame(self.notebook)
        self.notebook.add(sign_frame, text="File Signing")
        
        # File selection section
        file_group = ttk.LabelFrame(sign_frame, text="File to Sign")
        file_group.pack(fill=tk.X, padx=10, pady=5)
        
        file_frame = ttk.Frame(file_group)
        file_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(file_frame, text="File to sign:").pack(side=tk.LEFT)
        self.sign_file_path = ttk.Entry(file_frame, width=50)
        self.sign_file_path.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Button(file_frame, text="Browse", command=self.browse_sign_file).pack(side=tk.RIGHT)
        
        # Certificate and key selection
        cert_group = ttk.LabelFrame(sign_frame, text="Certificate and Key")
        cert_group.pack(fill=tk.X, padx=10, pady=5)
        
        # Private key
        key_frame = ttk.Frame(cert_group)
        key_frame.pack(fill=tk.X, padx=5, pady=2)
        ttk.Label(key_frame, text="Private Key:").pack(side=tk.LEFT)
        self.sign_key_path = ttk.Entry(key_frame, width=50)
        self.sign_key_path.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Button(key_frame, text="Browse", command=self.browse_sign_key).pack(side=tk.RIGHT)
        
        # Certificate
        cert_frame = ttk.Frame(cert_group)
        cert_frame.pack(fill=tk.X, padx=5, pady=2)
        ttk.Label(cert_frame, text="Certificate:").pack(side=tk.LEFT)
        self.sign_cert_path = ttk.Entry(cert_frame, width=50)
        self.sign_cert_path.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Button(cert_frame, text="Browse", command=self.browse_sign_cert).pack(side=tk.RIGHT)
        
        # Key password
        pwd_frame = ttk.Frame(cert_group)
        pwd_frame.pack(fill=tk.X, padx=5, pady=2)
        ttk.Label(pwd_frame, text="Key Password:").pack(side=tk.LEFT)
        self.sign_key_password = ttk.Entry(pwd_frame, show="*", width=30)
        self.sign_key_password.pack(side=tk.LEFT, padx=5)
        
        # Signing options
        options_group = ttk.LabelFrame(sign_frame, text="Signing Options")
        options_group.pack(fill=tk.X, padx=10, pady=5)
        
        options_frame = ttk.Frame(options_group)
        options_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Algorithm
        ttk.Label(options_frame, text="Algorithm:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.sign_algorithm = ttk.Combobox(options_frame, values=["SHA256", "SHA384", "SHA512"], state="readonly")
        self.sign_algorithm.set("SHA256")
        self.sign_algorithm.grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
        
        # Padding
        ttk.Label(options_frame, text="Padding:").grid(row=0, column=2, sticky=tk.W, padx=5, pady=2)
        self.sign_padding = ttk.Combobox(options_frame, values=["PSS", "PKCS1v15"], state="readonly")
        self.sign_padding.set("PSS")
        self.sign_padding.grid(row=0, column=3, sticky=tk.W, padx=5, pady=2)
        
        # Engine
        ttk.Label(options_frame, text="Engine:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        self.sign_engine = ttk.Combobox(options_frame, values=["cryptography", "pycryptodome"], state="readonly")
        self.sign_engine.set("cryptography")
        self.sign_engine.grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)
        
        # Output directory
        ttk.Label(options_frame, text="Output Dir:").grid(row=1, column=2, sticky=tk.W, padx=5, pady=2)
        self.sign_output_dir = ttk.Entry(options_frame, width=20)
        self.sign_output_dir.insert(0, str(Path.cwd() / "signatures"))
        self.sign_output_dir.grid(row=1, column=3, sticky=tk.W+tk.E, padx=5, pady=2)
        
        options_frame.columnconfigure(3, weight=1)
        
        # Sign button
        ttk.Button(sign_frame, text="Sign File", command=self.sign_file_action, style="Accent.TButton").pack(pady=10)
        
        # Progress and results
        self.sign_progress = ttk.Progressbar(sign_frame, mode='indeterminate')
        self.sign_progress.pack(fill=tk.X, padx=10, pady=5)
        self.sign_progress.pack_forget()  # Hide initially
        
        # Results text
        result_group = ttk.LabelFrame(sign_frame, text="Results")
        result_group.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.sign_result_text = scrolledtext.ScrolledText(result_group, height=8, state=tk.DISABLED)
        self.sign_result_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def create_verification_tab(self):
        """Create the signature verification tab."""
        verify_frame = ttk.Frame(self.notebook)
        self.notebook.add(verify_frame, text="Signature Verification")
        
        # Signature file selection
        sig_group = ttk.LabelFrame(verify_frame, text="Signature File")
        sig_group.pack(fill=tk.X, padx=10, pady=5)
        
        sig_frame = ttk.Frame(sig_group)
        sig_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(sig_frame, text="Signature File:").pack(side=tk.LEFT)
        self.verify_sig_path = ttk.Entry(sig_frame, width=50)
        self.verify_sig_path.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Button(sig_frame, text="Browse", command=self.browse_verify_sig).pack(side=tk.RIGHT)
        
        # Optional file path
        file_group = ttk.LabelFrame(verify_frame, text="File to Verify (Optional)")
        file_group.pack(fill=tk.X, padx=10, pady=5)
        
        file_frame = ttk.Frame(file_group)
        file_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(file_frame, text="File Path:").pack(side=tk.LEFT)
        self.verify_file_path = ttk.Entry(file_frame, width=50)
        self.verify_file_path.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Button(file_frame, text="Browse", command=self.browse_verify_file).pack(side=tk.RIGHT)
        
        ttk.Label(file_group, text="Leave empty to verify against original file location", 
                 font=("Arial", 8)).pack(padx=5, pady=2)
        
        # Verification options
        options_group = ttk.LabelFrame(verify_frame, text="Verification Options")
        options_group.pack(fill=tk.X, padx=10, pady=5)
        
        options_frame = ttk.Frame(options_group)
        options_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(options_frame, text="Engine:").pack(side=tk.LEFT)
        self.verify_engine = ttk.Combobox(options_frame, values=["cryptography", "pycryptodome"], state="readonly")
        self.verify_engine.set("cryptography")
        self.verify_engine.pack(side=tk.LEFT, padx=5)
        
        # Verify button
        ttk.Button(verify_frame, text="Verify Signature", command=self.verify_signature_action, 
                  style="Accent.TButton").pack(pady=10)
        
        # Progress
        self.verify_progress = ttk.Progressbar(verify_frame, mode='indeterminate')
        self.verify_progress.pack(fill=tk.X, padx=10, pady=5)
        self.verify_progress.pack_forget()  # Hide initially
        
        # Results
        result_group = ttk.LabelFrame(verify_frame, text="Verification Results")
        result_group.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.verify_result_text = scrolledtext.ScrolledText(result_group, height=12, state=tk.DISABLED)
        self.verify_result_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def create_tools_tab(self):
        """Create the tools and utilities tab."""
        tools_frame = ttk.Frame(self.notebook)
        self.notebook.add(tools_frame, text="Tools & Info")
        
        # Signature info section
        info_group = ttk.LabelFrame(tools_frame, text="Signature Information")
        info_group.pack(fill=tk.X, padx=10, pady=5)
        
        info_frame = ttk.Frame(info_group)
        info_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(info_frame, text="Signature File:").pack(side=tk.LEFT)
        self.tools_sig_path = ttk.Entry(info_frame, width=50)
        self.tools_sig_path.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Button(info_frame, text="Browse", command=self.browse_tools_sig).pack(side=tk.RIGHT)
        ttk.Button(info_frame, text="Load Info", command=self.load_signature_info).pack(side=tk.RIGHT, padx=(0, 5))
        
        # Info display
        self.tools_info_text = scrolledtext.ScrolledText(info_group, height=8, state=tk.DISABLED)
        self.tools_info_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # File utilities section
        utils_group = ttk.LabelFrame(tools_frame, text="File Utilities")
        utils_group.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        utils_buttons_frame = ttk.Frame(utils_group)
        utils_buttons_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(utils_buttons_frame, text="Calculate File Hash", 
                  command=self.calculate_file_hash).pack(side=tk.LEFT, padx=5)
        ttk.Button(utils_buttons_frame, text="View File Info", 
                  command=self.view_file_info).pack(side=tk.LEFT, padx=5)
        ttk.Button(utils_buttons_frame, text="Open Certificates Folder", 
                  command=self.open_certificates_folder).pack(side=tk.LEFT, padx=5)
        ttk.Button(utils_buttons_frame, text="Open Signatures Folder", 
                  command=self.open_signatures_folder).pack(side=tk.LEFT, padx=5)
        
        # Utils results
        self.tools_result_text = scrolledtext.ScrolledText(utils_group, height=8, state=tk.DISABLED)
        self.tools_result_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def create_status_bar(self):
        """Create the status bar."""
        self.status_bar = ttk.Frame(self.root)
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM)
        
        self.status_label = ttk.Label(self.status_bar, text="Ready")
        self.status_label.pack(side=tk.LEFT, padx=5, pady=2)
        
        # Version label
        version_label = ttk.Label(self.status_bar, text=f"CodeSign v{__version__}")
        version_label.pack(side=tk.RIGHT, padx=5, pady=2)
    
    def set_status(self, message: str):
        """Set the status bar message."""
        self.status_label.config(text=message)
        self.root.update_idletasks()
    
    def append_to_text_widget(self, widget: scrolledtext.ScrolledText, text: str):
        """Append text to a text widget."""
        widget.config(state=tk.NORMAL)
        widget.insert(tk.END, text + "\n")
        widget.see(tk.END)
        widget.config(state=tk.DISABLED)
        self.root.update_idletasks()
    
    def clear_text_widget(self, widget: scrolledtext.ScrolledText):
        """Clear a text widget."""
        widget.config(state=tk.NORMAL)
        widget.delete(1.0, tk.END)
        widget.config(state=tk.DISABLED)
    
    # Browser methods for file selection
    def browse_cert_output_dir(self):
        """Browse for certificate output directory."""
        directory = filedialog.askdirectory(title="Select Certificate Output Directory")
        if directory:
            self.cert_output_dir.delete(0, tk.END)
            self.cert_output_dir.insert(0, directory)
    
    def browse_cert_info_file(self):
        """Browse for certificate file to view info."""
        file_path = filedialog.askopenfilename(
            title="Select Certificate File",
            filetypes=[("Certificate files", "*.crt *.pem *.cer"), ("All files", "*.*")]
        )
        if file_path:
            self.cert_info_path.delete(0, tk.END)
            self.cert_info_path.insert(0, file_path)
    
    def browse_sign_file(self):
        """Browse for file to sign."""
        file_path = filedialog.askopenfilename(title="Select File to Sign")
        if file_path:
            self.sign_file_path.delete(0, tk.END)
            self.sign_file_path.insert(0, file_path)
    
    def browse_sign_key(self):
        """Browse for private key file."""
        file_path = filedialog.askopenfilename(
            title="Select Private Key File",
            filetypes=[("Key files", "*.key *.pem"), ("All files", "*.*")]
        )
        if file_path:
            self.sign_key_path.delete(0, tk.END)
            self.sign_key_path.insert(0, file_path)
    
    def browse_sign_cert(self):
        """Browse for certificate file."""
        file_path = filedialog.askopenfilename(
            title="Select Certificate File",
            filetypes=[("Certificate files", "*.crt *.pem *.cer"), ("All files", "*.*")]
        )
        if file_path:
            self.sign_cert_path.delete(0, tk.END)
            self.sign_cert_path.insert(0, file_path)
    
    def browse_verify_sig(self):
        """Browse for signature file to verify."""
        file_path = filedialog.askopenfilename(
            title="Select Signature File",
            filetypes=[("Signature files", "*.sig"), ("All files", "*.*")]
        )
        if file_path:
            self.verify_sig_path.delete(0, tk.END)
            self.verify_sig_path.insert(0, file_path)
    
    def browse_verify_file(self):
        """Browse for file to verify."""
        file_path = filedialog.askopenfilename(title="Select File to Verify")
        if file_path:
            self.verify_file_path.delete(0, tk.END)
            self.verify_file_path.insert(0, file_path)
    
    def browse_tools_sig(self):
        """Browse for signature file in tools tab."""
        file_path = filedialog.askopenfilename(
            title="Select Signature File",
            filetypes=[("Signature files", "*.sig"), ("All files", "*.*")]
        )
        if file_path:
            self.tools_sig_path.delete(0, tk.END)
            self.tools_sig_path.insert(0, file_path)
    
    # Action methods
    def generate_certificate(self):
        """Generate a new certificate."""
        # Validate inputs
        common_name = self.cert_common_name.get().strip()
        if not common_name:
            messagebox.showerror("Error", "Common Name is required")
            return
        
        try:
            organization = self.cert_organization.get().strip() or "CodeSign User"
            country = self.cert_country.get().strip() or "US"
            key_size = int(self.cert_key_size.get())
            validity_days = int(self.cert_validity.get())
            output_dir = Path(self.cert_output_dir.get().strip())
            password = self.cert_password.get().strip() or None
            
            # Create output directory if it doesn't exist
            output_dir.mkdir(parents=True, exist_ok=True)
            
            def generate_cert_thread():
                try:
                    self.set_status("Generating certificate...")
                    
                    cert_path, key_path = create_code_signing_certificate(
                        output_dir=output_dir,
                        common_name=common_name,
                        organization=organization,
                        country=country,
                        key_size=key_size,
                        validity_days=validity_days,
                        password=password
                    )
                    
                    # Update GUI in main thread
                    self.root.after(0, lambda: self.certificate_generated(cert_path, key_path, password))
                    
                except Exception as e:
                    self.root.after(0, lambda: self.certificate_generation_failed(str(e)))
            
            # Run in background thread
            threading.Thread(target=generate_cert_thread, daemon=True).start()
            
        except ValueError as e:
            messagebox.showerror("Error", f"Invalid input: {e}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate certificate: {e}")
    
    def certificate_generated(self, cert_path: Path, key_path: Path, password: Optional[str]):
        """Called when certificate generation is complete."""
        self.set_status("Certificate generated successfully")
        
        message = f"Certificate generated successfully!\n\n"
        message += f"Certificate: {cert_path}\n"
        message += f"Private Key: {key_path}\n\n"
        
        if password:
            message += "⚠️ Private key is encrypted. Keep the password safe!"
        else:
            message += "⚠️ Private key is not encrypted. Consider using a password for better security."
        
        messagebox.showinfo("Success", message)
        
        # Auto-populate the signing tab
        self.sign_cert_path.delete(0, tk.END)
        self.sign_cert_path.insert(0, str(cert_path))
        self.sign_key_path.delete(0, tk.END)
        self.sign_key_path.insert(0, str(key_path))
    
    def certificate_generation_failed(self, error: str):
        """Called when certificate generation fails."""
        self.set_status("Certificate generation failed")
        messagebox.showerror("Error", f"Failed to generate certificate:\n{error}")
    
    def load_cert_info(self):
        """Load and display certificate information."""
        cert_path = self.cert_info_path.get().strip()
        if not cert_path:
            messagebox.showerror("Error", "Please select a certificate file")
            return
        
        if not Path(cert_path).exists():
            messagebox.showerror("Error", "Certificate file not found")
            return
        
        try:
            self.clear_text_widget(self.cert_info_text)
            self.set_status("Loading certificate information...")
            
            cert_info = CertUtils.get_cert_info(Path(cert_path))
            
            self.append_to_text_widget(self.cert_info_text, "Certificate Information:")
            self.append_to_text_widget(self.cert_info_text, "=" * 50)
            self.append_to_text_widget(self.cert_info_text, f"Subject: {cert_info.get('subject', {})}")
            self.append_to_text_widget(self.cert_info_text, f"Issuer: {cert_info.get('issuer', {})}")
            self.append_to_text_widget(self.cert_info_text, f"Serial Number: {cert_info.get('serial_number')}")
            self.append_to_text_widget(self.cert_info_text, f"Version: {cert_info.get('version')}")
            self.append_to_text_widget(self.cert_info_text, f"Valid From: {cert_info.get('not_valid_before')}")
            self.append_to_text_widget(self.cert_info_text, f"Valid To: {cert_info.get('not_valid_after')}")
            self.append_to_text_widget(self.cert_info_text, f"Signature Algorithm: {cert_info.get('signature_algorithm')}")
            self.append_to_text_widget(self.cert_info_text, f"Public Key Size: {cert_info.get('public_key_size')} bits")
            self.append_to_text_widget(self.cert_info_text, f"Self-Signed: {cert_info.get('is_self_signed')}")
            self.append_to_text_widget(self.cert_info_text, f"Valid Now: {cert_info.get('is_valid_now')}")
            self.append_to_text_widget(self.cert_info_text, f"Days Until Expiry: {cert_info.get('days_until_expiry')}")
            
            # Extensions
            extensions = cert_info.get('extensions', {})
            if extensions:
                self.append_to_text_widget(self.cert_info_text, "\nExtensions:")
                for ext_name, ext_info in extensions.items():
                    self.append_to_text_widget(self.cert_info_text, f"  {ext_name}: {ext_info}")
            
            self.set_status("Certificate information loaded")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load certificate information:\n{e}")
            self.set_status("Failed to load certificate information")
    
    def sign_file_action(self):
        """Sign a file."""
        # Validate inputs
        file_path = self.sign_file_path.get().strip()
        key_path = self.sign_key_path.get().strip()
        cert_path = self.sign_cert_path.get().strip()
        
        if not file_path or not Path(file_path).exists():
            messagebox.showerror("Error", "Please select a valid file to sign")
            return
        
        if not key_path or not Path(key_path).exists():
            messagebox.showerror("Error", "Please select a valid private key file")
            return
        
        if not cert_path or not Path(cert_path).exists():
            messagebox.showerror("Error", "Please select a valid certificate file")
            return
        
        try:
            algorithm = self.sign_algorithm.get()
            padding = self.sign_padding.get()
            engine = self.sign_engine.get()
            output_dir = Path(self.sign_output_dir.get().strip())
            password = self.sign_key_password.get().strip() or None
            
            use_pss = padding == "PSS"
            use_pycryptodome = engine == "pycryptodome"
            
            # Create output directory
            output_dir.mkdir(parents=True, exist_ok=True)
            
            def sign_file_thread():
                try:
                    self.root.after(0, lambda: self.sign_progress.pack(fill=tk.X, padx=10, pady=5))
                    self.root.after(0, lambda: self.sign_progress.start())
                    
                    self.root.after(0, lambda: self.set_status("Signing file..."))
                    self.root.after(0, lambda: self.clear_text_widget(self.sign_result_text))
                    
                    signature_file = sign_file(
                        file_path=Path(file_path),
                        private_key_path=Path(key_path),
                        certificate_path=Path(cert_path),
                        output_dir=output_dir,
                        algorithm=algorithm,
                        use_pss=use_pss,
                        use_pycryptodome=use_pycryptodome,
                        private_key_password=password
                    )
                    
                    # Update GUI in main thread
                    self.root.after(0, lambda: self.file_signed_successfully(signature_file, file_path, algorithm))
                    
                except Exception as e:
                    self.root.after(0, lambda: self.file_signing_failed(str(e)))
            
            # Run in background thread
            threading.Thread(target=sign_file_thread, daemon=True).start()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to sign file: {e}")
    
    def file_signed_successfully(self, signature_file: Path, original_file: str, algorithm: str):
        """Called when file signing is successful."""
        self.sign_progress.stop()
        self.sign_progress.pack_forget()
        self.set_status("File signed successfully")
        
        self.append_to_text_widget(self.sign_result_text, "✅ File signed successfully!")
        self.append_to_text_widget(self.sign_result_text, f"Original File: {original_file}")
        self.append_to_text_widget(self.sign_result_text, f"Signature File: {signature_file}")
        self.append_to_text_widget(self.sign_result_text, f"Algorithm: {algorithm}")
        
        # Load signature details
        try:
            signer = DigitalSigner()
            sig_info = signer.load_signature(signature_file)
            
            self.append_to_text_widget(self.sign_result_text, "\nSignature Details:")
            self.append_to_text_widget(self.sign_result_text, f"File Hash: {sig_info['file_hash']}")
            self.append_to_text_widget(self.sign_result_text, f"Signer: {sig_info['signer_info']['common_name']}")
            self.append_to_text_widget(self.sign_result_text, f"Timestamp: {sig_info['timestamp']}")
            
        except Exception as e:
            self.append_to_text_widget(self.sign_result_text, f"Note: Could not load signature details: {e}")
        
        messagebox.showinfo("Success", f"File signed successfully!\nSignature saved to: {signature_file}")
    
    def file_signing_failed(self, error: str):
        """Called when file signing fails."""
        self.sign_progress.stop()
        self.sign_progress.pack_forget()
        self.set_status("File signing failed")
        
        self.append_to_text_widget(self.sign_result_text, "❌ File signing failed!")
        self.append_to_text_widget(self.sign_result_text, f"Error: {error}")
        
        messagebox.showerror("Error", f"Failed to sign file:\n{error}")
    
    def verify_signature_action(self):
        """Verify a signature."""
        sig_path = self.verify_sig_path.get().strip()
        if not sig_path or not Path(sig_path).exists():
            messagebox.showerror("Error", "Please select a valid signature file")
            return
        
        file_path = self.verify_file_path.get().strip()
        target_file = Path(file_path) if file_path else None
        engine = self.verify_engine.get()
        use_pycryptodome = engine == "pycryptodome"
        
        def verify_signature_thread():
            try:
                self.root.after(0, lambda: self.verify_progress.pack(fill=tk.X, padx=10, pady=5))
                self.root.after(0, lambda: self.verify_progress.start())
                self.root.after(0, lambda: self.set_status("Verifying signature..."))
                self.root.after(0, lambda: self.clear_text_widget(self.verify_result_text))
                
                is_valid = verify_file(
                    signature_path=Path(sig_path),
                    file_path=target_file,
                    use_pycryptodome=use_pycryptodome
                )
                
                # Update GUI in main thread
                self.root.after(0, lambda: self.signature_verified(is_valid, sig_path, target_file))
                
            except Exception as e:
                self.root.after(0, lambda: self.signature_verification_failed(str(e)))
        
        # Run in background thread
        threading.Thread(target=verify_signature_thread, daemon=True).start()
    
    def signature_verified(self, is_valid: bool, sig_path: str, target_file: Optional[Path]):
        """Called when signature verification is complete."""
        self.verify_progress.stop()
        self.verify_progress.pack_forget()
        
        if is_valid:
            self.set_status("Signature is valid")
            self.append_to_text_widget(self.verify_result_text, "✅ Signature is VALID")
            
            try:
                # Load signature details
                signer = DigitalSigner()
                sig_info = signer.load_signature(Path(sig_path))
                
                self.append_to_text_widget(self.verify_result_text, "\nSignature Details:")
                self.append_to_text_widget(self.verify_result_text, f"Original File: {sig_info['file_path']}")
                self.append_to_text_widget(self.verify_result_text, f"File Size: {FormatUtils.format_bytes(sig_info['file_size'])}")
                self.append_to_text_widget(self.verify_result_text, f"Hash Algorithm: {sig_info['hash_algorithm']}")
                self.append_to_text_widget(self.verify_result_text, f"Padding: {sig_info['padding_scheme']}")
                self.append_to_text_widget(self.verify_result_text, f"Timestamp: {sig_info['timestamp']}")
                
                self.append_to_text_widget(self.verify_result_text, "\nSigner Information:")
                self.append_to_text_widget(self.verify_result_text, f"Common Name: {sig_info['signer_info']['common_name']}")
                if sig_info['signer_info']['organization']:
                    self.append_to_text_widget(self.verify_result_text, f"Organization: {sig_info['signer_info']['organization']}")
                self.append_to_text_widget(self.verify_result_text, f"Certificate Valid: {sig_info['signer_info']['not_valid_before']} to {sig_info['signer_info']['not_valid_after']}")
                
                if target_file:
                    self.append_to_text_widget(self.verify_result_text, f"\nVerified against: {target_file}")
                
            except Exception as e:
                self.append_to_text_widget(self.verify_result_text, f"Note: Could not load signature details: {e}")
            
            messagebox.showinfo("Success", "Signature is VALID ✅")
        else:
            self.set_status("Signature is invalid")
            self.append_to_text_widget(self.verify_result_text, "❌ Signature is INVALID")
            messagebox.showerror("Verification Failed", "Signature is INVALID ❌")
    
    def signature_verification_failed(self, error: str):
        """Called when signature verification fails."""
        self.verify_progress.stop()
        self.verify_progress.pack_forget()
        self.set_status("Signature verification failed")
        
        self.append_to_text_widget(self.verify_result_text, "❌ Signature verification failed!")
        self.append_to_text_widget(self.verify_result_text, f"Error: {error}")
        
        messagebox.showerror("Error", f"Failed to verify signature:\n{error}")
    
    def load_signature_info(self):
        """Load and display signature information."""
        sig_path = self.tools_sig_path.get().strip()
        if not sig_path or not Path(sig_path).exists():
            messagebox.showerror("Error", "Please select a valid signature file")
            return
        
        try:
            self.clear_text_widget(self.tools_info_text)
            self.set_status("Loading signature information...")
            
            signer = DigitalSigner()
            sig_info = signer.load_signature(Path(sig_path))
            
            self.append_to_text_widget(self.tools_info_text, "Signature File Information:")
            self.append_to_text_widget(self.tools_info_text, "=" * 50)
            self.append_to_text_widget(self.tools_info_text, f"Original File: {sig_info['file_path']}")
            self.append_to_text_widget(self.tools_info_text, f"File Size: {FormatUtils.format_bytes(sig_info['file_size'])}")
            self.append_to_text_widget(self.tools_info_text, f"File Hash ({sig_info['hash_algorithm']}): {sig_info['file_hash']}")
            self.append_to_text_widget(self.tools_info_text, f"Padding Scheme: {sig_info['padding_scheme']}")
            self.append_to_text_widget(self.tools_info_text, f"Timestamp: {sig_info['timestamp']}")
            
            self.append_to_text_widget(self.tools_info_text, "\nSigner Information:")
            self.append_to_text_widget(self.tools_info_text, f"Common Name: {sig_info['signer_info']['common_name']}")
            if sig_info['signer_info']['organization']:
                self.append_to_text_widget(self.tools_info_text, f"Organization: {sig_info['signer_info']['organization']}")
            self.append_to_text_widget(self.tools_info_text, f"Certificate Serial: {sig_info['signer_info']['serial_number']}")
            self.append_to_text_widget(self.tools_info_text, f"Valid From: {sig_info['signer_info']['not_valid_before']}")
            self.append_to_text_widget(self.tools_info_text, f"Valid To: {sig_info['signer_info']['not_valid_after']}")
            
            self.set_status("Signature information loaded")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load signature information:\n{e}")
            self.set_status("Failed to load signature information")
    
    def calculate_file_hash(self):
        """Calculate and display file hash."""
        file_path = filedialog.askopenfilename(title="Select File to Hash")
        if not file_path:
            return
        
        try:
            self.clear_text_widget(self.tools_result_text)
            self.set_status("Calculating file hash...")
            
            file_info = FileUtils.get_file_info(Path(file_path))
            
            self.append_to_text_widget(self.tools_result_text, f"File: {file_info['name']}")
            self.append_to_text_widget(self.tools_result_text, f"Path: {file_info['path']}")
            self.append_to_text_widget(self.tools_result_text, f"Size: {FormatUtils.format_bytes(file_info['size'])}")
            self.append_to_text_widget(self.tools_result_text, f"SHA256: {file_info['hash_sha256']}")
            self.append_to_text_widget(self.tools_result_text, f"MD5: {file_info['hash_md5']}")
            
            self.set_status("File hash calculated")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to calculate file hash:\n{e}")
            self.set_status("Failed to calculate file hash")
    
    def view_file_info(self):
        """View detailed file information."""
        file_path = filedialog.askopenfilename(title="Select File to Analyze")
        if not file_path:
            return
        
        try:
            self.clear_text_widget(self.tools_result_text)
            self.set_status("Loading file information...")
            
            file_info = FileUtils.get_file_info(Path(file_path))
            
            self.append_to_text_widget(self.tools_result_text, "File Information:")
            self.append_to_text_widget(self.tools_result_text, "=" * 30)
            self.append_to_text_widget(self.tools_result_text, f"Name: {file_info['name']}")
            self.append_to_text_widget(self.tools_result_text, f"Path: {file_info['path']}")
            self.append_to_text_widget(self.tools_result_text, f"Size: {FormatUtils.format_bytes(file_info['size'])}")
            self.append_to_text_widget(self.tools_result_text, f"Created: {file_info['created']}")
            self.append_to_text_widget(self.tools_result_text, f"Modified: {file_info['modified']}")
            self.append_to_text_widget(self.tools_result_text, f"Executable: {file_info['is_executable']}")
            self.append_to_text_widget(self.tools_result_text, f"Permissions: {file_info['permissions']}")
            self.append_to_text_widget(self.tools_result_text, f"SHA256: {file_info['hash_sha256']}")
            self.append_to_text_widget(self.tools_result_text, f"MD5: {file_info['hash_md5']}")
            
            self.set_status("File information loaded")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load file information:\n{e}")
            self.set_status("Failed to load file information")
    
    def open_certificates_folder(self):
        """Open the certificates folder."""
        try:
            cert_dir = Path.cwd() / "certificates"
            cert_dir.mkdir(exist_ok=True)
            
            # Open folder in file manager
            if sys.platform == "win32":
                os.startfile(cert_dir)
            elif sys.platform == "darwin":
                os.system(f"open {cert_dir}")
            else:
                os.system(f"xdg-open {cert_dir}")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open certificates folder:\n{e}")
    
    def open_signatures_folder(self):
        """Open the signatures folder."""
        try:
            sig_dir = Path.cwd() / "signatures"
            sig_dir.mkdir(exist_ok=True)
            
            # Open folder in file manager
            if sys.platform == "win32":
                os.startfile(sig_dir)
            elif sys.platform == "darwin":
                os.system(f"open {sig_dir}")
            else:
                os.system(f"xdg-open {sig_dir}")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open signatures folder:\n{e}")
    
    def show_help(self):
        """Show help information."""
        help_text = f"""CodeSign GUI v{__version__} - Help

Certificate Management:
• Generate new self-signed certificates for code signing
• View detailed certificate information
• Support for RSA keys (2048-4096 bits)
• Optional password protection for private keys

File Signing:
• Sign any file with digital signatures
• Support for SHA256, SHA384, SHA512 algorithms
• Choose between PSS and PKCS#1 v1.5 padding
• Dual crypto engine support (cryptography/pycryptodome)

Signature Verification:
• Verify digital signatures and file integrity
• Display detailed signature and signer information
• Support for verifying files in different locations

Tools & Utilities:
• View signature file details
• Calculate file hashes (SHA256, MD5)
• View comprehensive file information
• Quick access to certificates and signatures folders

Tips:
• Always keep private keys secure
• Use strong passwords for key encryption
• Verify signatures before trusting files
• Check certificate validity periods

For more information, visit the CodeSign documentation.
"""
        
        help_window = tk.Toplevel(self.root)
        help_window.title("CodeSign Help")
        help_window.geometry("600x500")
        help_window.transient(self.root)
        help_window.grab_set()
        
        text_widget = scrolledtext.ScrolledText(help_window, wrap=tk.WORD)
        text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        text_widget.insert(tk.END, help_text)
        text_widget.config(state=tk.DISABLED)
        
        ttk.Button(help_window, text="Close", command=help_window.destroy).pack(pady=5)
    
    def show_about(self):
        """Show about information."""
        about_text = f"""CodeSign GUI v{__version__}
Digital Code Signing Utility

Copyright (c) 2025 Env Open
Copyright (c) 2025 Argo Nickerson

Licensed under the MIT License

A comprehensive code signing platform using:
• pycryptodomex - Cryptographic library
• pyOpenSSL - X.509 certificate handling
• cryptography - Alternative crypto backend
• tkinter - GUI framework

For support and documentation:
Visit the CodeSign repository
"""
        messagebox.showinfo("About CodeSign", about_text)
    
    def run(self):
        """Start the GUI application."""
        self.root.mainloop()


def main():
    """Main entry point for the GUI application."""
    try:
        app = CodeSignGUI()
        app.run()
    except Exception as e:
        print(f"Failed to start CodeSign GUI: {e}")
        messagebox.showerror("Startup Error", f"Failed to start CodeSign GUI:\n{e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
