#!/usr/bin/env python3
"""
Platform Runner Script
Alternatif untuk menjalankan aplikasi Platform
"""

import sys
import os

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from platform.main import Platform

if __name__ == "__main__":
    try:
        app = Platform()
        app.run()
    except KeyboardInterrupt:
        print(f"\n[+] Program dihentikan oleh user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Terjadi kesalahan: {e}")
        sys.exit(1) 