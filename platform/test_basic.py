#!/usr/bin/env python3
"""
Basic test untuk memverifikasi struktur aplikasi Platform
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_imports():
    """Test import semua modul"""
    try:
        from platform.utils.colors import Colors
        from platform.utils.helpers import Helpers
        from platform.modules.sast_analyzer import SASTAnalyzer
        from platform.modules.reconnaissance import Footprinting
        from platform.modules.scan_and_enum import ScanningEnumeration
        from platform.modules.exploit_and_analysis import ExploitationAnalysis
        from platform.modules.vulnerability import VulnerabilityScanner
        from platform.modules.reporting import Reporting
        from platform.main import Platform
        print("✅ Semua modul berhasil diimport")
        return True
    except ImportError as e:
        print(f"❌ Error import: {e}")
        return False

def test_colors():
    """Test modul colors"""
    try:
        from platform.utils.colors import Colors
        colors = Colors()
        assert colors.RED == '\033[0;31m'
        assert colors.GREEN == '\033[0;32m'
        assert colors.BLUE == '\033[0;34m'
        assert colors.YELLOW == '\033[1;33m'
        assert colors.NC == '\033[0m'
        print("✅ Modul colors berfungsi")
        return True
    except Exception as e:
        print(f"❌ Error colors: {e}")
        return False

def test_helpers():
    """Test modul helpers"""
    try:
        from platform.utils.helpers import Helpers
        helpers = Helpers()
        
        # Test fungsi dasar
        assert helpers.output_dir == "/home/kali/penedge/output"
        assert helpers.tools_dir == os.path.expanduser("~/tools")
        
        # Test normalisasi domain
        assert helpers.normalize_domain("https://example.com/") == "example.com"
        assert helpers.normalize_domain("http://test.com") == "test.com"
        
        print("✅ Modul helpers berfungsi")
        return True
    except Exception as e:
        print(f"❌ Error helpers: {e}")
        return False

def test_modules():
    """Test inisialisasi modul-modul"""
    try:
        from platform.utils.colors import Colors
        from platform.modules.sast_analyzer import SASTAnalyzer
        from platform.modules.reconnaissance import Footprinting
        from platform.modules.scan_and_enum import ScanningEnumeration
        from platform.modules.exploit_and_analysis import ExploitationAnalysis
        from platform.modules.vulnerability import VulnerabilityScanner
        from platform.modules.reporting import Reporting
        
        colors = Colors()
        sast = SASTAnalyzer()
        footprint = Footprinting()
        network = ScanningEnumeration()
        enum = ExploitationAnalysis()
        vuln = VulnerabilityScanner()
        report = Reporting()
        
        print("✅ Semua modul berhasil diinisialisasi")
        return True
    except Exception as e:
        print(f"❌ Error modul: {e}")
        return False

def test_main():
    """Test aplikasi utama"""
    try:
        from platform.main import Platform
        app = Platform()
        assert app.output_dir == "/home/kali/penedge/output"
        print("✅ Aplikasi utama berhasil diinisialisasi")
        return True
    except Exception as e:
        print(f"❌ Error main: {e}")
        return False

def main():
    """Run semua test"""
    print("🧪 Menjalankan test dasar Platform...\n")
    
    tests = [
        test_imports,
        test_colors,
        test_helpers,
        test_modules,
        test_main
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
        print()
    
    print(f"📊 Hasil test: {passed}/{total} berhasil")
    
    if passed == total:
        print("🎉 Semua test berhasil! Aplikasi siap digunakan.")
        return True
    else:
        print("⚠️  Beberapa test gagal. Periksa error di atas.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 