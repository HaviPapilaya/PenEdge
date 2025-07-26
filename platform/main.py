#!/usr/bin/env python3
"""
Platform - Penetration Testing Platform
Main entry point untuk aplikasi
"""

# ====== IMPORTS ======
import os
import sys
import subprocess
from datetime import datetime
# Internal modules
from platform.modules.sast_analyzer import SASTAnalyzer
from platform.modules.reconnaissance import Footprinting
from platform.modules.scan_and_enum import ScanningEnumeration
from platform.modules.exploit_and_analysis import ExploitationAnalysis
from platform.modules.vulnerability import VulnerabilityScanner
from platform.modules.reporting import Reporting
from platform.modules.full_pipeline import FullPipeline
from platform.utils.colors import Colors
from platform.utils.helpers import Helpers

# Tambahkan parent directory ke sys.path agar bisa import modules/utils jika dijalankan dari dalam platform
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# ====== MAIN CLASS ======
class Platform:
    def __init__(self):
        self.colors = Colors()
        self.helpers = Helpers()
        self.sast_analyzer = SASTAnalyzer()
        self.footprinting = Footprinting()
        self.scanning_enumeration = ScanningEnumeration()
        self.exploitation_analysis = ExploitationAnalysis()
        self.vulnerability_scanner = VulnerabilityScanner()
        self.reporting = Reporting()
        self.output_dir = "/home/kali/penedge/output"
        os.makedirs(self.output_dir, exist_ok=True)

    # ====== BANNER & HELP ======
    def show_banner(self):
        print(self.colors.GREEN)
        print("██████╗ ███████╗███╗   ██╗███████╗██████╗  ██████╗ ███████╗")
        print("██╔══██╗██╔════╝████╗  ██║██╔════╝██╔══██╗██╔════╝ ██╔════╝")
        print("██████╔╝█████╗  ██╔██╗ ██║█████╗  ██║  ██║██║  ███╗█████╗  ")
        print("██╔═══╝ ██╔══╝  ██║╚██╗██║██╔══╝  ██║  ██║██║   ██║██╔══╝  ")
        print("██║     ███████╗██║ ╚████║███████╗██████╔╝╚██████╔╝███████╗")
        print("╚═╝     ╚══════╝╚═╝  ╚═══╝╚══════╝╚═════╝  ╚═════╝ ╚══════╝")
        print(self.colors.NC)
        print("               Penetration Testing Platform                  ")
        print("                                                   by @havi")
        print("")

    def show_help(self):
        """Menampilkan petunjuk dasar penggunaan tools"""
        print(f"\n{self.colors.BLUE}=== Help/Petunjuk Penggunaan ==={self.colors.NC}")
        print("\nPenedge adalah platform penetration testing otomatis yang menyediakan berbagai tools untuk analisis keamanan aplikasi dan jaringan.")
        
        print("\nStruktur Menu Utama:")
        print("  1. Help/Petunjuk Penggunaan: Menampilkan petunjuk ini.")
        print("  2. Analisis Source Code: Analisa keamanan kode sumber dengan Semgrep.")
        print("  3. Jalankan Tools Pentest: Menjalankan berbagai tools pentest (4 tahapan utama).")
        print("  4. Melihat Report: Menampilkan dan membuka file PDF report hasil pentest.")
        print("  5. Keluar: Menutup aplikasi.")
        print("\n4 Tahapan Pentest:")
        print("  1. Reconnaissance: Information gathering dan footprinting target.")
        print("  2. Scanning & Enumeration: Network scanning dan enumeration services.")
        print("  3. Exploitation & Analysis: Eksploitasi kerentanan dan analisis mendalam.")
        print("  4. Reporting: Pembuatan laporan hasil pentest.")
        print("\nAlur Kerja Umum:")
        print("  1. Lakukan reconnaissance untuk memahami target.")
        print("  2. Lanjutkan dengan scanning dan enumeration.")
        print("  3. Lakukan exploitation dan analysis kerentanan.")
        print("  4. Buat report PDF di tahapan Reporting.")
        print("  5. Lihat report PDF di menu 'Melihat Report'.")
        
        # Tabel Tools yang Digunakan
        print(f"\n{self.colors.GREEN}=== DAFTAR TOOLS OPEN SOURCE YANG DIGUNAKAN ==={self.colors.NC}")
        print("\n" + "="*120)
        print(f"{'TAHAP':<20} {'TOOL':<25} {'DESKRIPSI':<50} {'KATEGORI':<20}")
        print("="*120)
        # SAST Analysis
        print(f"{'SAST Analysis':<20} {'Semgrep':<25} {'Static Application Security Testing':<50} {'Code Analysis':<20}")
        # Reconnaissance
        print(f"{'Reconnaissance':<20} {'dig':<25} {'DNS lookup dan query':<50} {'DNS Analysis':<20}")
        print(f"{'':<20} {'host':<25} {'DNS hostname resolution':<50} {'DNS Analysis':<20}")
        print(f"{'':<20} {'nslookup':<25} {'DNS name server lookup':<50} {'DNS Analysis':<20}")
        print(f"{'':<20} {'whois':<25} {'Domain registration info':<50} {'Domain Info':<20}")
        print(f"{'':<20} {'subfinder':<25} {'Subdomain discovery':<50} {'Subdomain Enum':<20}")
        print(f"{'':<20} {'assetfinder':<25} {'Subdomain enumeration':<50} {'Subdomain Enum':<20}")
        print(f"{'':<20} {'theHarvester':<25} {'Email, subdomain, port discovery':<50} {'OSINT':<20}")
        # Scanning & Enumeration
        print(f"{'Scanning & Enum':<20} {'nmap':<25} {'Network discovery & security audit':<50} {'Network Scan':<20}")
        print(f"{'':<20} {'paramspider':<25} {'Parameter discovery':<50} {'Web Enum':<20}")
        print(f"{'':<20} {'gf':<25} {'Pattern matching & filtering':<50} {'Data Filtering':<20}")
        print(f"{'':<20} {'httpx':<25} {'HTTP probe & URL validation':<50} {'HTTP Tools':<20}")
        print(f"{'':<20} {'nuclei':<25} {'Vulnerability scanner':<50} {'Vuln Scanner':<20}")
        # Exploitation & Analysis
        print(f"{'Exploitation':<20} {'sqlmap':<25} {'SQL injection automation':<50} {'SQL Injection':<20}")
        print(f"{'':<20} {'dalfox':<25} {'XSS scanner & parameter finder':<50} {'XSS Scanner':<20}")
        print(f"{'':<20} {'ffuf':<25} {'Fuzzing untuk LFI/Redirect':<50} {'Fuzzer':<20}")
        # Reporting
        print(f"{'Reporting':<20} {'jinja2':<25} {'Template engine':<50} {'Report Gen':<20}")
        print(f"{'':<20} {'weasyprint':<25} {'HTML to PDF converter':<50} {'Report Gen':<20}")
        print(f"{'':<20} {'markdown':<25} {'Markdown processor':<50} {'Report Gen':<20}")
        print("="*120)
        
        print(f"\n{self.colors.YELLOW}Catatan Penting:{self.colors.NC}")
        print("  - Semua tools di atas adalah open source dan dapat diinstal secara otomatis")
        print("  - Jalankan 'install.sh' untuk menginstal semua tools yang diperlukan")
        print("  - Beberapa tools memerlukan hak akses root/sudo untuk berfungsi optimal")
        print("  - Pastikan koneksi internet stabil untuk update tools dan templates")
        print("  - Tools AI/LLM memerlukan Ollama server yang berjalan terpisah")
        print("  - Untuk analisis AI, pastikan model CodeLlama dan Llama3.2 sudah diunduh")
        
        print("\nPetunjuk Input:")
        print("  - Masukkan URL target dengan format lengkap, contoh: http://example.com")
        print("  - Pilih file output sesuai instruksi di layar.")
        print("  - Ikuti setiap instruksi input yang muncul pada tools.")
        print("\nLokasi Output:")
        print("  - Semua hasil pentest akan tersimpan di folder 'output/' pada direktori aplikasi.")
        print("  - File PDF report dapat dilihat melalui menu 'Melihat Report'.")
        print("\nTips Troubleshooting:")
        print("  - Jika terjadi error 'command not found', pastikan dependency sudah terinstall.")
        print("  - Jika error 'permission denied', coba jalankan dengan sudo/root.")
        print("  - Pastikan koneksi internet aktif untuk instalasi dan update tools.")
        print("\nDisclaimer:")
        print("  - Gunakan tools ini hanya untuk tujuan yang legal dan dengan izin yang sah.")
        print("  - Segala penyalahgunaan menjadi tanggung jawab pengguna.")
        print("")

    # ====== MENU ======
    def display_main_menu(self):
        """Menampilkan menu utama"""
        print(f"\n{self.colors.BLUE}=== Menu Utama ==={self.colors.NC}")
        print("1. Help/Petunjuk Penggunaan")
        print("2. Analisis Source Code")
        print("3. Jalankan Tools Pentest")
        print("4. Melihat Report")
        print("5. Keluar")
        print("Masukkan pilihan Anda (1-5): ", end="")

    def pentest_tools_menu(self):
        while True:
            print(f"\n{self.colors.BLUE}=== Menu Tools Pentest ==={self.colors.NC}")
            print("1. Jalankan SEMUA Tahapan Pentest (Full Pipeline)")
            print("2. Jalankan Per Tahap (Manual)")
            print("3. Kembali ke Menu Utama")
            print("Pilih mode (1-3): ", end="")
            mode_choice = input().strip().lower()
            if mode_choice == "1":
                print(f"{self.colors.GREEN}[+] Menjalankan Full Pipeline Pentest...{self.colors.NC}")
                pipeline = FullPipeline()
                pipeline.run()
                input(f"{self.colors.GREEN}Tekan enter untuk kembali ke menu...{self.colors.NC}")
            elif mode_choice == "2":
                while True:
                    print(f"\n{self.colors.BLUE}=== Pilih Tahapan Pentest ==={self.colors.NC}")
                    print("1. Reconnaissance")
                    print("2. Scanning & Enumeration")
                    print("3. Exploitation & Analysis")
                    print("4. Reporting")
                    print("5. Kembali ke Menu Tools Pentest")
                    print("Pilih tahapan (1-5): ", end="")
                    tahap_choice = input().strip().lower()
                    if tahap_choice == "1":
                        self.footprinting.run_footprinting_workflow()
                        input(f"{self.colors.GREEN}Tekan enter untuk melanjutkan...{self.colors.NC}")
                    elif tahap_choice == "2":
                        self.scanning_enumeration.run_scanning_enumeration_workflow()
                        input(f"{self.colors.GREEN}Tekan enter untuk melanjutkan...{self.colors.NC}")
                    elif tahap_choice == "3":
                        self.exploitation_analysis.run_exploitation_analysis_menu()
                    elif tahap_choice == "4":
                        self.reporting.show_output_menu()
                    elif tahap_choice == "5":
                        break
                    else:
                        print(f"{self.colors.RED}[!] Pilihan tidak valid{self.colors.NC}")
            elif mode_choice == "3":
                return
            else:
                print(f"{self.colors.RED}[!] Pilihan tidak valid{self.colors.NC}")

    def view_pdf_reports(self):
        """Menampilkan daftar dan membuka file PDF report"""
        print(f"\n{self.colors.BLUE}=== Melihat Report PDF ==={self.colors.NC}")
        
        # Cari file PDF di direktori output
        pdf_files = []
        for root, _, files in os.walk(self.output_dir):
            for file in files:
                if file.endswith('.pdf'):
                    pdf_files.append(os.path.join(root, file))
        
        if not pdf_files:
            print(f"{self.colors.YELLOW}[!] Tidak ada file PDF report di {self.output_dir}{self.colors.NC}")
            print(f"{self.colors.BLUE}[*] Untuk membuat report PDF:{self.colors.NC}")
            print(f"{self.colors.BLUE}[*] 1. Jalankan tahapan Reporting di menu Tools Pentest{self.colors.NC}")
            print(f"{self.colors.BLUE}[*] 2. Atau jalankan Full Pipeline untuk membuat report otomatis{self.colors.NC}")
            print(f"{self.colors.BLUE}[*] 3. Pastikan WeasyPrint terinstal: pip install weasyprint{self.colors.NC}")
            return
        
        # Tampilkan daftar file PDF
        print(f"\n{self.colors.GREEN}Daftar Report PDF yang tersedia:{self.colors.NC}")
        for idx, pdf_file in enumerate(pdf_files, 1):
            file_size = os.path.getsize(pdf_file) / (1024 * 1024)  # Convert to MB
            file_time = os.path.getmtime(pdf_file)
            file_date = datetime.fromtimestamp(file_time).strftime("%m/%d %H:%M")
            print(f"{idx}. {os.path.basename(pdf_file)} ({file_size:.2f} MB, {file_date})")
        
        while True:
            print(f"\n{self.colors.BLUE}Pilih nomor file PDF untuk dibuka (1-{len(pdf_files)}, ketik 'q' untuk keluar):{self.colors.NC}")
            choice = input().strip()
            
            if choice.lower() == 'q':
                print(f"{self.colors.YELLOW}[!] Proses dibatalkan oleh pengguna.{self.colors.NC}")
                return
            
            try:
                choice_num = int(choice)
                if 1 <= choice_num <= len(pdf_files):
                    selected_pdf = pdf_files[choice_num - 1]
                    print(f"{self.colors.GREEN}[+] Membuka file: {os.path.basename(selected_pdf)}{self.colors.NC}")
                    
                    # Cek apakah ada DISPLAY environment variable
                    display_available = 'DISPLAY' in os.environ and os.environ['DISPLAY']
                    
                    if not display_available:
                        print(f"{self.colors.YELLOW}[!] Tidak ada DISPLAY environment variable.{self.colors.NC}")
                        print(f"{self.colors.BLUE}[*] File PDF tersimpan di: {selected_pdf}{self.colors.NC}")
                        print(f"{self.colors.BLUE}[*] Untuk membuka PDF, Anda perlu:{self.colors.NC}")
                        print(f"{self.colors.BLUE}[*] 1. Menggunakan GUI environment, atau{self.colors.NC}")
                        print(f"{self.colors.BLUE}[*] 2. Menginstal PDF viewer command line seperti 'zathura' atau 'mupdf'{self.colors.NC}")
                        print(f"{self.colors.BLUE}[*] 3. Menggunakan browser dengan: firefox {selected_pdf}{self.colors.NC}")
                        return
                    
                    # Coba buka PDF dengan berbagai viewer
                    success = False
                    viewers_tried = []
                    
                    # Cek dan coba berbagai PDF viewer
                    pdf_viewers = [
                        ("xdg-open", ["xdg-open", selected_pdf]),
                        ("evince", ["evince", selected_pdf]),
                        ("okular", ["okular", selected_pdf]),
                        ("zathura", ["zathura", selected_pdf]),
                        ("mupdf", ["mupdf", selected_pdf]),
                        ("firefox", ["firefox", selected_pdf]),
                        ("google-chrome", ["google-chrome", selected_pdf]),
                        ("chromium", ["chromium", selected_pdf])
                    ]
                    
                    for viewer_name, cmd in pdf_viewers:
                        if success:
                            break
                            
                        # Cek apakah viewer tersedia
                        try:
                            subprocess.run(["which", cmd[0]], check=True, capture_output=True)
                        except subprocess.CalledProcessError:
                            continue
                        
                        viewers_tried.append(viewer_name)
                        try:
                            # Jalankan viewer dalam background
                            subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                            success = True
                            print(f"{self.colors.GREEN}[+] PDF berhasil dibuka dengan {viewer_name}!{self.colors.NC}")
                        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
                            continue
                    
                    if not success:
                        print(f"{self.colors.YELLOW}[!] Tidak dapat membuka PDF secara otomatis.{self.colors.NC}")
                        print(f"{self.colors.BLUE}[*] File PDF tersimpan di: {selected_pdf}{self.colors.NC}")
                        print(f"{self.colors.BLUE}[*] Viewers yang dicoba: {', '.join(viewers_tried) if viewers_tried else 'Tidak ada viewer yang tersedia'}{self.colors.NC}")
                        
                        # Tanya apakah ingin menampilkan info file atau mencoba extract teks
                        print(f"\n{self.colors.BLUE}Pilihan:{self.colors.NC}")
                        print("1. Tampilkan info file PDF")
                        print("2. Coba extract teks dari PDF (jika pdftotext tersedia)")
                        print("3. Kembali ke menu")
                        print("Pilih opsi (1-3): ", end="")
                        
                        choice = input().strip()
                        if choice == "1":
                            # Tampilkan info file
                            file_size = os.path.getsize(selected_pdf) / (1024 * 1024)
                            file_time = os.path.getmtime(selected_pdf)
                            file_date = datetime.fromtimestamp(file_time).strftime("%Y-%m-%d %H:%M:%S")
                            
                            print(f"\n{self.colors.GREEN}=== Info File PDF ==={self.colors.NC}")
                            print(f"Nama file: {os.path.basename(selected_pdf)}")
                            print(f"Ukuran: {file_size:.2f} MB")
                            print(f"Tanggal dibuat: {file_date}")
                            print(f"Path lengkap: {selected_pdf}")
                            
                        elif choice == "2":
                            # Coba extract teks dari PDF
                            try:
                                result = subprocess.run(["pdftotext", selected_pdf, "-"], 
                                                      capture_output=True, text=True, timeout=30)
                                if result.returncode == 0 and result.stdout.strip():
                                    print(f"\n{self.colors.GREEN}=== Konten PDF (Extract Teks) ==={self.colors.NC}")
                                    print(result.stdout[:2000] + "..." if len(result.stdout) > 2000 else result.stdout)
                                else:
                                    print(f"{self.colors.YELLOW}[!] Tidak dapat mengekstrak teks dari PDF.{self.colors.NC}")
                                    print(f"{self.colors.BLUE}[*] Install pdftotext: sudo apt install poppler-utils{self.colors.NC}")
                            except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
                                print(f"{self.colors.YELLOW}[!] pdftotext tidak tersedia.{self.colors.NC}")
                                print(f"{self.colors.BLUE}[*] Install pdftotext: sudo apt install poppler-utils{self.colors.NC}")
                        
                        print(f"\n{self.colors.BLUE}Solusi untuk membuka PDF:{self.colors.NC}")
                        print(f"{self.colors.BLUE}[*] 1. Install PDF viewer: sudo apt install evince okular zathura{self.colors.NC}")
                        print(f"{self.colors.BLUE}[*] 2. Buka manual: firefox {selected_pdf}{self.colors.NC}")
                        print(f"{self.colors.BLUE}[*] 3. Copy file ke sistem dengan GUI{self.colors.NC}")
                    
                    break
                else:
                    print(f"{self.colors.RED}[!] Nomor file tidak valid. Pilih 1-{len(pdf_files)}.{self.colors.NC}")
            except ValueError:
                print(f"{self.colors.RED}[!] Masukkan angka yang valid.{self.colors.NC}")

    # ====== WORKFLOW ======
    def run_full_pentest_workflow(self):
        """Menjalankan seluruh tahapan pentest secara otomatis"""
        while True:
            print(f"{self.colors.BLUE}[*] Masukkan domain target (contoh: example.com, ketik 'q' untuk keluar): {self.colors.NC}", end="")
            domain = input().strip()
            if domain.lower() == 'q':
                print(f"{self.colors.YELLOW}[!] Proses dibatalkan oleh pengguna.{self.colors.NC}")
                return
            if not domain:
                print(f"{self.colors.RED}[!] Domain tidak boleh kosong.{self.colors.NC}")
                continue
            break
        print(f"{self.colors.GREEN}[+] Memulai workflow pentest otomatis untuk: {domain}{self.colors.NC}")

        original_input = __builtins__.input

        def fake_input(prompt=""):
            if "domain" in prompt.lower() or "target" in prompt.lower():
                print(prompt, end="")
                print(domain)
                return domain
            return original_input(prompt)

        __builtins__.input = fake_input

        try:
            # 1. Reconnaissance
            print(f"\n{self.colors.BLUE}=== Tahap 1: Reconnaissance ==={self.colors.NC}")
            self.footprinting.run_footprinting_workflow()
            
            # 2. Scanning & Enumeration
            print(f"\n{self.colors.BLUE}=== Tahap 2: Scanning & Enumeration ==={self.colors.NC}")
            self.scanning_enumeration.run_scanning_enumeration_workflow()
            
            # 3. Exploitation & Analysis
            print(f"\n{self.colors.BLUE}=== Tahap 3: Exploitation & Analysis ==={self.colors.NC}")
            self.exploitation_analysis.run_exploitation_analysis_menu()
            
            # 4. Reporting
            print(f"\n{self.colors.BLUE}=== Tahap 4: Reporting ==={self.colors.NC}")
            self.reporting.show_output_menu()
        finally:
            __builtins__.input = original_input

        print(f"\n{self.colors.GREEN}[+] Workflow pentest selesai untuk: {domain}{self.colors.NC}")
        input(f"{self.colors.GREEN}Tekan enter untuk kembali ke menu...{self.colors.NC}")

    # ====== MAIN LOOP ======
    def run(self):
        """Menjalankan aplikasi utama"""
        self.show_banner()
        
        while True:
            self.display_main_menu()
            choice = input().strip()
            
            if choice == "1":
                self.show_help()
                input(f"{self.colors.GREEN}Tekan enter untuk kembali ke menu...{self.colors.NC}")
            elif choice == "2":
                print(f"{self.colors.GREEN}[+] Memulai analisis SAST dengan Semgrep...{self.colors.NC}")
                self.sast_analyzer.run_sast_analysis_manual()
                input(f"{self.colors.GREEN}Tekan enter untuk kembali ke menu...{self.colors.NC}")
            elif choice == "3":
                self.pentest_tools_menu()
            elif choice == "4":
                self.view_pdf_reports()
            elif choice == "5":
                print(f"{self.colors.GREEN}[+] Keluar dari program.{self.colors.NC}")
                sys.exit(0)
            else:
                print(f"{self.colors.RED}[!] Pilihan tidak valid. Silakan pilih 1-5.{self.colors.NC}")

# ====== MAIN GUARD ======
if __name__ == "__main__":
    try:
        app = Platform()
        app.run()
    except KeyboardInterrupt:
        print(f"\n{Colors().GREEN}[+] Program dihentikan oleh user.{Colors().NC}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors().RED}[!] Terjadi kesalahan: {e}{Colors().NC}")
        sys.exit(1) 