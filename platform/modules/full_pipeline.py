import re
import ipaddress
import os
from datetime import datetime
from platform.modules.reconnaissance import Footprinting
from platform.modules.scan_and_enum import ScanningEnumeration
from platform.modules.exploit_and_analysis import ExploitationAnalysis
from platform.modules.auto_exploit_pipeline import AutoExploitPipeline
from platform.modules.sast_analyzer import SASTAnalyzer
from platform.modules.vulnerability import VulnerabilityScanner
from platform.modules.reporting import Reporting
from platform.utils.helpers import Helpers

class FullPipeline:
    def __init__(self):
        self.footprinting = Footprinting()
        self.scanning = ScanningEnumeration()
        self.exploit = ExploitationAnalysis()
        self.auto_exploit = AutoExploitPipeline()
        self.sast = SASTAnalyzer()
        self.vuln = VulnerabilityScanner()
        self.reporting = Reporting()
        self.current_output_files = []  # Menyimpan file output yang relevan
        self.helpers = Helpers()

    def add_output_file(self, file_path):
        """Menambahkan file output yang relevan ke daftar"""
        if os.path.exists(file_path):
            self.current_output_files.append(file_path)
            print(f"[+] File output ditambahkan: {os.path.basename(file_path)}")

    def collect_relevant_output_files(self, domain):
        """Mengumpulkan file output yang relevan sesuai tahapan yang sudah dijalankan"""
        output_files = []
        domain_output_dir = self.footprinting.helpers.get_domain_output_dir(domain)
        
        if not os.path.exists(domain_output_dir):
            print(f"[!] Direktori output tidak ditemukan: {domain_output_dir}")
            return output_files
        
        # Ambil file output yang sudah ditambahkan selama pipeline berjalan
        for file_path in self.current_output_files:
            if os.path.exists(file_path):
                output_files.append(file_path)
        
        print(f"[+] Menggunakan {len(output_files)} file output yang relevan untuk reporting")
        for file_path in output_files:
            print(f"  - {os.path.basename(file_path)}")
        
        return output_files

    def run(self):
        while True:
            domain = input("Masukkan domain atau IP target (ketik 'q' untuk keluar): ").strip()
            if domain.lower() == 'q':
                print("[!] Proses dibatalkan oleh pengguna.")
                return
            if not domain:
                print("[!] Input tidak boleh kosong.")
                continue
            if not (self.helpers.is_valid_domain(domain) or self.helpers.is_valid_ip(domain)):
                print("[!] Domain atau IP tidak valid!")
                continue
            break

        # Reset daftar file output
        self.current_output_files = []

        # 1. Reconnaissance
        print("\n=== [1] Reconnaissance ===")
        self.footprinting.run_footprinting_workflow(domain)
        recon_summary = self.footprinting.get_summary(domain)
        
        # Tambahkan file output footprinting yang terbaru
        domain_output_dir = self.footprinting.helpers.get_domain_output_dir(domain)
        if os.path.exists(domain_output_dir):
            footprinting_files = []
            for filename in os.listdir(domain_output_dir):
                if filename.startswith('footprinting_') and filename.endswith('.txt'):
                    file_path = os.path.join(domain_output_dir, filename)
                    footprinting_files.append((file_path, os.path.getmtime(file_path)))
            
            if footprinting_files:
                # Ambil file footprinting yang paling baru
                latest_file = max(footprinting_files, key=lambda x: x[1])[0]
                self.add_output_file(latest_file)

        # 2. Scanning & Enumeration
        print("\n=== [2] Scanning & Enumeration ===")
        self.scanning.run_scanning_enumeration_workflow(domain)
        scan_summary = self.scanning.get_summary(domain)
        
        # Tambahkan file output scanning yang terbaru
        if os.path.exists(domain_output_dir):
            scanning_files = []
            for filename in os.listdir(domain_output_dir):
                if filename.startswith('scanning_enumeration_') and filename.endswith('.txt'):
                    file_path = os.path.join(domain_output_dir, filename)
                    scanning_files.append((file_path, os.path.getmtime(file_path)))
            
            if scanning_files:
                # Ambil file scanning yang paling baru
                latest_file = max(scanning_files, key=lambda x: x[1])[0]
                self.add_output_file(latest_file)

        # 3. Exploitation & Analysis (Auto Pipeline)
        print("\n=== [3] Exploitation & Analysis (Auto Pipeline) ===")
        exploit_results = self.auto_exploit.run_auto_exploit_pipeline(domain)
        exploit_summary = self.exploit.get_summary(domain)
        
        # Tambahkan file output LLM yang terbaru
        if os.path.exists(domain_output_dir):
            llm_files = []
            for filename in os.listdir(domain_output_dir):
                if filename.startswith('llm_') and filename.endswith('.txt'):
                    file_path = os.path.join(domain_output_dir, filename)
                    llm_files.append((file_path, os.path.getmtime(file_path)))
            
            if llm_files:
                # Ambil file LLM yang paling baru untuk setiap jenis (sqlmap, dalfox)
                llm_types = {}
                for file_path, mtime in llm_files:
                    filename = os.path.basename(file_path)
                    if 'sqlmap' in filename:
                        if 'sqlmap' not in llm_types or mtime > llm_types['sqlmap'][1]:
                            llm_types['sqlmap'] = (file_path, mtime)
                    elif 'dalfox' in filename:
                        if 'dalfox' not in llm_types or mtime > llm_types['dalfox'][1]:
                            llm_types['dalfox'] = (file_path, mtime)
                
                # Tambahkan file LLM yang terbaru
                for llm_type, (file_path, _) in llm_types.items():
                    self.add_output_file(file_path)

        # 4. Vulnerability Scanning
        print("\n=== [5] Vulnerability Scanning ===")
        self.vuln.run(domain)
        vuln_summary = self.vuln.get_summary(domain)

        # 6. Reporting dengan file output yang relevan
        print("\n=== [6] Reporting ===")
        
        # Kumpulkan file output yang relevan
        output_files = self.collect_relevant_output_files(domain)
        
        if output_files:
            # Parse file output untuk tool_outputs menggunakan method dari reporting
            tool_outputs = self.reporting._parse_output_files(output_files)
            
            if tool_outputs:
                # Gunakan method run dari reporting dengan file output yang sudah dikumpulkan
                self.reporting.run(
                    domain=domain,
                    recon_summary=recon_summary,
                    scan_summary=scan_summary,
                    exploit_summary=exploit_summary,
                    output_files=output_files
                )
            else:
                print(f"[!] Tidak ada data yang valid untuk reporting")
        else:
            print(f"[!] Tidak ada file output yang ditemukan untuk domain {domain}")
            print(f"[!] Pastikan semua tahapan telah selesai dan menghasilkan file output")
        
        print("\n=== Pipeline Selesai ===") 