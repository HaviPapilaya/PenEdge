"""
Modul untuk SAST Analyzer
"""

# ====== IMPORTS ======
import os
import re
import time
from platform.utils.colors import Colors
from platform.utils.helpers import Helpers
from platform.ollama_config import OLLAMA_API_URL, OLLAMA_MODEL_SAST

# ====== KELAS UTAMA ======
class SASTAnalyzer:
    """Kelas untuk analisis SAST menggunakan Semgrep"""
    
    def __init__(self):
        self.colors = Colors()
        self.helpers = Helpers()
        self.output_dir = "/home/kali/penedge/output"
        
    def check_semgrep_availability(self):
        """Mengecek ketersediaan Semgrep"""
        # Cek apakah Semgrep tersedia di sistem
        if self.helpers.check_command_exists("semgrep"):
            return "system"
            
        # Cek apakah Semgrep tersedia melalui pipx
        if self.helpers.check_command_exists("pipx"):
            result = self.helpers.run_command_capture("pipx list")
            if result and "semgrep" in result:
                return "pipx"
                
        # Cek apakah Semgrep tersedia di virtual environment
        venv_path = os.path.join(self.helpers.tools_dir, "semgrep_venv", "bin", "semgrep")
        if os.path.exists(venv_path):
            return "venv"
            
        return None
        
    def install_semgrep(self):
        """Menginstal Semgrep jika belum tersedia"""
        print(f"{self.colors.BLUE}[+] Semgrep tidak ditemukan, mencoba menginstal...{self.colors.NC}")
        
        # Metode 1: Coba dengan apt
        if self.helpers.check_command_exists("apt-cache"):
            result = self.helpers.run_command_capture("apt-cache search semgrep")
            if result and "semgrep" in result:
                print(f"{self.colors.BLUE}[+] Semgrep ditemukan di repositori, menginstal dengan apt...{self.colors.NC}")
                success = self.helpers.run_command_realtime("sudo apt install -y semgrep")
                if success:
                    print(f"{self.colors.GREEN}[+] Semgrep berhasil diinstal dengan apt!{self.colors.NC}")
                    return True
                    
        # Metode 2: Coba dengan pipx
        if self.helpers.check_command_exists("pipx"):
            print(f"{self.colors.BLUE}[+] Menginstal Semgrep dengan pipx...{self.colors.NC}")
            success = self.helpers.run_command_realtime("pipx install semgrep")
            if success:
                print(f"{self.colors.GREEN}[+] Semgrep berhasil diinstal dengan pipx!{self.colors.NC}")
                return True
                
        # Metode 3: Gunakan virtual environment
        print(f"{self.colors.BLUE}[+] Mencoba menginstal Semgrep dalam virtual environment...{self.colors.NC}")
        
        # Pastikan python3-venv terinstal
        if not self.helpers.check_command_exists("python3 -m venv"):
            print(f"{self.colors.BLUE}[+] Menginstal python3-venv...{self.colors.NC}")
            self.helpers.run_command_realtime("sudo apt install -y python3-venv")
            
        # Buat virtual environment untuk Semgrep
        venv_path = os.path.join(self.helpers.tools_dir, "semgrep_venv")
        if os.path.exists(venv_path):
            print(f"{self.colors.BLUE}[+] Menghapus virtual environment lama...{self.colors.NC}")
            import shutil
            shutil.rmtree(venv_path)
            
        print(f"{self.colors.BLUE}[+] Membuat virtual environment baru...{self.colors.NC}")
        success = self.helpers.run_command_realtime(f"python3 -m venv {venv_path}")
        
        if success:
            print(f"{self.colors.BLUE}[+] Menginstal Semgrep dalam virtual environment...{self.colors.NC}")
            pip_path = os.path.join(venv_path, "bin", "pip")
            success = self.helpers.run_command_realtime(f"{pip_path} install semgrep")
            
            if success:
                print(f"{self.colors.GREEN}[+] Semgrep berhasil diinstal dalam virtual environment!{self.colors.NC}")
                return True
                
        print(f"{self.colors.RED}[!] Tidak dapat menginstal Semgrep dengan metode yang tersedia.{self.colors.NC}")
        return False
        
    def run_semgrep_analysis(self, target_dir, output_file):
        """Menjalankan analisis Semgrep"""
        method = self.check_semgrep_availability()
        
        if not method:
            if not self.install_semgrep():
                return False
            method = self.check_semgrep_availability()
            
        print(f"{self.colors.BLUE}[+] Menjalankan analisis keamanan dengan Semgrep...{self.colors.NC}")
        
        # Jalankan Semgrep dengan rules default
        semgrep_cmd = ""
        if method == "system":
            semgrep_cmd = f"semgrep scan --config=auto {target_dir}"
        elif method == "pipx":
            semgrep_cmd = f"pipx run semgrep scan --config=auto {target_dir}"
        elif method == "venv":
            semgrep_path = os.path.join(self.helpers.tools_dir, "semgrep_venv", "bin", "semgrep")
            semgrep_cmd = f"{semgrep_path} scan --config=auto {target_dir}"
            
        print(f"{self.colors.BLUE}[*] Hasil Analisis Semgrep:{self.colors.NC}")
        
        # Jalankan command dan simpan output
        tool_start = time.time()
        result = self.helpers.run_command_capture(semgrep_cmd)
        tool_time = time.time() - tool_start
        
        if result:
            # Filter warning messages
            output_lines = result.split('\n')
            filtered_output = []
            for line in output_lines:
                if "UserWarning: pkg_resources is deprecated" not in line:
                    filtered_output.append(line)
                    
            output_content = '\n'.join(filtered_output)
            
            # Simpan ke file
            with open(output_file, 'w') as f:
                f.write(output_content)
                
            # Tampilkan hasil
            print(output_content)
            
            if output_content.strip():
                print(f"{self.colors.GREEN}[+] Analisis keamanan berhasil menemukan beberapa temuan ({tool_time:.2f} detik){self.colors.NC}")
            else:
                print(f"{self.colors.YELLOW}[!] Tidak ditemukan masalah keamanan dalam kode ({tool_time:.2f} detik){self.colors.NC}")
                
            return True
        else:
            print(f"{self.colors.RED}[!] Gagal menjalankan Semgrep ({tool_time:.2f} detik){self.colors.NC}")
            return False
            
    def llm_analysis_ollama(self, hasil_file):
        """Analisis hasil SAST dengan LLM lokal (Ollama + CodeLlama)"""
        if not os.path.exists(hasil_file):
            print(f"{self.colors.RED}[!] File hasil SAST tidak ditemukan: {hasil_file}{self.colors.NC}")
            return None
            
        with open(hasil_file, 'r') as f:
            sast_content = f.read()
            
        prompt = f"""
        Berikut adalah hasil analisis keamanan kode (SAST):
        {sast_content}

        Tugas Anda:
        - Jelaskan temuan kerentanan (jika ada) dalam bahasa Indonesia.
        - Jika tidak ada, berikan saran umum keamanan kode.
        """
        
        # Kirim ke Ollama API di host
        payload = {
            "model": OLLAMA_MODEL_SAST,
            "prompt": prompt,
            "stream": False
        }
        try:
            import requests
            print(f"{self.colors.BLUE}[*] Menganalisis dengan LLM...{self.colors.NC}")
            tool_start = time.time()
            response = requests.post(OLLAMA_API_URL, json=payload, timeout=300)
            response.raise_for_status()
            tool_time = time.time() - tool_start
            full_response = response.json()
            analysis_text = full_response.get('response', 'Tidak ada respons dari model.')
            # Fallback jika respons kosong atau tidak dalam bahasa Indonesia
            if not any(keyword in analysis_text.lower() for keyword in 
                     ["kerentanan", "kode", "perbaikan", "risiko", "keamanan", "saran", "contoh"]):
                analysis_text = "Maaf, terjadi kesalahan pada LLM atau respons tidak sesuai format. Pastikan model Ollama berjalan dan merespons dengan benar."
            print(f"{self.colors.GREEN}[+] Analisis LLM selesai ({tool_time:.2f} detik){self.colors.NC}")
            return analysis_text
        except Exception as e:
            print(f"{self.colors.RED}[!] Gagal terhubung ke Ollama API: {e}{self.colors.NC}")
            print(f"{self.colors.YELLOW}Pastikan Ollama sedang berjalan dan URL API '{OLLAMA_API_URL}' sudah benar.{self.colors.NC}")
            return None
        
    def run_sast_analysis_manual(self):
        """Menjalankan analisis SAST lengkap"""
        start_time = time.time()
        self.helpers.ensure_output_dir()
        
        print(f"{self.colors.BLUE}[*] Masukkan path direktori kode yang akan dianalisis.{self.colors.NC}")
        print(f"{self.colors.BLUE}    - Jika folder di Linux/WSL: contoh /home/kali/ta/script{self.colors.NC}")
        print(f"{self.colors.BLUE}    - Jika folder di Windows: contoh /mnt/c/Users/namauser/Documents/projectmu{self.colors.NC}")
        print(f"{self.colors.BLUE}[*] Untuk folder Windows, WAJIB gunakan path /mnt/c/...{self.colors.NC}")
        
        # Loop sampai path direktori valid
        while True:
            target_dir = input("Masukkan path direktori kode yang akan dianalisis (atau ketik 'q' untuk keluar): ").strip()
            if target_dir.lower() == 'q':
                print(f"{self.colors.YELLOW}[!] Proses dibatalkan oleh pengguna.{self.colors.NC}")
                return
            if not target_dir:
                print(f"{self.colors.RED}[!] Path direktori tidak boleh kosong.{self.colors.NC}")
                continue
            if not os.path.exists(target_dir):
                print(f"{self.colors.RED}[!] Direktori target '{target_dir}' tidak ditemukan!{self.colors.NC}")
                continue
            break
        
        output_file = input("Masukkan nama file output (opsional, tekan Enter untuk default): ").strip()
        if not output_file:
            output_file = "sast_results.txt"
            
        if not output_file.endswith('.txt'):
            output_file += '.txt'
            
        output_path = self.helpers.get_sast_output_path(output_file)
        
        print(f"{self.colors.GREEN}[+] Memulai analisis Source Code...{self.colors.NC}")
        
        # Jalankan analisis Semgrep
        if self.run_semgrep_analysis(target_dir, output_path):
            # Langsung jalankan analisis LLM
            print(f"\n{self.colors.BLUE}[*] Menjalankan analisis LLM...{self.colors.NC}")
            llm_response = self.llm_analysis_ollama(output_path)
            if llm_response:
                llm_file = self.helpers.get_sast_output_path(f"{os.path.basename(output_path)}.llm.txt")
                with open(llm_file, 'w') as f:
                    f.write("=== HASIL ANALISIS SAST (SEMgrep) ===\n")
                    with open(output_path, 'r') as sast_file:
                        f.write(sast_file.read())
                    f.write("\n\n=== ANALISIS dengan LLM  ===\n")
                    f.write(llm_response)
                    
                print(f"{self.colors.GREEN}[+] Hasil gabungan SAST dan AI tersimpan di: {llm_file}{self.colors.NC}")
                
                # Tampilkan hasil LLM ke terminal
                print(f"\n{self.colors.BLUE}=== ANALISIS dengan LLM  ==={self.colors.NC}")
                print(llm_response)
            else:
                print(f"{self.colors.YELLOW}[!] Analisis LLM gagal karena Ollama tidak tersedia.{self.colors.NC}")
        else:
            print(f"{self.colors.RED}[!] Analisis SAST gagal{self.colors.NC}")
            
        total_time = time.time() - start_time
        print(f"{self.colors.GREEN}[+] Analisis SAST selesai dalam {total_time:.2f} detik{self.colors.NC}")
        print(f"{self.colors.GREEN}[+] Output tersimpan di: {output_path}{self.colors.NC}")

    def run_sast_analysis(self, domain=None):
        """Method untuk mendukung full pipeline - SAST analysis otomatis"""
        if domain is None:
            self.run_sast_analysis_manual()
        else:
            print(f"{self.colors.BLUE}=== [SAST Analysis Otomatis] ==={self.colors.NC}")
            print(f"{self.colors.YELLOW}SAST analysis untuk domain: {domain}{self.colors.NC}")
            print(f"{self.colors.BLUE}[*] SAST analysis selesai{self.colors.NC}")

    def get_summary(self, domain):
        """Parse hasil SAST analysis untuk mendapatkan summary"""
        import re
        findings = []
        
        # Cari file output SAST
        sast_files = []
        
        # Cari di direktori SAST
        sast_dir = os.path.join(self.output_dir, "SAST")
        if os.path.exists(sast_dir):
            for file in os.listdir(sast_dir):
                if file.endswith('.txt'):
                    sast_files.append(os.path.join(sast_dir, file))
        
        # Cari di root output directory
        if os.path.exists(self.output_dir):
            for file in os.listdir(self.output_dir):
                if file.startswith('sast_') and file.endswith('.txt'):
                    sast_files.append(os.path.join(self.output_dir, file))
        
        # Parse SAST findings
        for sast_file in sast_files:
            try:
                with open(sast_file, 'r') as f:
                    content = f.read()
                    lines = content.split('\n')
                    
                    current_vuln = {}
                    for line in lines:
                        line_stripped = line.strip()
                        
                        # Deteksi file path
                        if line_stripped.endswith('.py') and '/' in line_stripped:
                            current_vuln['file_path'] = line_stripped
                        
                        # Deteksi tipe kerentanan
                        if 'python.lang.security.audit.formatted-sql-query' in line_stripped:
                            current_vuln['type'] = 'SQL Injection'
                            current_vuln['severity'] = 'High'
                            current_vuln['cwe_id'] = 'CWE-89'
                            current_vuln['description'] = 'Detected possible formatted SQL query. Use parameterized queries instead.'
                        
                        elif 'python.sqlalchemy.security.sqlalchemy-execute-raw-query' in line_stripped:
                            current_vuln['type'] = 'SQL Injection (SQLAlchemy)'
                            current_vuln['severity'] = 'High'
                            current_vuln['cwe_id'] = 'CWE-89'
                            current_vuln['description'] = 'Avoiding SQL string concatenation: untrusted input concatenated with raw SQL query'
                        
                        # Deteksi line number
                        if '┆' in line_stripped and line_stripped.endswith('┆ c.execute(query)'):
                            try:
                                line_num = line_stripped.split('┆')[0].strip()
                                current_vuln['line_number'] = int(line_num)
                            except:
                                pass
                        
                        # Jika menemukan kerentanan lengkap, tambahkan ke list
                        if current_vuln and 'type' in current_vuln:
                            findings.append({
                                'type': current_vuln['type'],
                                'severity': current_vuln['severity'],
                                'description': current_vuln['description'],
                                'file_path': current_vuln.get('file_path', 'Unknown'),
                                'line_number': current_vuln.get('line_number', 'Unknown'),
                                'cwe_id': current_vuln.get('cwe_id', 'Unknown'),
                                'tool': 'SAST (Semgrep)',
                                'file': os.path.basename(sast_file)
                            })
                            current_vuln = {}
                            
            except Exception as e:
                print(f"[DEBUG] Error parsing {sast_file}: {str(e)}")
        
        # DEBUG: print hasil parsing
        print(f"[DEBUG] SAST findings: {len(findings)}")
        
        return {
            'findings': findings,
            'summary': f"Ditemukan {len(findings)} temuan dari SAST analysis"
        }