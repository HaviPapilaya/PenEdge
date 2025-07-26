"""
Modul helper dengan fungsi-fungsi utilitas
"""

# ====== IMPORTS ======
import os
import subprocess
import tempfile
import time
import shutil
from datetime import datetime
from platform.utils.colors import Colors

# ====== KELAS UTAMA ======
class Helpers:
    """Kelas helper dengan fungsi-fungsi utilitas"""
    
    def __init__(self):
        self.colors = Colors()
        self.output_dir = "/home/kali/penedge/output"
        self.tools_dir = os.path.expanduser("~/tools")

    # ====== FUNGSI UTILITAS/HELPER ======
    def ensure_output_dir(self):
        """Memastikan folder output ada"""
        os.makedirs(self.output_dir, exist_ok=True)
        
    def check_connection(self):
        """Mengecek koneksi internet"""
        try:
            subprocess.run(["ping", "-c", "1", "8.8.8.8"], 
                         capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            print(f"{self.colors.RED}[!] Tidak ada koneksi internet!{self.colors.NC}")
            return False
            
    def normalize_domain(self, domain):
        """Normalisasi domain (menghapus http/https)"""
        domain = domain.replace("http://", "").replace("https://", "")
        return domain.rstrip("/")
        
    def add_https_if_needed(self, domain):
        """Menambahkan https:// jika diperlukan"""
        if not domain.startswith(("http://", "https://")):
            return f"https://{domain}"
        return domain
        
    def get_domain_output_dir(self, domain):
        """Mendapatkan dan membuat direktori output untuk domain tertentu di bawah self.output_dir"""
        safe_domain = "".join(c for c in domain if c.isalnum() or c in "._-")
        dir_path = os.path.join(self.output_dir, safe_domain)
        os.makedirs(dir_path, exist_ok=True)
        return dir_path

    def get_gf_candidates_path(self, scan_type, domain):
        """Mendapatkan path file hasil filter GF (sql_candidates_gf.txt, xss_candidates_gf.txt, dst)"""
        domain_dir = self.get_domain_output_dir(domain)
        return os.path.join(domain_dir, f"{scan_type}_candidates_gf.txt")

    def get_scan_output_path(self, scan_type, domain):
        """Mendapatkan path file hasil scan utama (sqlmap_<timestamp>_output.txt, dalfox_<timestamp>_output.txt, dst)"""
        domain_dir = self.get_domain_output_dir(domain)
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        if scan_type == 'sqlmap':
            return os.path.join(domain_dir, f"sqlmap_{timestamp}_output.txt")
        if scan_type == 'dalfox':
            return os.path.join(domain_dir, f"dalfox_{timestamp}_output.txt")
        return os.path.join(domain_dir, f"{scan_type}_output.txt")

    def get_output_file_path(self, scan_type, domain):
        """(Legacy) Mendapatkan output file path lengkap dengan timestamp, untuk keperluan khusus/logging."""
        domain_dir = self.get_domain_output_dir(domain)
        filename = self.generate_output_filename(scan_type, domain)
        return os.path.join(domain_dir, filename)
        
    def generate_output_filename(self, scan_type, domain):
        """Membuat nama file otomatis berdasarkan jenis scan"""
        safe_domain = "".join(c for c in domain if c.isalnum() or c in "._-")
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        return f"{scan_type}_{safe_domain}_{timestamp}.txt"
        
    def check_command_exists(self, cmd):
        """Cek apakah sebuah command ada di PATH sistem."""
        return shutil.which(cmd) is not None

    def run_command(self, command):
        """Menjalankan perintah dan menampilkan output secara real-time."""
        try:
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            if process.stdout:
                for line in process.stdout:
                    print(line, end='')
            process.wait()
        except Exception as e:
            print(f"Error saat menjalankan perintah: {e}")

    def run_command_tee(self, command, output_file=None):
        """
        Menjalankan perintah, menampilkan output ke terminal (stdout),
        dan menyimpan output ke file jika output_file ditentukan.
        Mirip dengan perintah 'tee' di Linux.
        """
        f_out = None
        try:
            # Jika ada file output, buka untuk ditulis
            if output_file:
                f_out = open(output_file, 'w')
            
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            
            if process.stdout:
                for line in process.stdout:
                    # Tampilkan ke terminal
                    print(line, end='')
                    # Tulis ke file jika ada
                    if f_out:
                        f_out.write(line)
            
            process.wait()

        except Exception as e:
            print(f"Error saat menjalankan perintah: {e}")
        finally:
            # Pastikan file ditutup
            if f_out:
                f_out.close()

    def run_command_capture(self, command):
        """Menjalankan perintah dan menangkap outputnya untuk diproses lebih lanjut."""
        try:
            result = subprocess.run(
                command, 
                shell=True, 
                capture_output=True, 
                text=True, 
                timeout=None
            )
            return result.stdout
        except subprocess.TimeoutExpired:
            print(f"Perintah '{command}' memakan waktu terlalu lama dan dihentikan.")
            return ""
        except Exception as e:
            print(f"Error saat menjalankan perintah: {e}")
            return ""
            
    def run_command_realtime(self, command, timeout=None):
        """Menjalankan command dan menampilkan output real-time ke terminal"""
        try:
            result = subprocess.run(
                command, 
                shell=True, 
                timeout=timeout
            )
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            print(f"{self.colors.YELLOW}[!] Command timeout: {command}{self.colors.NC}")
            return False
        except Exception as e:
            print(f"{self.colors.RED}[!] Error menjalankan command: {e}{self.colors.NC}")
            return False
        
    def show_spinner(self, message):
        """Menampilkan spinner untuk proses yang sedang berjalan"""
        import threading
        import sys
        
        class Spinner:
            def __init__(self, message):
                self.message = message
                self.spin_chars = '|/-\\'
                self.i = 0
                self.running = True
                
            def spin(self):
                while self.running:
                    sys.stdout.write(f'\r{self.message} {self.spin_chars[self.i]}')
                    sys.stdout.flush()
                    self.i = (self.i + 1) % 4
                    time.sleep(0.1)
                    
            def stop(self):
                self.running = False
                sys.stdout.write(f'\r{self.message} Selesai.     \n')
                sys.stdout.flush()
                
        return Spinner(message)
        
    def prompt_output_filename(self, default_name):
        """Meminta nama file output dengan validasi"""
        while True:
            print(f"\n{self.colors.BLUE}[*] Hasil akan disimpan dalam file output.{self.colors.NC}")
            print(f"{self.colors.BLUE}[*] Silakan masukkan nama file untuk menyimpan hasil.{self.colors.NC}")
            print(f"Masukkan nama file output (default: {default_name}): ", end="")
            
            output_file = input().strip()
            if not output_file:
                output_file = default_name
                
            # Pastikan ekstensi .txt
            if not output_file.endswith('.txt'):
                output_file += '.txt'
                
            print(f"{self.colors.GREEN}[+] Nama file output yang akan dibuat: {output_file}{self.colors.NC}")
            
            full_path = os.path.join(self.output_dir, output_file)
            if os.path.exists(full_path):
                print(f"{self.colors.YELLOW}[!] File '{output_file}' sudah ada.{self.colors.NC}")
                print("Apakah Anda ingin menimpa file tersebut? (y/n): ", end="")
                overwrite_choice = input().strip().lower()
                
                if overwrite_choice in ['y', 'yes']:
                    print(f"{self.colors.GREEN}[+] File akan ditimpa.{self.colors.NC}")
                    break
                else:
                    print(f"{self.colors.BLUE}[+] File tidak akan ditimpa.{self.colors.NC}")
                    print(f"\n{self.colors.BLUE}=== Daftar File Output yang Sudah Ada ==={self.colors.NC}")
                    for file in os.listdir(self.output_dir):
                        if file.endswith('.txt'):
                            print(file)
                    print(f"{self.colors.BLUE}========================================={self.colors.NC}")
                    continue
            else:
                break
                
        return output_file
        
    def check_sudo_required(self):
        """Mengecek apakah sudo diperlukan"""
        return os.geteuid() != 0
        
    def get_sudo_cmd(self):
        """Mendapatkan command sudo jika diperlukan"""
        if self.check_sudo_required():
            print(f"{self.colors.YELLOW}[!] Script tidak dijalankan sebagai root. Beberapa tool mungkin memerlukan 'sudo'.{self.colors.NC}")
            return "sudo "
        return ""
        
    def create_temp_dir(self):
        """Membuat temporary directory"""
        return tempfile.mkdtemp(prefix="platform_")
        
    def cleanup_temp_files(self, temp_files, temp_dir=None):
        """Membersihkan temporary files"""
        for temp_file in temp_files:
            if os.path.exists(temp_file):
                os.remove(temp_file)
                
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)

    def run_command_realtime_and_capture(self, command):
        """Menjalankan perintah, menampilkan output secara real-time, dan menangkapnya."""
        output_lines = []
        try:
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding='utf-8',
                errors='replace'
            )
            if process.stdout:
                while True:
                    output = process.stdout.readline()
                    if output == '' and process.poll() is not None:
                        break
                    if output:
                        line = output.strip()
                        print(line)
                        output_lines.append(line)
            
            process.wait()
            return "\n".join(output_lines)
        except FileNotFoundError:
            error_msg = f"Perintah tidak ditemukan: {command.split()[0]}"
            print(f"{self.colors.RED}{error_msg}{self.colors.NC}")
            return error_msg
        except Exception as e:
            error_msg = f"Terjadi kesalahan saat menjalankan perintah: {e}"
            print(f"{self.colors.RED}{error_msg}{self.colors.NC}")
            return error_msg

    def filter_theharvester_output(self, raw_output: str) -> str:
        """Membersihkan banner, pesan error, log tidak penting, dan escape code warna dari output theHarvester."""
        clean_lines = []
        for line in raw_output.splitlines():
            if (
                "theHarvester" in line
                or "Edge-Security" in line
                or "Coded by" in line
                or "Christian Martorella" in line
                or "Read proxies.yaml" in line
                or "Read api-keys.yaml" in line
                or "An exception has occurred" in line
                or "Sitedossier module has triggered a captcha" in line
                or "Change IPs, manually solve the captcha" in line
                or line.strip().startswith("*")
                or line.strip().startswith("|")
                or line.strip().startswith("_")
                or line.strip() == ""
                or "\x1b" in line
                or "\033[" in line
            ):
                continue
            clean_lines.append(line)
        return "\n".join(clean_lines)

    def filter_gf_output(self, input_file, output_file, pattern):
        """Filter file dengan gf dan pattern tertentu, simpan ke output_file. Return True jika sukses, False jika gagal."""
        if not self.check_command_exists("gf"):
            print(f"{self.colors.YELLOW}[!] Tool gf tidak ditemukan di sistem.{self.colors.NC}")
            return False
        cmd = f"gf {pattern} {input_file} > {output_file}"
        result = os.system(cmd)
        return result == 0 and os.path.exists(output_file)

    def get_sast_output_path(self, filename):
        sast_dir = os.path.join(self.output_dir, "SAST")
        os.makedirs(sast_dir, exist_ok=True)
        return os.path.join(sast_dir, filename)

    def is_valid_domain(self, domain):
        """Validasi format domain (contoh: example.com)"""
        import re
        pattern = r"^(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$"
        return re.match(pattern, domain) is not None

    def is_valid_ip(self, ip):
        """Validasi format IP address (IPv4/IPv6)"""
        import ipaddress
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
