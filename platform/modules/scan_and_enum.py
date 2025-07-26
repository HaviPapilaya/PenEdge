"""
Modul untuk Scanning & Enumeration
"""

# ====== IMPORTS ======
import os
import time
from platform.utils.colors import Colors
from platform.utils.helpers import Helpers

# ====== KELAS UTAMA ======
class ScanningEnumeration:
    """Kelas untuk network scanning dan enumeration"""
    
    def __init__(self):
        self.colors = Colors()
        self.helpers = Helpers()
        
    # ====== WORKFLOW UTAMA ======
    def run_nmap_command(self, command, description, output_file):
        """Menjalankan perintah nmap dan menyimpan hasilnya"""
        print(f"{self.colors.BLUE}[*] {description}...{self.colors.NC}")
        tool_start = time.time()
        
        # Jalankan command dan simpan output
        result = self.helpers.run_command_capture(command)
        tool_time = time.time() - tool_start
        
        if result:
            output_file.write(f"\n=== {description} ===\n")
            output_file.write(f"Command: {command}\n")
            output_file.write(f"Time: {tool_time:.2f} detik\n")
            output_file.write("=" * 50 + "\n")
            output_file.write(result)
            output_file.write("\n" + "=" * 50 + "\n")
            
            # Tampilkan output ke terminal
            print(f"{self.colors.YELLOW}[*] Output Nmap:{self.colors.NC}")
            print(result)
            
            print(f"{self.colors.GREEN}[+] {description} selesai ({tool_time:.2f} detik){self.colors.NC}")
            return True
        else:
            print(f"{self.colors.RED}[!] {description} gagal atau tidak ada port terbuka{self.colors.NC}")
            return False

    def run_scanning_enumeration_workflow(self, target=None):
        """Workflow scanning dan enumeration lengkap"""
        start_time = time.time()
        if target is None:
            while True:
                print(f"{self.colors.BLUE}[*] Masukkan target (domain atau IP, contoh: example.com, ketik 'q' untuk keluar): {self.colors.NC}", end="")
                target = input().strip()
                if target.lower() == 'q':
                    print(f"{self.colors.YELLOW}[!] Proses dibatalkan oleh pengguna.{self.colors.NC}")
                    return
                if not target:
                    print(f"{self.colors.RED}[!] Target tidak boleh kosong.{self.colors.NC}")
                    continue
                break
            
        output_file_path = self.helpers.get_output_file_path("scanning_enumeration", target)
        print(f"{self.colors.GREEN}[+] Mulai Scanning & Enumeration untuk: {target}{self.colors.NC}")
        print(f"{self.colors.GREEN}[+] Output akan disimpan di: {output_file_path}{self.colors.NC}")
        
        with open(output_file_path, 'w') as out:
            # Scan port dengan Nmap - lebih agresif untuk menghindari tcpwrapped
            command = f"nmap -Pn -sS --top-ports 1000 -sV --version-intensity 5 --open {target}"
            result = self.run_nmap_command(command, "NMAP Top 1000 Ports + Service Version (Aggressive)", out)
            
            # Jika scan pertama gagal atau mendapat tcpwrapped, coba scan alternatif
            if not result:
                print(f"{self.colors.YELLOW}[!] Scan agresif gagal, mencoba scan alternatif...{self.colors.NC}")
                alt_command = f"nmap -Pn -sT --top-ports 1000 -sV --version-intensity 3 --open {target}"
                self.run_nmap_command(alt_command, "NMAP Top 1000 Ports + Service Version (Connect Scan)", out)

            # === Tambahkan proses paramspider + GF filter di sini ===
            domain_dir = self.helpers.get_domain_output_dir(target)
            if self.helpers.check_command_exists("paramspider"):
                print(f"{self.colors.BLUE}[*] Menjalankan paramspider...{self.colors.NC}")
                paramspider_cmd = f"paramspider -d {target}"
                self.helpers.run_command_realtime(paramspider_cmd)
                paramspider_out = os.path.join("results", f"{target}.txt")
                if os.path.exists(paramspider_out):
                    print(f"{self.colors.GREEN}[+] Hasil paramspider disimpan di: {paramspider_out}{self.colors.NC}")
                    with open(paramspider_out) as f:
                        paramspider_result = f.read()
                    out.write("\n--- paramspider output ---\n")
                    out.write(paramspider_result + "\n")
                    print(f"{self.colors.YELLOW}[*] Output paramspider:{self.colors.NC}")
                    print(paramspider_result)
                    # Sorting dengan gf sqli dan xss (pakai helpers)
                    sql_gf_out = os.path.join(domain_dir, "sql_candidates_gf.txt")
                    xss_gf_out = os.path.join(domain_dir, "xss_candidates_gf.txt")
                    redirect_gf_out = os.path.join(domain_dir, "redirect_candidates_gf.txt")
                    lfi_gf_out = os.path.join(domain_dir, "lfi_candidates_gf.txt")
                    print(f"{self.colors.BLUE}[*] Menyaring hasil paramspider dengan gf sqli...{self.colors.NC}")
                    if self.helpers.filter_gf_output(paramspider_out, sql_gf_out, "sqli"):
                        print(f"{self.colors.GREEN}[+] Hasil filter gf sqli disimpan di: {sql_gf_out}{self.colors.NC}")
                    else:
                        print(f"{self.colors.YELLOW}[!] Tidak ada hasil filter gf sqli.{self.colors.NC}")
                    print(f"{self.colors.BLUE}[*] Menyaring hasil paramspider dengan gf xss...{self.colors.NC}")
                    if self.helpers.filter_gf_output(paramspider_out, xss_gf_out, "xss"):
                        print(f"{self.colors.GREEN}[+] Hasil filter gf xss disimpan di: {xss_gf_out}{self.colors.NC}")
                    else:
                        print(f"{self.colors.YELLOW}[!] Tidak ada hasil filter gf xss.{self.colors.NC}")
                    print(f"{self.colors.BLUE}[*] Menyaring hasil paramspider dengan gf redirect...{self.colors.NC}")
                    if self.helpers.filter_gf_output(paramspider_out, redirect_gf_out, "redirect"):
                        print(f"{self.colors.GREEN}[+] Hasil filter gf redirect disimpan di: {redirect_gf_out}{self.colors.NC}")
                    else:
                        print(f"{self.colors.YELLOW}[!] Tidak ada hasil filter gf redirect.{self.colors.NC}")
                    print(f"{self.colors.BLUE}[*] Menyaring hasil paramspider dengan gf lfi...{self.colors.NC}")
                    if self.helpers.filter_gf_output(paramspider_out, lfi_gf_out, "lfi"):
                        print(f"{self.colors.GREEN}[+] Hasil filter gf lfi disimpan di: {lfi_gf_out}{self.colors.NC}")
                    else:
                        print(f"{self.colors.YELLOW}[!] Tidak ada hasil filter gf lfi.{self.colors.NC}")
                else:
                    print(f"{self.colors.YELLOW}[!] Hasil paramspider tidak ditemukan!{self.colors.NC}")
            else:
                print(f"{self.colors.YELLOW}[!] Tool paramspider tidak ditemukan di sistem.{self.colors.NC}")

            # Nuclei Web Vulnerability Scan dengan httpx pre-filtering
            if self.helpers.check_command_exists("nuclei") and self.helpers.check_command_exists("httpx"):
                print(f"{self.colors.BLUE}[*] Menjalankan Nuclei Web Vulnerability Scan dengan httpx pre-filtering...{self.colors.NC}")
                out.write("\n=== Nuclei Web Vulnerability Scan (httpx pre-filtered) ===\n")
                tool_start = time.time()
                
                # Update nuclei templates terlebih dahulu
                print(f"{self.colors.BLUE}[*] Updating Nuclei templates...{self.colors.NC}")
                self.helpers.run_command_capture("nuclei -update-templates")
                
                # Buat file temporary untuk menyimpan URL yang akan di-test
                temp_urls_file = os.path.join(domain_dir, "temp_urls_for_nuclei.txt")
                
                # Tentukan input untuk httpx: hasil paramspider jika ada, jika tidak fallback ke domain utama
                paramspider_out = os.path.join("results", f"{target}.txt")
                use_paramspider = os.path.exists(paramspider_out) and os.path.getsize(paramspider_out) > 0
                if use_paramspider:
                    print(f"{self.colors.BLUE}[*] Menggunakan hasil paramspider sebagai input httpx: {paramspider_out}{self.colors.NC}")
                    httpx_cmd = f"httpx -l {paramspider_out} -status-code -mc 200 -silent"
                else:
                    print(f"{self.colors.YELLOW}[!] Hasil paramspider tidak ditemukan/masih kosong, menggunakan domain utama saja.{self.colors.NC}")
                    httpx_cmd = f"httpx -u http://{target} -status-code -mc 200 -silent"
                
                # Jalankan httpx dan capture hasil
                print(f"{self.colors.BLUE}[*] Mencari URL aktif dengan httpx...{self.colors.NC}")
                httpx_result = self.helpers.run_command_capture(httpx_cmd)
                active_urls = []
                if httpx_result:
                    for line in httpx_result.strip().split('\n'):
                        url = line.strip()
                        if url:
                            active_urls.append(url)
                            print(f"{self.colors.GREEN}[+] URL aktif ditemukan: {url}{self.colors.NC}")
                out.write(f"\n--- httpx scan ---\n")
                out.write(f"Command: {httpx_cmd}\n")
                out.write("=" * 50 + "\n")
                out.write(httpx_result if httpx_result else "Tidak ada URL aktif ditemukan")
                out.write("\n" + "=" * 50 + "\n")
                
                # Jika ada URL aktif, jalankan nuclei hanya pada URL tersebut
                if active_urls:
                    print(f"{self.colors.GREEN}[+] Ditemukan {len(active_urls)} URL aktif. Menjalankan Nuclei...{self.colors.NC}")
                    with open(temp_urls_file, 'w') as f:
                        for url in active_urls:
                            f.write(url + '\n')
                    nuclei_cmd = f"nuclei -l {temp_urls_file} -t vulnerabilities/xss/ -t vulnerabilities/sqli/"
                    print(f"{self.colors.BLUE}[*] Menjalankan Nuclei pada {len(active_urls)} URL aktif: {nuclei_cmd}{self.colors.NC}")
                    self.helpers.run_command_realtime(nuclei_cmd)
                    nuclei_result = self.helpers.run_command_capture(nuclei_cmd)
                    if nuclei_result:
                        out.write(f"\n--- Nuclei scan pada URL aktif ---\n")
                        out.write(f"Command: {nuclei_cmd}\n")
                        out.write(f"URL aktif yang di-scan: {len(active_urls)}\n")
                        out.write("=" * 50 + "\n")
                        out.write(nuclei_result)
                        out.write("\n" + "=" * 50 + "\n")
                        print(f"{self.colors.YELLOW}[*] Output Nuclei:{self.colors.NC}")
                        print(nuclei_result)
                    else:
                        print(f"{self.colors.YELLOW}[!] Nuclei tidak menemukan vulnerability pada URL aktif{self.colors.NC}")
                        out.write(f"\n--- Nuclei scan pada URL aktif ---\n")
                        out.write(f"Command: {nuclei_cmd}\n")
                        out.write("Tidak ada vulnerability ditemukan\n")
                    if os.path.exists(temp_urls_file):
                        os.remove(temp_urls_file)
                else:
                    print(f"{self.colors.YELLOW}[!] Tidak ada URL aktif ditemukan, melewati Nuclei scan{self.colors.NC}")
                    out.write("\n--- Nuclei scan ---\n")
                    out.write("Tidak ada URL aktif ditemukan, Nuclei scan dilewati\n")
                tool_time = time.time() - tool_start
                print(f"{self.colors.GREEN}[+] Nuclei Web Vulnerability Scan selesai ({tool_time:.2f} detik){self.colors.NC}")
            elif self.helpers.check_command_exists("nuclei"):
                print(f"{self.colors.YELLOW}[!] httpx tidak ditemukan, menjalankan Nuclei tanpa pre-filtering...{self.colors.NC}")
                out.write("\n=== Nuclei Web Vulnerability Scan (tanpa pre-filtering) ===\n")
                tool_start = time.time()
                
                # Update nuclei templates terlebih dahulu
                print(f"{self.colors.BLUE}[*] Updating Nuclei templates...{self.colors.NC}")
                self.helpers.run_command_capture("nuclei -update-templates")
                
                nuclei_commands = [
                    f"timeout 300 nuclei -u http://{target} -t vulnerabilities/xss/ -t vulnerabilities/sqli/",
                    f"timeout 300 nuclei -u https://{target} -t vulnerabilities/xss/ -t vulnerabilities/sqli/"
                ]
                
                for i, cmd in enumerate(nuclei_commands):
                    protocol = "HTTP" if i == 0 else "HTTPS"
                    print(f"{self.colors.BLUE}[*] Menjalankan Nuclei {protocol}: {cmd}{self.colors.NC}")
                    
                    # Jalankan Nuclei dengan output real-time
                    self.helpers.run_command_realtime(cmd)
                    
                    # Capture hasil untuk disimpan ke file
                    result = self.helpers.run_command_capture(cmd)
                    
                    if result:
                        out.write(f"Command: {cmd}\n")
                        out.write("=" * 50 + "\n")
                        out.write(result)
                        out.write("\n" + "=" * 50 + "\n")
                        
                        # Tampilkan output ke terminal
                        print(f"{self.colors.YELLOW}[*] Output Nuclei {protocol}:{self.colors.NC}")
                        print(result)
                    else:
                        print(f"{self.colors.YELLOW}[!] Nuclei {protocol} tidak menemukan vulnerability atau tidak ada response{self.colors.NC}")
                
                tool_time = time.time() - tool_start
                print(f"{self.colors.GREEN}[+] Nuclei Web Vulnerability Scan selesai ({tool_time:.2f} detik){self.colors.NC}")
            else:
                print(f"{self.colors.YELLOW}[!] Nuclei tidak ditemukan, melewati web vulnerability scan{self.colors.NC}")
        
        total_time = time.time() - start_time
        print(f"{self.colors.GREEN}[+] Scanning & Enumeration selesai dalam {total_time:.2f} detik{self.colors.NC}")
        print(f"{self.colors.GREEN}[+] Output di: {output_file_path}{self.colors.NC}")
        input(f"\n{self.colors.BLUE}Tekan Enter untuk lanjut ke tahap eksploitasi dan analisis...{self.colors.NC}")

    # ====== FUNGSI UTILITAS ======
    def get_summary(self, domain):
        """Parse hasil scanning dan enumeration untuk mendapatkan summary"""
        import re
        output_file_path = self.helpers.get_output_file_path("scanning_enumeration", domain)
        open_ports = []
        nuclei_findings = []
        
        if not os.path.exists(output_file_path):
            return {'open_ports': [], 'nuclei_findings': []}
        
        with open(output_file_path, 'r') as f:
            content = f.read()
            lines = content.split('\n')
            
            # Parse port terbuka dari output nmap
            for line in lines:
                # Contoh: 80/tcp open  http    nginx 1.19.0
                m = re.match(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)\s+(.+)$", line.strip())
                if m:
                    port = m.group(1) + '/' + m.group(2)
                    service = m.group(3)
                    version = m.group(4)
                    open_ports.append({
                        'port': port,
                        'service': service,
                        'version': version
                    })
            
            # Parse findings dari nuclei (jika ada)
            in_nuclei_section = False
            for line in lines:
                if 'nuclei' in line.lower() and 'vulnerability' in line.lower():
                    in_nuclei_section = True
                    continue
                elif in_nuclei_section:
                    if line.strip().startswith('===') or line.strip().startswith('---'):
                        in_nuclei_section = False
                    elif line.strip() and not line.strip().startswith('Command:'):
                        # Cari CVE atau vulnerability info
                        if any(keyword in line.lower() for keyword in ['cve-', 'vulnerability', 'critical', 'high', 'medium', 'low']):
                            nuclei_findings.append(line.strip())
        
        # DEBUG: print hasil parsing
        print(f"[DEBUG] Open ports: {len(open_ports)}")
        print(f"[DEBUG] Nuclei findings: {len(nuclei_findings)}")
        
        return {
            'open_ports': open_ports,
            'nuclei_findings': nuclei_findings
        }