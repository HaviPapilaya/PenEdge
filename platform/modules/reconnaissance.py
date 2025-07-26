"""
Modul untuk  Reconnaissance
"""

# ====== IMPORTS ======
import os
import time
import re
import ipaddress
from platform.utils.colors import Colors
from platform.utils.helpers import Helpers

# ====== KELAS UTAMA ======
class Footprinting:
    def __init__(self):
        self.colors = Colors()
        self.helpers = Helpers()

    # ====== WORKFLOW UTAMA ======
    def run_footprinting_workflow(self, domain=None):
        start_time = time.time()
        if domain is None:
            while True:
                print(f"{self.colors.BLUE}[*] Masukkan domain atau IP target (contoh: example.com atau 1.2.3.4, ketik 'q' untuk keluar): {self.colors.NC}", end="")
                domain = input().strip()
                if domain.lower() == 'q':
                    print(f"{self.colors.YELLOW}[!] Proses dibatalkan oleh pengguna.{self.colors.NC}")
                    return
                if not domain:
                    print(f"{self.colors.RED}[!] Input tidak boleh kosong.{self.colors.NC}")
                    continue
                if not (self.helpers.is_valid_domain(domain) or self.helpers.is_valid_ip(domain)):
                    print(f"{self.colors.RED}[!] Domain atau IP tidak valid!{self.colors.NC}")
                    continue
                break
        output_file_path = self.helpers.get_output_file_path("footprinting", domain)
        domain_dir = self.helpers.get_domain_output_dir(domain)
        print(f"{self.colors.GREEN}[+] Mulai Footprinting & Reconnaissance untuk: {domain}{self.colors.NC}")
        print(f"{self.colors.GREEN}[+] Output akan disimpan di: {output_file_path}{self.colors.NC}")
        
        with open(output_file_path, 'w') as out:
            # DNS & WHOIS
            out.write("=== DNS & WHOIS ===\n")
            print(f"{self.colors.BLUE}[*] Menjalankan DNS lookup...{self.colors.NC}")
            tool_start = time.time()
            
            # Dig command
            dig_result = self.helpers.run_command_capture(f"dig {domain} ANY +noall +answer")
            if dig_result:
                print(f"{self.colors.GREEN}[+] DNS lookup selesai{self.colors.NC}")
                print(f"{self.colors.YELLOW}[*] Output dig:{self.colors.NC}")
                print(dig_result)
                out.write(dig_result + "\n")
            else:
                print(f"{self.colors.YELLOW}[!] DNS lookup tidak mengembalikan hasil{self.colors.NC}")
            
            # Host command
            print(f"{self.colors.BLUE}[*] Menjalankan host lookup...{self.colors.NC}")
            out.write("\n--- host ---\n")
            host_result = self.helpers.run_command_capture(f"host {domain}")
            if host_result:
                print(f"{self.colors.GREEN}[+] Host lookup selesai{self.colors.NC}")
                print(f"{self.colors.YELLOW}[*] Output host:{self.colors.NC}")
                print(host_result)
                out.write(host_result + "\n")
            else:
                print(f"{self.colors.YELLOW}[!] Host lookup tidak mengembalikan hasil{self.colors.NC}")
            
            # Nslookup command
            print(f"{self.colors.BLUE}[*] Menjalankan nslookup...{self.colors.NC}")
            out.write("\n--- nslookup ---\n")
            nslookup_result = self.helpers.run_command_capture(f"nslookup {domain}")
            if nslookup_result:
                print(f"{self.colors.GREEN}[+] Nslookup selesai{self.colors.NC}")
                print(f"{self.colors.YELLOW}[*] Output nslookup:{self.colors.NC}")
                print(nslookup_result)
                out.write(nslookup_result + "\n")
            else:
                print(f"{self.colors.YELLOW}[!] Nslookup tidak mengembalikan hasil{self.colors.NC}")
            
            # Whois command
            print(f"{self.colors.BLUE}[*] Menjalankan whois lookup...{self.colors.NC}")
            out.write("\n--- whois ---\n")
            whois_result = self.helpers.run_command_capture(f"whois {domain}")
            if whois_result:
                print(f"{self.colors.GREEN}[+] Whois lookup selesai{self.colors.NC}")
                print(f"{self.colors.YELLOW}[*] Output whois:{self.colors.NC}")
                print(whois_result)
                out.write(whois_result + "\n")
            else:
                print(f"{self.colors.YELLOW}[!] Whois lookup tidak mengembalikan hasil{self.colors.NC}")
            
            dns_time = time.time() - tool_start
            print(f"{self.colors.BLUE}[*] DNS & WHOIS selesai dalam {dns_time:.2f} detik{self.colors.NC}")
            
            # Subdomain Enumeration
            out.write("\n\n=== Subdomain Enumeration ===\n")
            subdomain_start = time.time()
            subdomain_tools = [
                ("subfinder", f"subfinder -d {domain} -silent"),
                ("assetfinder", f"assetfinder --subs-only {domain}"),
            ]
            
            for tool, cmd in subdomain_tools:
                if self.helpers.check_command_exists(tool):
                    print(f"{self.colors.BLUE}[*] Menjalankan {tool}...{self.colors.NC}")
                    tool_start = time.time()
                    result = self.helpers.run_command_capture(cmd)
                    tool_time = time.time() - tool_start
                    if result:
                        print(f"{self.colors.GREEN}[+] {tool} selesai dalam {tool_time:.2f} detik{self.colors.NC}")
                        print(f"{self.colors.YELLOW}[*] Output {tool}:{self.colors.NC}")
                        print(result)
                        out.write(f"\n--- {tool} output ---\n")
                        out.write(result + "\n")
                    else:
                        print(f"{self.colors.YELLOW}[!] {tool} tidak mengembalikan hasil ({tool_time:.2f} detik){self.colors.NC}")
                else:
                    print(f"{self.colors.YELLOW}[!] Tool {tool} tidak ditemukan{self.colors.NC}")
            
            subdomain_time = time.time() - subdomain_start
            print(f"{self.colors.BLUE}[*] Subdomain enumeration selesai dalam {subdomain_time:.2f} detik{self.colors.NC}")
            
            # TheHarvester
            if self.helpers.check_command_exists("theHarvester"):
                print(f"{self.colors.BLUE}[*] Menjalankan theHarvester...{self.colors.NC}")
                harvester_start = time.time()
                harvester_sources = "bing,baidu,certspotter,duckduckgo,crtsh,hackertarget,sitedossier,rapiddns,subdomaincenter,subdomainfinderc99,urlscan,yahoo"
                # Tangkap output ringkasan (stdout) theHarvester dan tulis ke file output
                result = self.helpers.run_command_capture(f"timeout 120 theHarvester -d {domain} -b {harvester_sources}")
                harvester_time = time.time() - harvester_start
                if result:
                    print(f"{self.colors.GREEN}[+] TheHarvester selesai dalam {harvester_time:.2f} detik{self.colors.NC}")
                    out.write(f"\n--- theHarvester summary output ---\n")
                    filtered = self.helpers.filter_theharvester_output(result)
                    out.write(filtered + "\n")
                    print(f"{self.colors.YELLOW}[*] Output theHarvester:{self.colors.NC}")
                    print(result)
                else:
                    print(f"{self.colors.YELLOW}[!] TheHarvester tidak menghasilkan output ({harvester_time:.2f} detik){self.colors.NC}")
            
        total_time = time.time() - start_time
        print(f"{self.colors.GREEN}[+] Footprinting & Reconnaissance selesai dalam {total_time:.2f} detik{self.colors.NC}")
        print(f"{self.colors.GREEN}[+] Output di: {output_file_path}{self.colors.NC}")
        
        # Summary timing
        print(f"\n{self.colors.BLUE}=== TIMING SUMMARY ==={self.colors.NC}")
        print(f"DNS & WHOIS: {dns_time:.2f} detik")
        print(f"Subdomain Enumeration: {subdomain_time:.2f} detik")
        if self.helpers.check_command_exists("theHarvester"):
            print(f"TheHarvester: {harvester_time:.2f} detik")
        print(f"Total Time: {total_time:.2f} detik")

    # ====== FUNGSI UTILITAS ======
    def get_summary(self, domain):
        import re
        output_file_path = self.helpers.get_output_file_path("footprinting", domain)
        dns = set()
        subdomains = set()
        emails = set()
        if not os.path.exists(output_file_path):
            return {'dns': [], 'subdomains': [], 'emails': []}
        with open(output_file_path, 'r') as f:
            content = f.read()
            # DNS parsing: hanya IP valid
            dns.update(re.findall(r"\b\d+\.\d+\.\d+\.\d+\b", content))
            # Email parsing
            emails.update(re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", content))
            # Subdomain parsing: regex semua kemungkinan subdomain valid
            # Contoh: apapun yang diakhiri .domain dan bukan persis domain
            subdomain_regex = re.compile(rf"\b((?:[a-zA-Z0-9_-]+\.)+{re.escape(domain)})\b")
            for match in subdomain_regex.findall(content):
                if match != domain:
                    subdomains.add(match)
        # DEBUG: print hasil parsing sebelum return
        print(f"[DEBUG] DNS: {dns}")
        print(f"[DEBUG] Subdomains: {subdomains}")
        print(f"[DEBUG] Emails: {emails}")
        return {
            'dns': list(dns),
            'subdomains': list(subdomains),
            'emails': list(emails)
        }