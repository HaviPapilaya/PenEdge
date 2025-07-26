"""
Modul untuk Reporting & Output
"""

# ====== IMPORTS ======
import os
import re
import json
import sqlite3
import hashlib
import shutil
import requests
from datetime import datetime
from pathlib import Path
# Third-party
from jinja2 import Template
try:
    from weasyprint import HTML
    WEASYPRINT_AVAILABLE = True
except ImportError:
    WEASYPRINT_AVAILABLE = False
try:
    import markdown
    MARKDOWN_AVAILABLE = True
except ImportError:
    MARKDOWN_AVAILABLE = False
# Internal
from platform.utils.colors import Colors
from platform.utils.helpers import Helpers

# ====== KELAS UTAMA ======
class Reporting:
    def __init__(self):
        self.colors = Colors()
        self.helpers = Helpers()
        self.output_dir = self.helpers.output_dir
        
        # Konfigurasi database analysis storage
        self.base_dir = Path(self.output_dir)
        self.analysis_dir = self.base_dir / "analysis_storage"
        self.db_path = self.analysis_dir / "analysis_database.db"
        
        # Inisialisasi storage
        self.init_analysis_storage()

    def init_analysis_storage(self):
        """Inisialisasi struktur penyimpanan analysis storage"""
        try:
            # Buat direktori utama jika belum ada
            self.base_dir.mkdir(exist_ok=True)
            self.analysis_dir.mkdir(exist_ok=True)
            
            # Buat subdirektori
            (self.analysis_dir / "sast_results").mkdir(exist_ok=True)
            (self.analysis_dir / "sql_injection").mkdir(exist_ok=True)
            (self.analysis_dir / "xss_results").mkdir(exist_ok=True)

            (self.analysis_dir / "reports").mkdir(exist_ok=True)
            (self.analysis_dir / "metadata").mkdir(exist_ok=True)
            
            # Inisialisasi database
            self.init_database()
            
            print(f"{self.colors.GREEN}[+] Analysis storage berhasil diinisialisasi: {self.analysis_dir}{self.colors.NC}")
            
        except Exception as e:
            print(f"{self.colors.RED}[!] Gagal inisialisasi analysis storage: {str(e)}{self.colors.NC}")

    def init_database(self):
        """Inisialisasi database SQLite untuk metadata"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Tabel untuk menyimpan metadata analisis
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS analysis_metadata (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    analysis_type TEXT NOT NULL,
                    target_name TEXT,
                    scan_date TEXT,
                    file_path TEXT,
                    file_hash TEXT,
                    severity_level TEXT,
                    vulnerability_count INTEGER,
                    description TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Tabel untuk menyimpan detail kerentanan
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    analysis_id INTEGER,
                    vulnerability_type TEXT,
                    severity TEXT,
                    file_path TEXT,
                    line_number INTEGER,
                    description TEXT,
                    recommendation TEXT,
                    cwe_id TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (analysis_id) REFERENCES analysis_metadata (id)
                )
            ''')
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            print(f"{self.colors.RED}[!] Gagal membuat database: {str(e)}{self.colors.NC}")

    def store_analysis_result(self, source_file, analysis_type, target_name="unknown"):
        """Menyimpan hasil analisis ke database dan file storage"""
        source_path = Path(source_file)
        if not source_path.exists():
            print(f"{self.colors.RED}[!] File tidak ditemukan: {source_file}{self.colors.NC}")
            return False
        
        try:
            # Baca konten file
            with open(source_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Generate hash untuk file
            file_hash = hashlib.md5(content.encode()).hexdigest()
            
            # Buat nama file baru dengan timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            new_filename = f"{analysis_type.lower()}_{target_name}_{timestamp}.txt"
            
            # Tentukan direktori berdasarkan jenis analisis
            if analysis_type.lower() == 'sast':
                new_path = self.analysis_dir / "sast_results" / new_filename
            elif analysis_type.lower() in ['sqlmap', 'sql_injection']:
                new_path = self.analysis_dir / "sql_injection" / new_filename
            elif analysis_type.lower() in ['dalfox', 'xss']:
                new_path = self.analysis_dir / "xss_results" / new_filename

            else:
                new_path = self.analysis_dir / "reports" / new_filename
            
            # Salin file
            shutil.copy2(source_path, new_path)
            
            # Parse hasil untuk metadata
            vulnerabilities = self.parse_analysis_results(content, analysis_type)
            
            # Simpan ke database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO analysis_metadata 
                (analysis_type, target_name, scan_date, file_path, file_hash, 
                 severity_level, vulnerability_count, description)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                analysis_type.upper(),
                target_name,
                timestamp,
                str(new_path),
                file_hash,
                self.get_highest_severity(vulnerabilities),
                len(vulnerabilities),
                f"{analysis_type.upper()} Analysis for {target_name}"
            ))
            
            analysis_id = cursor.lastrowid
            
            # Simpan detail kerentanan
            for vuln in vulnerabilities:
                cursor.execute('''
                    INSERT INTO vulnerabilities 
                    (analysis_id, vulnerability_type, severity, file_path, 
                     line_number, description, recommendation, cwe_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    analysis_id,
                    vuln.get('type', 'Unknown'),
                    vuln.get('severity', 'Unknown'),
                    vuln.get('file_path', ''),
                    vuln.get('line_number', 0),
                    vuln.get('description', ''),
                    vuln.get('recommendation', ''),
                    vuln.get('cwe_id', '')
                ))
            
            conn.commit()
            conn.close()
            
            print(f"{self.colors.GREEN}[+] Hasil {analysis_type} berhasil disimpan: {new_path}{self.colors.NC}")
            return True
            
        except Exception as e:
            print(f"{self.colors.RED}[!] Gagal menyimpan hasil {analysis_type}: {str(e)}{self.colors.NC}")
            return False

    def parse_analysis_results(self, content, analysis_type):
        """Parse hasil analisis untuk ekstraksi metadata"""
        vulnerabilities = []
        
        if analysis_type.lower() == 'sast':
            vulnerabilities = self.parse_sast_results(content)
        elif analysis_type.lower() in ['sqlmap', 'sql_injection']:
            vulnerabilities = self.parse_sqlmap_results(content)
        elif analysis_type.lower() in ['dalfox', 'xss']:
            vulnerabilities = self.parse_xss_results(content)

        
        return vulnerabilities

    def parse_sast_results(self, content):
        """Parse hasil SAST untuk ekstraksi metadata"""
        vulnerabilities = []
        lines = content.split('\n')
        
        current_vuln = {}
        for line in lines:
            line = line.strip()
            
            # Deteksi file path
            if line.endswith('.py') and '/' in line:
                current_vuln['file_path'] = line
            
            # Deteksi tipe kerentanan
            if 'python.lang.security.audit.formatted-sql-query' in line:
                current_vuln['type'] = 'SQL Injection'
                current_vuln['severity'] = 'High'
                current_vuln['cwe_id'] = 'CWE-89'
                current_vuln['description'] = 'Detected possible formatted SQL query. Use parameterized queries instead.'
                current_vuln['recommendation'] = 'Use parameterized queries or ORM to prevent SQL injection'
            
            elif 'python.sqlalchemy.security.sqlalchemy-execute-raw-query' in line:
                current_vuln['type'] = 'SQL Injection (SQLAlchemy)'
                current_vuln['severity'] = 'High'
                current_vuln['cwe_id'] = 'CWE-89'
                current_vuln['description'] = 'Avoiding SQL string concatenation: untrusted input concatenated with raw SQL query'
                current_vuln['recommendation'] = 'Use SQLAlchemy TextualSQL with prepared statements or ORM'
            
            # Deteksi line number
            if '┆' in line and line.strip().endswith('┆ c.execute(query)'):
                try:
                    line_num = line.split('┆')[0].strip()
                    current_vuln['line_number'] = int(line_num)
                except:
                    pass
            
            # Jika menemukan kerentanan lengkap, tambahkan ke list
            if current_vuln and 'type' in current_vuln:
                vulnerabilities.append(current_vuln.copy())
                current_vuln = {}
        
        return vulnerabilities

    def parse_sqlmap_results(self, content):
        """Parse hasil SQLMap untuk ekstraksi metadata"""
        vulnerabilities = []
        lines = content.split('\n')
        
        for line in lines:
            line_lower = line.lower()
            
            # Cari parameter yang vulnerable
            if "parameter:" in line_lower and "vulnerable" in line_lower:
                param_name = line.split(":")[-1].strip()
                
                vulnerabilities.append({
                    'type': 'SQL Injection',
                    'severity': 'High',
                    'cwe_id': 'CWE-89',
                    'description': f"Parameter '{param_name}' rentan terhadap SQL injection attack",
                    'recommendation': "Implementasikan prepared statements dan parameterized queries",
                    'file_path': 'Web Application',
                    'line_number': 0
                })
        
        return vulnerabilities

    def parse_xss_results(self, content):
        """Parse hasil XSS untuk ekstraksi metadata"""
        vulnerabilities = []
        lines = content.split('\n')
        
        for line in lines:
            line_lower = line.lower()
            
            # Cari XSS vulnerability
            if "xss" in line_lower and ("found" in line_lower or "vulnerable" in line_lower):
                vulnerabilities.append({
                    'type': 'Cross-Site Scripting (XSS)',
                    'severity': 'High',
                    'cwe_id': 'CWE-79',
                    'description': "Website rentan terhadap XSS attack",
                    'recommendation': "Implementasikan input validation dan output encoding",
                    'file_path': 'Web Application',
                    'line_number': 0
                })
        
        return vulnerabilities



    def get_highest_severity(self, vulnerabilities):
        """Mendapatkan severity tertinggi dari list vulnerabilities"""
        if not vulnerabilities:
            return 'Unknown'
        
        severity_order = ['Critical', 'High', 'Medium', 'Low', 'Info']
        highest = 'Info'
        
        for vuln in vulnerabilities:
            vuln_severity = vuln.get('severity', 'Info')
            if severity_order.index(vuln_severity) < severity_order.index(highest):
                highest = vuln_severity
        
        return highest

    def search_analysis(self, target_name=None, analysis_type=None, severity=None):
        """Mencari hasil analisis berdasarkan kriteria"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            query = "SELECT * FROM analysis_metadata WHERE 1=1"
            params = []
            
            if target_name:
                query += " AND target_name LIKE ?"
                params.append(f"%{target_name}%")
            
            if analysis_type:
                query += " AND analysis_type = ?"
                params.append(analysis_type.upper())
            
            if severity:
                query += " AND severity_level = ?"
                params.append(severity)
            
            query += " ORDER BY created_at DESC"
            
            cursor.execute(query, params)
            results = cursor.fetchall()
            conn.close()
            
            return results
            
        except Exception as e:
            print(f"{self.colors.RED}[!] Gagal mencari analisis: {str(e)}{self.colors.NC}")
            return []

    def get_analysis_summary(self):
        """Mendapatkan ringkasan analisis dari database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Total analisis
            cursor.execute("SELECT COUNT(*) FROM analysis_metadata")
            total_analyses = cursor.fetchone()[0]
            
            # Analisis per jenis
            cursor.execute("SELECT analysis_type, COUNT(*) FROM analysis_metadata GROUP BY analysis_type")
            analysis_by_type = cursor.fetchall()
            
            # Severity distribution
            cursor.execute("SELECT severity_level, COUNT(*) FROM analysis_metadata GROUP BY severity_level")
            severity_distribution = cursor.fetchall()
            
            # Total vulnerabilities
            cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
            total_vulnerabilities = cursor.fetchone()[0]
            
            conn.close()
            
            return {
                'total_analyses': total_analyses,
                'analysis_by_type': analysis_by_type,
                'severity_distribution': severity_distribution,
                'total_vulnerabilities': total_vulnerabilities
            }
            
        except Exception as e:
            print(f"{self.colors.RED}[!] Gagal mendapatkan ringkasan: {str(e)}{self.colors.NC}")
            return {}

    def export_metadata_to_json(self, output_file="analysis_metadata.json"):
        """Export metadata ke file JSON"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Ambil semua metadata
            cursor.execute("""
                SELECT am.*, GROUP_CONCAT(v.vulnerability_type) as vuln_types
                FROM analysis_metadata am
                LEFT JOIN vulnerabilities v ON am.id = v.analysis_id
                GROUP BY am.id
                ORDER BY am.created_at DESC
            """)
            
            results = cursor.fetchall()
            conn.close()
            
            # Convert ke format JSON
            metadata = []
            for row in results:
                metadata.append({
                    'id': row[0],
                    'analysis_type': row[1],
                    'target_name': row[2],
                    'scan_date': row[3],
                    'file_path': row[4],
                    'file_hash': row[5],
                    'severity_level': row[6],
                    'vulnerability_count': row[7],
                    'description': row[8],
                    'created_at': row[9],
                    'vulnerability_types': row[10] if row[10] else []
                })
            
            # Simpan ke file JSON
            output_path = self.analysis_dir / "metadata" / output_file
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(metadata, f, indent=2, ensure_ascii=False)
            
            print(f"{self.colors.GREEN}[+] Metadata berhasil diexport ke: {output_path}{self.colors.NC}")
            return str(output_path)
            
        except Exception as e:
            print(f"{self.colors.RED}[!] Gagal export metadata: {str(e)}{self.colors.NC}")
            return None

    def show_output_menu(self):
        print(f"\n{self.colors.BLUE}=== Menu Output Pentest ==={self.colors.NC}")
        if not os.path.isdir(self.output_dir):
            print(f"{self.colors.RED}[!] Folder output tidak ditemukan: {self.output_dir}{self.colors.NC}")
            os.makedirs(self.output_dir, exist_ok=True)
            print(f"{self.colors.GREEN}[+] Folder output berhasil dibuat: {self.output_dir}{self.colors.NC}")
            print(f"{self.colors.YELLOW}[!] Tidak ada file output saat ini{self.colors.NC}")
            return
        
        files = []
        for root, _, filenames in os.walk(self.output_dir):
            for filename in filenames:
                if filename.endswith('.txt'):
                    files.append(os.path.join(root, filename))
        # Urutkan berdasarkan waktu modifikasi (timestamp), paling baru di paling bawah
        files.sort(key=lambda x: os.path.getmtime(x))
        
        if not files:
            print(f"{self.colors.YELLOW}[!] Tidak ada file output di {self.output_dir}{self.colors.NC}")
            return
        
        while True:
            print(f"\n{self.colors.GREEN}Pilihan:{self.colors.NC}")
            print("1. Lihat file spesifik")
            print("2. Generate Report PDF")
            print("3. Kembali ke menu utama")
            print("Pilih opsi (1-3): ", end="")
            choice = input().strip()
            if choice == "1":
                self._view_specific_file(files)
            elif choice == "2":
                self._generate_pdf_report(files)
            elif choice == "3":
                return
            else:
                print(f"{self.colors.RED}[!] Pilihan tidak valid{self.colors.NC}")

    def _view_specific_file(self, files):
        """Menampilkan file output spesifik"""
        print(f"\n{self.colors.BLUE}=== Daftar File Output ==={self.colors.NC}")
        for idx, file in enumerate(files):
            print(f"{idx+1}. {os.path.relpath(file, self.output_dir)}")
        print(f"\n{self.colors.GREEN}Masukkan nomor file (1-{len(files)}) atau nama file lengkap (domain/namafile.txt):{self.colors.NC}")
        print("Input: ", end="")
        file_input = input().strip()
        selected_file = None
        if file_input.isdigit() and 1 <= int(file_input) <= len(files):
            selected_file = files[int(file_input)-1]
        else:
            for file in files:
                if os.path.relpath(file, self.output_dir) == file_input:
                    selected_file = file
                    break
        if selected_file and os.path.isfile(selected_file):
            print(f"\n{self.colors.GREEN}=== {os.path.relpath(selected_file, self.output_dir)} ==={self.colors.NC}")
            with open(selected_file) as f:
                print(f.read())
            print(f"\n{self.colors.BLUE}Apakah Anda ingin menyimpan konten ini ke file lain? (y/n):{self.colors.NC}", end=" ")
            save_choice = input().strip().lower()
            if save_choice == 'y':
                print("Masukkan nama file untuk menyimpan output: ", end="")
                save_filename = input().strip()
                if not save_filename.endswith('.txt'):
                    save_filename += '.txt'
                save_path = os.path.join(self.output_dir, save_filename)
                with open(selected_file) as src, open(save_path, 'w') as dst:
                    dst.write(src.read())
                print(f"{self.colors.GREEN}[+] Output tersimpan di: {save_path}{self.colors.NC}")
        else:
            print(f"{self.colors.RED}[!] File tidak ditemukan. Pastikan Anda memasukkan nomor file yang valid atau nama file yang benar (domain/namafile.txt).{self.colors.NC}")

    def _generate_pdf_report(self, files):
        """Generate report PDF dari file output yang dipilih"""
        if not WEASYPRINT_AVAILABLE:
            print(f"{self.colors.RED}[!] WeasyPrint tidak tersedia. Install dengan: pip install weasyprint{self.colors.NC}")
            return
        
        print(f"\n{self.colors.BLUE}=== Generate Report PDF ==={self.colors.NC}")
        
        # Pilih file output
        selected_files = self._select_files_for_report(files)
        if not selected_files:
            return
        
        # Input informasi report
        report_info = self._get_report_info()
        if report_info is None:
            return
        
        # Parse output files
        tool_outputs = self._parse_output_files(selected_files)
        
        # Generate HTML
        html_content = self._generate_html_content(report_info, tool_outputs)
        
        # Convert to PDF
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        pdf_filename = f"pentest_report_{timestamp}.pdf"
        pdf_path = os.path.join(self.output_dir, pdf_filename)
        
        try:
            HTML(string=html_content).write_pdf(pdf_path)
            print(f"{self.colors.GREEN}[+] Report PDF berhasil dibuat: {pdf_path}{self.colors.NC}")
        except Exception as e:
            print(f"{self.colors.RED}[!] Gagal membuat PDF: {str(e)}{self.colors.NC}")

    def _select_files_for_report(self, files):
        """Memilih file output untuk report"""
        print(f"\n{self.colors.GREEN}Daftar file output yang tersedia:{self.colors.NC}")
        for idx, file in enumerate(files):
            print(f"{idx+1}. {os.path.relpath(file, self.output_dir)}")
        
        print(f"\n{self.colors.BLUE}Pilih file untuk report (pisahkan dengan koma, contoh: 1,3,5 atau 'all' untuk semua):{self.colors.NC}")
        choice = input().strip()
        
        selected_files = []
        if choice.lower() == 'all':
            selected_files = files
        else:
            try:
                indices = [int(x.strip()) - 1 for x in choice.split(',')]
                for idx in indices:
                    if 0 <= idx < len(files):
                        selected_files.append(files[idx])
            except ValueError:
                print(f"{self.colors.RED}[!] Format input tidak valid{self.colors.NC}")
                return []
        
        if not selected_files:
            print(f"{self.colors.RED}[!] Tidak ada file yang dipilih{self.colors.NC}")
            return []
        
        print(f"{self.colors.GREEN}[+] {len(selected_files)} file dipilih untuk report{self.colors.NC}")
        return selected_files

    def _get_report_info(self):
        """Mendapatkan informasi report dari user"""
        print(f"\n{self.colors.BLUE}=== Informasi Report ==={self.colors.NC}")
        
        report_title = input("Judul report (default: Laporan Pentest): ").strip()
        if not report_title:
            report_title = "Laporan Pentest"
        target_domain = input("Target domain: ").strip()
        if not target_domain:
            target_domain = "N/A"
        researcher_name = input("Nama peneliti (default: Penedge Team): ").strip()
        if not researcher_name:
            researcher_name = "Penedge Team"
        
        return {
            'report_title': report_title,
            'target_domain': target_domain,
            'researcher_name': researcher_name,
            'report_date': datetime.now().strftime("%d %B %Y"),
            'report_version': "1.0",
            'current_year': datetime.now().year
        }

    def _parse_output_files(self, files):
        """Parse file output untuk ekstrak informasi"""
        tool_outputs = []
        ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')  # regex untuk kode warna ANSI

        for file_path in files:
            filename = os.path.basename(file_path)
            tool_name = os.path.splitext(filename)[0]
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Hilangkan kode warna ANSI
                content = ansi_escape.sub('', content)
                
                # Filter content berdasarkan tool
                filtered_content = self._filter_tool_output(tool_name, content)
                
                # Masukkan semua file output, tidak hanya yang ada hasil
                tool_outputs.append({
                    'tool_name': tool_name,
                    'content': filtered_content if filtered_content and filtered_content.strip() else content,
                    'file_path': file_path,
                    'original_content': content  # Simpan original untuk ekstraksi findings
                })
                    
            except Exception as e:
                print(f"{self.colors.YELLOW}[!] Gagal membaca file {filename}: {str(e)}{self.colors.NC}")
        
        print(f"{self.colors.GREEN}[+] Berhasil memparse {len(tool_outputs)} file output{self.colors.NC}")
        for output in tool_outputs:
            print(f"  - {output['tool_name']}: {os.path.basename(output['file_path'])}")
        
        return tool_outputs

    def _filter_tool_output(self, tool_name, content):
        """Filter output berdasarkan tool untuk hanya menampilkan hasil yang relevan"""
        tool_name_lower = tool_name.lower()
        
        # Untuk file LLM, tampilkan semua konten karena sudah terstruktur
        if 'llm_' in tool_name_lower:
            return self._filter_llm_output(content)
        
        # Untuk file footprinting, filter untuk menampilkan hasil reconnaissance
        elif 'footprinting' in tool_name_lower:
            return self._filter_footprinting_output(content)
        
        # Untuk file scanning_enumeration, filter untuk menampilkan port dan vulnerability
        elif 'scanning_enumeration' in tool_name_lower:
            return self._filter_scanning_output(content)
        
        # Untuk file SAST, filter untuk menampilkan hasil analisis keamanan
        elif 'sast' in tool_name_lower:
            return self._filter_sast_output(content)
        
        # Untuk tool lain yang tidak dikenali, tampilkan semua konten asli
        else:
            return self._clean_content(content)

    def _clean_content(self, content):
        """Membersihkan konten dari template Lorem ipsum dan karakter yang tidak diinginkan"""
        # Hapus template Lorem ipsum
        lorem_pattern = r'\nLorem ipsum dolor sit amet, consectetuer adipiscing elit\.\s*Donec molestie\.\s*Sed aliquam sem ut arcu\.\s*Phasellus sollicitudin\.\s*Vestibulum condimentum facilisis\s*nulla\.\s*In hac habitasse platea dictumst\.\s*Nulla nonummy\.\s*Cras quis libero\.\s*Cras venenatis\.\s*Aliquam posuere lobortis pede\.\s*Nullam fringilla urna id leo\.\s*Praesent aliquet pretium erat\.\s*Praesent non odio\.\s*Pellentesque a magna a\s*mauris vulputate lacinia\.\s*Aenean viverra\.\s*Class aptent taciti sociosqu ad\s*litora torquent per conubia nostra, per inceptos hymenaeos\.\s*Aliquam lacus\.\s*Mauris magna eros, semper a, tempor et, rutrum et, tortor\.\s*\n'
        content = re.sub(lorem_pattern, '', content, flags=re.IGNORECASE | re.MULTILINE | re.DOTALL)
        
        # Hapus baris kosong berlebihan
        content = re.sub(r'\n\s*\n\s*\n', '\n\n', content)
        
        # Hapus karakter escape yang tidak perlu
        content = content.replace('\\n', '\n')
        
        return content.strip()

    def _filter_sqlmap_output(self, content):
        """Filter output SQLMap untuk hanya menampilkan hasil vulnerability dan database info"""
        lines = content.split('\n')
        filtered_lines = []
        in_vulnerability_section = False
        in_database_section = False
        in_table_section = False
        in_dump_section = False
        
        for line in lines:
            line_stripped = line.strip()
            line_lower = line.lower()
            
            # Mulai capture jika menemukan section vulnerability
            if any(keyword in line_lower for keyword in [
                "parameter:", "type:", "title:", "payload:", "injection point",
                "sql injection", "vulnerable", "database:", "web server:"
            ]):
                in_vulnerability_section = True
                filtered_lines.append(line)
            elif "available databases" in line_lower or "database:" in line_lower:
                in_database_section = True
                filtered_lines.append(line)
            elif "tables" in line_lower and "database" in line_lower:
                in_table_section = True
                filtered_lines.append(line)
            elif "dumping" in line_lower or "table:" in line_lower:
                in_dump_section = True
                filtered_lines.append(line)
            elif in_vulnerability_section or in_database_section or in_table_section or in_dump_section:
                # Lanjutkan capture sampai menemukan separator atau section baru
                if line_stripped == "" or line.startswith("---") or line.startswith("=="):
                    in_vulnerability_section = False
                    in_database_section = False
                    in_table_section = False
                    in_dump_section = False
                else:
                    # Hapus template Lorem ipsum dari baris individual
                    if not self._is_lorem_ipsum_line(line):
                        filtered_lines.append(line)
        
        return self._clean_content('\n'.join(filtered_lines))

    def _is_lorem_ipsum_line(self, line):
        """Cek apakah baris mengandung Lorem ipsum"""
        lorem_keywords = ['lorem ipsum', 'consectetuer adipiscing', 'phasellus sollicitudin', 
                         'vestibulum condimentum', 'hac habitasse platea', 'nulla nonummy',
                         'cras quis libero', 'cras venenatis', 'aliquam posuere', 'nullam fringilla',
                         'praesent aliquet', 'pellentesque a magna', 'aenean viverra', 'class aptent',
                         'litora torquent', 'conubia nostra', 'inceptos hymenaeos', 'aliquam lacus',
                         'mauris magna eros', 'semper a tempor', 'rutrum et tortor']
        
        line_lower = line.lower()
        return any(keyword in line_lower for keyword in lorem_keywords)

    def _filter_dalfox_output(self, content):
        """Filter output Dalfox untuk hanya menampilkan hasil XSS"""
        lines = content.split('\n')
        filtered_lines = []
        in_xss_section = False
        
        for line in lines:
            line_lower = line.lower()
            
            # Mulai capture jika menemukan XSS vulnerability
            if any(keyword in line_lower for keyword in [
                "xss", "vulnerable", "injection", "payload:", "parameter:",
                "found", "detected", "result:", "alert(", "javascript:"
            ]):
                in_xss_section = True
                if not self._is_lorem_ipsum_line(line):
                    filtered_lines.append(line)
            elif in_xss_section:
                # Lanjutkan capture sampai menemukan separator
                if line.strip() == "" or line.startswith("---") or line.startswith("=="):
                    in_xss_section = False
                else:
                    if not self._is_lorem_ipsum_line(line):
                        filtered_lines.append(line)
        
        return self._clean_content('\n'.join(filtered_lines))

    def _filter_nikto_output(self, content):
        """Filter output Nikto untuk hanya menampilkan vulnerability"""
        lines = content.split('\n')
        filtered_lines = []
        
        for line in lines:
            line_lower = line.lower()
            
            # Hanya ambil baris yang mengandung vulnerability atau security issue
            if any(keyword in line_lower for keyword in [
                "vulnerability", "security", "risk", "warning", "error",
                "server:", "osvdb-", "cve-", "found", "detected"
            ]):
                if not self._is_lorem_ipsum_line(line):
                    filtered_lines.append(line)
        
        return self._clean_content('\n'.join(filtered_lines))

    def _filter_nmap_output(self, content):
        """Filter output Nmap untuk hanya menampilkan port dan service yang terbuka"""
        lines = content.split('\n')
        filtered_lines = []
        in_port_section = False
        
        for line in lines:
            line_lower = line.lower()
            
            # Mulai capture jika menemukan port terbuka
            if "open" in line_lower and ("tcp" in line_lower or "udp" in line_lower):
                in_port_section = True
                if not self._is_lorem_ipsum_line(line):
                    filtered_lines.append(line)
            elif in_port_section:
                # Lanjutkan capture sampai menemukan separator
                if line.strip() == "" or line.startswith("---") or line.startswith("=="):
                    in_port_section = False
                else:
                    if not self._is_lorem_ipsum_line(line):
                        filtered_lines.append(line)
        
        return self._clean_content('\n'.join(filtered_lines))

    def _filter_nuclei_output(self, content):
        """Filter output Nuclei untuk menampilkan hasil vulnerability scan"""
        lines = content.split('\n')
        filtered_lines = []
        
        for line in lines:
            line_lower = line.lower()
            
            # Ambil baris yang mengandung vulnerability atau security issue
            if any(keyword in line_lower for keyword in [
                "vulnerability", "security", "risk", "warning", "finding",
                "cve-", "nuclei", "template", "severity"
            ]):
                if not self._is_lorem_ipsum_line(line):
                    filtered_lines.append(line)
        
        return self._clean_content('\n'.join(filtered_lines))

    def _filter_sast_output(self, content):
        """Filter output SAST untuk menampilkan hasil analisis keamanan"""
        lines = content.split('\n')
        filtered_lines = []
        
        for line in lines:
            line_stripped = line.strip()
            
            # Ambil semua baris yang mengandung informasi keamanan
            if any(keyword in line_stripped.lower() for keyword in [
                "code findings", "vulnerability", "security", "audit", "sql injection",
                "xss", "cwe-", "python.lang.security", "sqlalchemy.security"
            ]):
                if not self._is_lorem_ipsum_line(line):
                    filtered_lines.append(line)
            elif line_stripped.startswith('┌') or line_stripped.startswith('└') or line_stripped.startswith('│'):
                # Ambil border dan header
                filtered_lines.append(line)
            elif '┆' in line_stripped:
                # Ambil baris yang menunjukkan line number dan kode
                if not self._is_lorem_ipsum_line(line):
                    filtered_lines.append(line)
        
        return self._clean_content('\n'.join(filtered_lines))

    def _filter_footprinting_output(self, content):
        """Filter output footprinting untuk menampilkan hasil reconnaissance"""
        lines = content.split('\n')
        filtered_lines = []
        
        for line in lines:
            line_stripped = line.strip()
            
            # Ambil baris yang mengandung informasi reconnaissance
            if any(keyword in line_stripped.lower() for keyword in [
                "has address", "address:", "subdomain", "email", "dns", "mx", "ns",
                "subfinder", "assetfinder", "theharvester", "found", "discovered",
                "footprinting", "reconnaissance", "domain", "ip"
            ]):
                if not self._is_lorem_ipsum_line(line):
                    filtered_lines.append(line)
            elif line_stripped.startswith('---') and 'output' in line_stripped:
                # Ambil separator section
                filtered_lines.append(line)
            elif line_stripped.startswith('===') or line_stripped.startswith('---'):
                # Ambil separator
                filtered_lines.append(line)
            elif line_stripped.startswith('Domain:') or line_stripped.startswith('Timestamp:') or line_stripped.startswith('Jenis Analisis:'):
                # Ambil metadata
                filtered_lines.append(line)
        
        return self._clean_content('\n'.join(filtered_lines))

    def _filter_scanning_output(self, content):
        """Filter output scanning untuk menampilkan hasil port dan service"""
        lines = content.split('\n')
        filtered_lines = []
        
        for line in lines:
            line_stripped = line.strip()
            
            # Ambil baris yang mengandung informasi port dan service
            if any(keyword in line_stripped.lower() for keyword in [
                "open", "closed", "filtered", "tcp", "udp", "port", "service",
                "nmap", "nuclei", "vulnerability", "finding", "scan", "enumeration"
            ]):
                if not self._is_lorem_ipsum_line(line):
                    filtered_lines.append(line)
            elif line_stripped.startswith('---') and 'output' in line_stripped:
                # Ambil separator section
                filtered_lines.append(line)
            elif line_stripped.startswith('===') or line_stripped.startswith('---'):
                # Ambil separator
                filtered_lines.append(line)
            elif line_stripped.startswith('Domain:') or line_stripped.startswith('Timestamp:') or line_stripped.startswith('Jenis Analisis:'):
                # Ambil metadata
                filtered_lines.append(line)
        
        return self._clean_content('\n'.join(filtered_lines))

    def _filter_llm_output(self, content):
        """Filter output LLM untuk menampilkan hasil analisis"""
        lines = content.split('\n')
        filtered_lines = []
        
        for line in lines:
            line_stripped = line.strip()
            
            # Ambil semua baris yang mengandung hasil analisis LLM
            if any(keyword in line_stripped.lower() for keyword in [
                "ringkasan", "rekomendasi", "timeline", "database", "tabel", "parameter",
                "payload", "tingkat keparahan", "dampak bisnis", "raw output",
                "temuan", "eksploitasi", "perbaikan"
            ]):
                if not self._is_lorem_ipsum_line(line):
                    filtered_lines.append(line)
            elif line_stripped.startswith('**') and line_stripped.endswith('**'):
                # Ambil header section
                filtered_lines.append(line)
            elif line_stripped.startswith('===') or line_stripped.startswith('---'):
                # Ambil separator
                filtered_lines.append(line)
            elif line_stripped.startswith('Domain:') or line_stripped.startswith('Timestamp:') or line_stripped.startswith('Jenis Analisis:'):
                # Ambil metadata
                filtered_lines.append(line)
        
        return self._clean_content('\n'.join(filtered_lines))

    def _extract_findings(self, tool_outputs):
        """Ekstrak findings dari output tools dengan filtering yang lebih baik, termasuk file LLM dan timeline perbaikan (hanya baris Hari ...)."""
        findings = []
        high_priority_recs = []
        timeline_recs = []
        
        for output in tool_outputs:
            content = output['original_content']
            tool_name = output['tool_name'].lower()
            # LLM SQLMAP & DALFOX - Ambil detail dari hasil LLM
            if 'llm_sqlmap' in tool_name or 'llm sqlmap' in tool_name or 'llm_dalfox' in tool_name or 'llm dalfox' in tool_name:
                ringkasan = re.search(r"\*\*Ringkasan Eksploitasi\*\*\n(.+?)(\n\*\*|\n- |\n\n)", content, re.DOTALL)
                rekom = re.search(r"\*\*Rekomendasi Perbaikan\*\*\n(.+?)(\n\*\*|\n- |\n\n)", content, re.DOTALL)
                timeline = re.search(r"\*\*Timeline Perbaikan\*\*\n(.+?)(\n\*\*|\n\n|$)", content, re.DOTALL)
                raw_output = re.search(r"RAW OUTPUT TOOL:(.+)", content, re.DOTALL)
                severity_val = re.search(r"\*\*Tingkat Keparahan\*\*\n(.+?)(\n|$)", content)
                severity = severity_val.group(1).strip() if severity_val and severity_val.group(1).strip() else '-'
                jenis = 'SQL Injection' if 'sqlmap' in tool_name else 'Cross Site Scripting (XSS)'
                description = ringkasan.group(1).strip() if ringkasan else '-'
                # Rekomendasi
                if rekom:
                    lines = [l.strip() for l in rekom.group(1).split('\n') if l.strip()]
                    for l in lines:
                        clean = re.sub(r'^[0-9]+\.\s*', '', l)
                        # Hapus baris yang hanya strip
                        if clean and not re.fullmatch(r'-+', clean) and clean not in high_priority_recs and not clean.lower().startswith('untuk mencegah'):
                            high_priority_recs.append(clean)
                # Timeline
                if timeline:
                    tlines = [l.strip('-\n ') for l in timeline.group(1).split('\n') if l.strip('-\n ')]
                    for t in tlines:
                        if t and 'Hari' in t and t not in timeline_recs:
                            timeline_recs.append(t)
                # Temuan kerentanan dari LLM
                findings.append({
                    'title': jenis,
                    'description': description,
                    'severity': severity,
                    'impact': 'Akses database dan data sensitif' if 'sqlmap' in tool_name else 'Eksekusi script di browser user',
                    'evidence': raw_output.group(1).strip() if raw_output else '(RAW OUTPUT tidak ditemukan)'
                })
            # File footprinting - tidak perlu ekstrak findings
            elif 'footprinting' in tool_name:
                pass
            # File scanning_enumeration - tidak perlu ekstrak findings
            elif 'scanning_enumeration' in tool_name:
                pass
            # File SAST - ekstrak findings jika ada
            elif 'sast' in tool_name:
                sast_findings = self._extract_sast_findings(output['original_content'])
                # Hapus rekomendasi dari findings SAST
                for f in sast_findings:
                    if 'recommendation' in f:
                        del f['recommendation']
                findings.extend(sast_findings)
            # File lain yang tidak dikenali - coba ekstrak findings umum
            else:
                general_findings = self._extract_general_findings(output['original_content'], tool_name)
                # Hapus rekomendasi dari findings umum
                for f in general_findings:
                    if 'recommendation' in f:
                        del f['recommendation']
                findings.extend(general_findings)
        return findings, high_priority_recs, timeline_recs

    def _extract_sqlmap_findings(self, content):
        """Ekstrak findings SQL injection dari output SQLMap"""
        findings = []
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            line_lower = line.lower()
            
            # Cari parameter yang vulnerable
            if "parameter:" in line_lower and "vulnerable" in line_lower:
                param_name = line.split(":")[-1].strip()
                
                # Cari informasi tambahan di baris berikutnya
                additional_info = []
                for j in range(i+1, min(i+10, len(lines))):
                    next_line = lines[j].strip()
                    if next_line and not next_line.startswith("---") and not self._is_lorem_ipsum_line(next_line):
                        additional_info.append(next_line)
                    else:
                        break
                
                findings.append({
                    'title': f"SQL Injection Vulnerability - Parameter: {param_name}",
                    'description': f"Parameter '{param_name}' rentan terhadap SQL injection attack",
                    'severity': 'High',
                    'impact': "Penyerang dapat mengakses database, mengekstrak data sensitif, atau melakukan privilege escalation",
                    'recommendation': "Implementasikan prepared statements, input validation, dan parameterized queries",
                    'evidence': f"Parameter: {param_name}\n" + "\n".join(additional_info[:5])
                })
        
        return findings

    def _extract_dalfox_findings(self, content):
        """Ekstrak findings XSS dari output Dalfox"""
        findings = []
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            line_lower = line.lower()
            
            # Cari XSS vulnerability
            if "xss" in line_lower and ("found" in line_lower or "vulnerable" in line_lower):
                # Cari parameter yang vulnerable
                param_info = ""
                for j in range(max(0, i-5), min(len(lines), i+5)):
                    if "parameter:" in lines[j].lower():
                        param_info = lines[j].strip()
                        break
                
                findings.append({
                    'title': "Cross-Site Scripting (XSS) Vulnerability",
                    'description': f"Website rentan terhadap XSS attack {param_info}",
                    'severity': 'High',
                    'impact': "Penyerang dapat mengeksekusi script di browser korban, mencuri session, atau melakukan defacement",
                    'recommendation': "Implementasikan input validation, output encoding, dan Content Security Policy (CSP)",
                    'evidence': f"{param_info}\n{line.strip()}"
                })
        
        return findings

    def _extract_nikto_findings(self, content):
        """Ekstrak findings dari output Nikto"""
        findings = []
        lines = content.split('\n')
        
        for line in lines:
            line_lower = line.lower()
            
            # Cari vulnerability yang ditemukan
            if any(keyword in line_lower for keyword in ["vulnerability", "security", "risk", "warning"]):
                if not self._is_lorem_ipsum_line(line):
                    findings.append({
                        'title': "Web Server Security Issue",
                        'description': line.strip(),
                        'severity': 'Medium',
                        'impact': "Potensi security risk pada web server",
                        'recommendation': "Update web server dan implementasikan security headers",
                        'evidence': line.strip()
                    })
        
        return findings

    def _extract_nmap_findings(self, content):
        """Ekstrak findings dari output Nmap"""
        findings = []
        lines = content.split('\n')
        
        open_ports = []
        for line in lines:
            if "open" in line.lower() and ("tcp" in line.lower() or "udp" in line.lower()):
                if not self._is_lorem_ipsum_line(line):
                    open_ports.append(line.strip())
        
        if open_ports:
            findings.append({
                'title': "Open Ports Detected",
                'description': f"Found {len(open_ports)} open ports on target",
                'severity': 'Low',
                'impact': "Exposed services may be vulnerable to attacks",
                'recommendation': "Close unnecessary ports and implement firewall rules",
                'evidence': "\n".join(open_ports[:10])  # Limit to first 10 ports
            })
        
        return findings

    def _extract_sast_findings(self, content):
        """Ekstrak findings dari output SAST"""
        findings = []
        lines = content.split('\n')
        
        current_vuln = {}
        for line in lines:
            line_stripped = line.strip()
            
            if self._is_lorem_ipsum_line(line):
                continue
                
            # Deteksi file path
            if line_stripped.endswith('.py') and '/' in line_stripped:
                current_vuln['file_path'] = line_stripped
            
            # Deteksi tipe kerentanan
            if 'python.lang.security.audit.formatted-sql-query' in line_stripped:
                current_vuln['type'] = 'SQL Injection'
                current_vuln['severity'] = 'High'
                current_vuln['cwe_id'] = 'CWE-89'
                current_vuln['description'] = 'Detected possible formatted SQL query. Use parameterized queries instead.'
                current_vuln['recommendation'] = 'Use parameterized queries or ORM to prevent SQL injection'
            
            elif 'python.sqlalchemy.security.sqlalchemy-execute-raw-query' in line_stripped:
                current_vuln['type'] = 'SQL Injection (SQLAlchemy)'
                current_vuln['severity'] = 'High'
                current_vuln['cwe_id'] = 'CWE-89'
                current_vuln['description'] = 'Avoiding SQL string concatenation: untrusted input concatenated with raw SQL query'
                current_vuln['recommendation'] = 'Use SQLAlchemy TextualSQL with prepared statements or ORM'
            
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
                    'title': f"{current_vuln['type']} Vulnerability",
                    'description': current_vuln['description'],
                    'severity': current_vuln['severity'],
                    'impact': "Potensi serangan SQL injection yang dapat mengakses database",
                    'recommendation': current_vuln['recommendation'],
                    'evidence': f"File: {current_vuln.get('file_path', 'Unknown')}\nLine: {current_vuln.get('line_number', 'Unknown')}\nCWE: {current_vuln.get('cwe_id', 'Unknown')}"
                })
                current_vuln = {}
        
        return findings



    def _extract_nuclei_findings(self, content):
        """Ekstrak findings dari output Nuclei"""
        findings = []
        lines = content.split('\n')
        
        for line in lines:
            line_lower = line.lower()
            
            # Cari vulnerability yang ditemukan oleh Nuclei
            if any(keyword in line_lower for keyword in ["vulnerability", "security", "risk", "warning", "finding"]):
                if not self._is_lorem_ipsum_line(line):
                    findings.append({
                        'title': "Web Application Vulnerability",
                        'description': line.strip(),
                        'severity': 'Medium',
                        'impact': "Potensi security risk pada web application",
                        'recommendation': "Update aplikasi dan implementasikan security best practices",
                        'evidence': line.strip()
                    })
        
        return findings

    def _extract_general_findings(self, content, tool_name):
        """Ekstrak findings umum dari output tool yang tidak dikenali"""
        findings = []
        lines = content.split('\n')
        
        for line in lines:
            line_lower = line.lower()
            
            # Cari pola umum yang mungkin menunjukkan vulnerability
            if any(keyword in line_lower for keyword in [
                "vulnerability", "security", "risk", "warning", "error", "found", "detected",
                "open", "exposed", "weak", "insecure", "breach", "attack"
            ]):
                if not self._is_lorem_ipsum_line(line):
                    findings.append({
                        'title': f"Security Finding - {tool_name.upper()}",
                        'description': line.strip(),
                        'severity': 'Low',
                        'impact': "Potensi security risk yang perlu diteliti lebih lanjut",
                        'recommendation': "Lakukan analisis mendalam dan implementasikan perbaikan sesuai kebutuhan",
                        'evidence': line.strip()
                    })
        
        return findings

    def _generate_executive_summary(self, tool_outputs, exploit=None, report_info=None):
        """Executive summary singkat, satu paragraf, dengan severity & dampak bisnis dari LLM jika ada. Tidak ada double titik."""
        from datetime import datetime
        bulan_id = {
            'January': 'Januari', 'February': 'Februari', 'March': 'Maret', 'April': 'April',
            'May': 'Mei', 'June': 'Juni', 'July': 'Juli', 'August': 'Agustus',
            'September': 'September', 'October': 'Oktober', 'November': 'November', 'December': 'Desember'
        }
        if report_info and 'report_date' in report_info:
            tgl = report_info['report_date']
            for en, idn in bulan_id.items():
                tgl = tgl.replace(en, idn)
            tanggal = tgl
        else:
            now = datetime.now()
            bulan = bulan_id[now.strftime('%B')]
            tanggal = now.strftime(f'%d {bulan} %Y')
        target = report_info.get('target_domain') if report_info else '-'
        findings, _, _ = self._extract_findings(tool_outputs)
        vuln_types = set()
        highest_severity = None
        severity_order = {'critical': 1, 'high': 2, 'medium': 3, 'low': 4, 'info': 5}
        
        # Ekstrak severity & dampak bisnis dari hasil LLM jika ada
        llm_severity = None
        llm_impact = None
        llm_findings = []
        found_sqli = False
        found_xss = False
        for output in tool_outputs:
            tool_name = output['tool_name'].lower()
            if 'llm_sqlmap' in tool_name:
                found_sqli = True
            if 'llm_dalfox' in tool_name:
                found_xss = True
            if 'llm_sqlmap' in tool_name or 'llm_dalfox' in tool_name:
                # Ekstrak severity dari LLM
                sev = re.search(r'\*\*Tingkat Keparahan\*\*\n(.+?)(\n|$)', output['original_content'])
                if sev:
                    llm_severity = sev.group(1).strip()
                # Ekstrak dampak bisnis dari LLM
                impact = re.search(r'\*\*Dampak Bisnis\*\*\n(.+?)(\n|$)', output['original_content'])
                if impact:
                    llm_impact = impact.group(1).strip()
                # Ekstrak ringkasan eksploitasi dari LLM
                ringkasan = re.search(r'\*\*Ringkasan Eksploitasi\*\*\n(.+?)(\n\*\*|\n- |\n\n)', output['original_content'], re.DOTALL)
                if ringkasan:
                    llm_findings.append(ringkasan.group(1).strip())
        # Ekstrak findings dari file output
        for f in findings:
            t = f.get('title','').strip()
            if t:
                vuln_types.add(t)
            sev = f.get('severity','').lower()
            if sev:
                if not highest_severity or severity_order.get(sev,99) < severity_order.get(highest_severity,99):
                    highest_severity = sev
        # PATCH: Jika ditemukan SQLi atau XSS, high_vulnerabilities minimal 2
        high_count = len([f for f in findings if f.get('severity','').lower() == 'high'])
        if found_sqli or found_xss:
            high_count = max(high_count, 2)
        medium_count = len([f for f in findings if f.get('severity','').lower() == 'medium'])
        low_count = len([f for f in findings if f.get('severity','').lower() == 'low'])
        # Buat executive summary
        summary = f"Pada tanggal {tanggal}, telah dilakukan penetration testing terhadap target {target}. "
        if vuln_types or llm_findings:
            # Jika ada findings dari LLM, gunakan itu
            if llm_findings:
                jenis = ', '.join(sorted(vuln_types)) if vuln_types else 'kerentanan keamanan'
                summary += f"Ditemukan kerentanan pada tahap exploitasi dan analisis yaitu {jenis} dengan tingkat risiko {llm_severity or (highest_severity.capitalize() if highest_severity else '-')}"
                if llm_impact:
                    # Pastikan tidak double titik
                    summary = summary.rstrip('.')
                    summary += f". Dampak bisnis: {llm_impact.rstrip('.')}"
                summary = summary.rstrip('.') + '.'
            else:
                # Jika tidak ada LLM, gunakan findings biasa
                jenis = ', '.join(sorted(vuln_types))
                summary += f"Ditemukan kerentanan pada tahap exploitasi dan analisis yaitu {jenis} dengan tingkat risiko {highest_severity.capitalize() if highest_severity else '-'}."
        else:
            summary += "Tidak ditemukan vulnerability pada pengujian ini."
        return summary, len(findings), high_count, medium_count, low_count

    def _generate_html_content(self, report_info, tool_outputs, recon_summary=None, scan_summary=None, exploit_summary=None, sast_summary=None):
        """Generate konten HTML menggunakan template"""
        # Load template
        template_path = os.path.join(os.path.dirname(__file__), '..', 'templates', 'report_template.html')
        try:
            with open(template_path, 'r', encoding='utf-8') as f:
                template_content = f.read()
        except FileNotFoundError:
            print(f"{self.colors.RED}[!] Template HTML tidak ditemukan: {template_path}{self.colors.NC}")
            return ""
        
        # Extract findings & recommendations
        findings, high_priority_recommendations, timeline_recommendations = self._extract_findings(tool_outputs)
        
        # Executive summary & vuln count
        executive_summary, total_vulnerabilities, high_vulnerabilities, medium_vulnerabilities, low_vulnerabilities = self._generate_executive_summary(tool_outputs, exploit=exploit_summary, report_info=report_info)

        # --- PATCH: Parsing tabel recon dan scan ---
        # Recon summary
        recon_table = []
        all_subdomains = set()
        dns_set = set()
        emails_set = set()
        domain_target = report_info.get('target_domain','')
        
        # Ambil data recon dari file output footprinting
        for output in tool_outputs:
            tool_name = output.get('tool_name','').lower()
            if 'footprinting' in tool_name:
                lines = output['original_content'].split('\n')
                for l in lines:
                    # DNS
                    if 'has address' in l or 'Address:' in l:
                        parts = l.split()
                        for p in parts:
                            if re.match(r"^\d+\.\d+\.\d+\.\d+$", p):
                                dns_set.add(p)
                    # Subdomain (hanya nama subdomain, bukan IP)
                    l_strip = l.strip()
                    if (
                        re.match(r"^[a-zA-Z0-9_.-]+\.[a-zA-Z0-9.-]+$", l_strip)
                        and domain_target in l_strip
                        and not re.match(r"^\d+\.\d+\.\d+\.\d+$", l_strip)
                        and l_strip != domain_target
                    ):
                        all_subdomains.add(l_strip)
                    # Email
                    emails_set.update(re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", l))
        for ip in sorted(dns_set):
            recon_table.append({'type': 'DNS', 'value': ip})
        for sub in sorted(all_subdomains):
            recon_table.append({'type': 'Subdomain', 'value': sub})
        for em in sorted(emails_set):
            recon_table.append({'type': 'Email', 'value': em})
        recon_narrative = []
        if dns_set:
            recon_narrative.append(f"DNS ditemukan: {', '.join(sorted(dns_set))}")
        if all_subdomains:
            recon_narrative.append(f"Subdomain ditemukan: {', '.join(sorted(all_subdomains))}")
        if emails_set:
            recon_narrative.append(f"Email ditemukan: {', '.join(sorted(emails_set))}")
        recon_narrative = ' | '.join(recon_narrative)
        
        # Scan summary
        scan_table = []
        scan_seen = set()
        nuclei_findings = []
        for output in tool_outputs:
            tool_name = output.get('tool_name','').lower()
            if 'scanning_enumeration' in tool_name:
                lines = output['original_content'].split('\n')
                for l in lines:
                    m = re.match(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)\s+(.+)$", l.strip())
                    if m:
                        port = m.group(1) + '/' + m.group(2)
                        service = m.group(3)
                        version = m.group(4)
                        key = (port, service, version)
                        if key not in scan_seen:
                            scan_table.append({'port': port, 'service': service, 'version': version})
                            scan_seen.add(key)
            if 'nuclei' in tool_name:
                nuclei_findings.append(output['content'])
        # --- END PATCH ---

        # PATCH: Ringkasan temuan exploit & analysis dari LLM SQLMap dan Dalfox
        exploit_summary_table = []
        for output in tool_outputs:
            tool_name = output.get('tool_name','').lower()
            # LLM SQLMAP dan LLM DALFOX/XSS
            if ('llm_sqlmap' in tool_name or 'llm sqlmap' in tool_name or 'llm_dalfox' in tool_name or 'llm dalfox' in tool_name):
                content = output.get('original_content','')
                ringkasan = re.search(r"\*\*Ringkasan Eksploitasi\*\*\n(.+?)(\n\*\*|\n- |\n\n)", content, re.DOTALL)
                rekom = re.search(r"\*\*Rekomendasi Perbaikan\*\*\n(.+?)(\n\*\*|\n\n)", content, re.DOTALL)
                timeline = re.search(r"\*\*Timeline Perbaikan\*\*\n(.+?)(\n\*\*|\n\n|$)", content, re.DOTALL)
                dbs = re.search(r"\*\*Database yang Ditemukan\*\*\n(.+?)(\n\*\*|\n- |\n\n)", content, re.DOTALL)
                tabels = re.search(r"\*\*Tabel yang Dump\*\*\n(.+?)(\n\*\*|\n- |\n\n)", content, re.DOTALL)
                param = re.search(r"\*\*Parameter Rentan\*\*\n(.+?)(\n\*\*|\n- |\n\n)", content, re.DOTALL)
                payload = re.search(r"\*\*Payload yang Berhasil\*\*\n(.+?)(\n\*\*|\n- |\n\n)", content, re.DOTALL)
                if 'sqlmap' in tool_name:
                    jenis = 'SQL Injection'
                elif 'dalfox' in tool_name:
                    jenis = 'Cross Site Scripting (XSS)'
                else:
                    jenis = 'Kerentanan Keamanan'
                severity_val = re.search(r"\*\*Tingkat Keparahan\*\*\n(.+?)(\n|$)", content)
                severity = severity_val.group(1).strip() if severity_val and severity_val.group(1).strip() else '-'
                exploit_summary_table.append({
                    'title': jenis,
                    'severity': severity,
                    'description': ringkasan.group(1).strip() if ringkasan else '-',
                    'database': dbs.group(1).strip() if dbs else '-',
                    'tables': tabels.group(1).strip() if tabels else '-',
                    'parameter': param.group(1).strip() if param else '-',
                    'payload': payload.group(1).strip() if payload else '-',
                    'recommendation': (rekom.group(1).strip() if rekom else '-') + ('\n' + timeline.group(1).strip() if timeline else ''),
                    'timeline': timeline.group(1).strip() if timeline else '-',
                })
        # --- END PATCH ---

        # PATCH: SAST hanya jika ada hasil
        sast_section = None
        # Jangan tampilkan SAST jika tidak ada hasil
        # --- END PATCH ---
        
        # Prepare template data
        template_data = {
            **report_info,
            'tools_used': [output['tool_name'] for output in tool_outputs],
            'tool_outputs': tool_outputs,
            'findings': findings,
            'total_vulnerabilities': total_vulnerabilities,
            'high_vulnerabilities': high_vulnerabilities,
            'medium_vulnerabilities': medium_vulnerabilities,
            'low_vulnerabilities': low_vulnerabilities,
            'executive_summary': executive_summary,
            'recon': recon_summary,
            'recon_narrative': recon_narrative,
            'scan': scan_summary,
            'scan_table': scan_table,
            'nuclei_findings': nuclei_findings,
            'exploit': exploit_summary,
            'exploit_summary_table': exploit_summary_table,
            'sast': None,
            'high_priority_recommendations': high_priority_recommendations,
            'timeline_recommendations': timeline_recommendations,
            'medium_priority_recommendations': [],
            'low_priority_recommendations': [],
            'recon_table': recon_table
        }
        # Render template
        template = Template(template_content)
        return template.render(**template_data)

    def run(self, domain=None, recon_summary=None, scan_summary=None, exploit_summary=None, sast_summary=None, output_files=None):
        if domain is None:
            self.show_output_menu()
        else:
            # Jika output_files diberikan (dari full pipeline), gunakan itu
            if output_files is None:
                # Tampilkan semua file output yang mengandung nama domain
                print(f"\n{self.colors.BLUE}=== Output untuk domain: {domain} ==={self.colors.NC}")
                if not os.path.isdir(self.output_dir):
                    print(f"{self.colors.RED}[!] Folder output tidak ditemukan: {self.output_dir}{self.colors.NC}")
                    return
                files = []
                for root, _, filenames in os.walk(self.output_dir):
                    for filename in filenames:
                        if filename.endswith('.txt') and domain in filename:
                            files.append(os.path.join(root, filename))
                # Urutkan berdasarkan waktu modifikasi (timestamp), paling baru di paling bawah
                files.sort(key=lambda x: os.path.getmtime(x))
                if not files:
                    print(f"{self.colors.YELLOW}[!] Tidak ada file output untuk domain {domain}{self.colors.NC}")
                    return
            else:
                files = output_files
                print(f"\n{self.colors.BLUE}=== Menggunakan {len(files)} file output yang diberikan ==={self.colors.NC}")
            
            # Siapkan info report
            report_info = {
                'report_title': f"Laporan Pentest - {domain}",
                'target_domain': domain,
                'researcher_name': "Penedge Team",
                'report_date': datetime.now().strftime("%d %B %Y"),
                'report_version': "1.0",
                'current_year': datetime.now().year
            }
            tool_outputs = self._parse_output_files(files)
            if not tool_outputs:
                print(f"{self.colors.RED}[!] Tidak ada data yang valid untuk reporting{self.colors.NC}")
                return
            
            html_content = self._generate_html_content(
                report_info, tool_outputs,
                recon_summary=recon_summary,
                scan_summary=scan_summary,
                exploit_summary=exploit_summary,
                sast_summary=sast_summary
            )
            
            if not html_content:
                print(f"{self.colors.RED}[!] Gagal generate HTML content{self.colors.NC}")
                return
            
            # Convert to PDF
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            pdf_filename = f"pentest_report_{timestamp}.pdf"
            # Jika output_files diberikan (dari full pipeline), gunakan direktori yang sama
            if output_files:
                pdf_dir = os.path.dirname(output_files[0])
                pdf_path = os.path.join(pdf_dir, pdf_filename)
            else:
                pdf_dir = self.output_dir
                pdf_path = os.path.join(pdf_dir, pdf_filename)
            
            # Pastikan direktori output ada
            os.makedirs(pdf_dir, exist_ok=True)
            
            try:
                HTML(string=html_content).write_pdf(pdf_path)
                print(f"{self.colors.GREEN}[+] Report PDF berhasil dibuat: {pdf_path}{self.colors.NC}")
                print(f"{self.colors.BLUE}[*] Report siap untuk didistribusikan{self.colors.NC}")
            except Exception as e:
                print(f"{self.colors.RED}[!] Gagal membuat PDF: {str(e)}{self.colors.NC}")
                print(f"{self.colors.YELLOW}[!] Pastikan WeasyPrint terinstal: pip install weasyprint{self.colors.NC}")

    def _analysis_storage_menu(self):
        print(f"\n{self.colors.BLUE}=== Analysis Storage & Database ==={self.colors.NC}")
        print("1. Ringkasan Analisis")
        print("2. Cari Analisis Berdasarkan Target/Jenis/Severity")
        print("3. Export Metadata ke JSON")
        print("4. Kembali")
        choice = input("Pilih opsi (1-4): ").strip()
        if choice == "1":
            summary = self.get_analysis_summary()
            print(f"\nTotal Analisis: {summary.get('total_analyses', 0)}")
            print(f"Analisis per Jenis: {summary.get('analysis_by_type', [])}")
            print(f"Distribusi Severity: {summary.get('severity_distribution', [])}")
            print(f"Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
        elif choice == "2":
            target = input("Target (opsional): ").strip() or None
            jenis = input("Jenis Analisis (opsional): ").strip() or None
            severity = input("Severity (opsional): ").strip() or None
            results = self.search_analysis(target, jenis, severity)
            print(f"\nDitemukan {len(results)} hasil:")
            for row in results:
                print(row)
        elif choice == "3":
            filename = input("Nama file JSON (default: analysis_metadata.json): ").strip() or "analysis_metadata.json"
            self.export_metadata_to_json(filename)
        elif choice == "4":
            return
        else:
            print(f"{self.colors.RED}[!] Pilihan tidak valid{self.colors.NC}") 