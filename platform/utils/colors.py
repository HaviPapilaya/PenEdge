"""
Modul untuk menangani warna output terminal
"""

class Colors:
    """Kelas untuk menangani warna ANSI untuk output terminal"""
    
    def __init__(self):
        # ANSI warna untuk output
        self.RED = '\033[0;31m'
        self.GREEN = '\033[0;32m'
        self.BLUE = '\033[0;34m'
        self.YELLOW = '\033[1;33m'
        self.NC = '\033[0m'  # No Color
        
    def red(self, text):
        """Mengembalikan teks dengan warna merah"""
        return f"{self.RED}{text}{self.NC}"
    
    def green(self, text):
        """Mengembalikan teks dengan warna hijau"""
        return f"{self.GREEN}{text}{self.NC}"
    
    def blue(self, text):
        """Mengembalikan teks dengan warna biru"""
        return f"{self.BLUE}{text}{self.NC}"
    
    def yellow(self, text):
        """Mengembalikan teks dengan warna kuning"""
        return f"{self.YELLOW}{text}{self.NC}" 