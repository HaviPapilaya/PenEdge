#!/usr/bin/env python3
"""
Script untuk mengecek ketersediaan tools penetration testing
"""

import subprocess
import shutil
from platform.utils.colors import Colors

class ToolChecker:
    def __init__(self):
        self.colors = Colors()
        
    def check_tool(self, tool_name, command=None):
        """Mengecek apakah tool tersedia"""
        if command is None:
            command = tool_name
            
        if shutil.which(command):
            return True, "✅"
        else:
            return False, "❌"
            
    def run_check(self, tool_name, command=None):
        """Menjalankan pengecekan tool"""
        available, status = self.check_tool(tool_name, command)
        print(f"{status} {tool_name}")
        return available
        
    def check_all_tools(self):
        """Mengecek semua tools yang diperlukan"""
        print(f"{self.colors.BLUE}🔍 Checking Penetration Testing Tools Availability{self.colors.NC}")
        print("=" * 50)
        
        tools = [
            # Core tools
            ("nmap", None),
            ("curl", None),
            ("wget", None),
            ("dig", None),
            ("host", None),
            ("nslookup", None),
            ("whois", None),
            ("grep", None),
            
            # SAST tools
            ("semgrep", None),
            ("ollama", None),
            
            # Subdomain enumeration
            ("subfinder", None),
            ("assetfinder", None),
            ("amass", None),
            ("sublist3r", None),
            ("theHarvester", None),
            
            # Web tools
            ("whatweb", None),
            ("exiftool", None),
            ("nikto", None),
            
            # Vulnerability tools
            ("sqlmap", None),
            ("dalfox", None),
            ("fimap", None),
            
            # Network tools
            ("netcat", "nc"),
            ("masscan", None),
            ("rustscan", None),
        ]
        
        available_count = 0
        total_count = len(tools)
        
        print(f"\n{self.colors.YELLOW}Core Tools:{self.colors.NC}")
        for tool, command in tools[:8]:
            if self.run_check(tool, command):
                available_count += 1
                
        print(f"\n{self.colors.YELLOW}SAST Tools:{self.colors.NC}")
        for tool, command in tools[8:10]:
            if self.run_check(tool, command):
                available_count += 1
                
        print(f"\n{self.colors.YELLOW}Subdomain Enumeration:{self.colors.NC}")
        for tool, command in tools[10:15]:
            if self.run_check(tool, command):
                available_count += 1
                
        print(f"\n{self.colors.YELLOW}Web Tools:{self.colors.NC}")
        for tool, command in tools[15:18]:
            if self.run_check(tool, command):
                available_count += 1
                
        print(f"\n{self.colors.YELLOW}Vulnerability Tools:{self.colors.NC}")
        for tool, command in tools[18:21]:
            if self.run_check(tool, command):
                available_count += 1
                
        print(f"\n{self.colors.YELLOW}Network Tools:{self.colors.NC}")
        for tool, command in tools[21:]:
            if self.run_check(tool, command):
                available_count += 1
        
        print("\n" + "=" * 50)
        print(f"{self.colors.GREEN}📊 Summary: {available_count}/{total_count} tools available{self.colors.NC}")
        
        if available_count == total_count:
            print(f"{self.colors.GREEN}🎉 All tools are available! You're ready to go.{self.colors.NC}")
        elif available_count >= total_count * 0.7:
            print(f"{self.colors.YELLOW}⚠️  Most tools are available. Some features may be limited.{self.colors.NC}")
        else:
            print(f"{self.colors.RED}❌ Many tools are missing. Consider installing them for full functionality.{self.colors.NC}")
            
        return available_count, total_count

def main():
    checker = ToolChecker()
    checker.check_all_tools()

if __name__ == "__main__":
    main() 