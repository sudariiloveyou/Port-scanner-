#!/usr/bin/env python3
import nmap
import requests
import json
from datetime import datetime
from urllib.parse import quote
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Configuration
VERSION = "1.1"
SCAN_ARGS = '-T4 -A -v -Pn'
CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/1.0"
TIMEOUT = 15

# Color shortcuts
R = Fore.RED
G = Fore.GREEN
Y = Fore.YELLOW
C = Fore.CYAN
B = Fore.BLUE
M = Fore.MAGENTA
W = Fore.WHITE
D = Style.DIM
BR = Style.BRIGHT
RS = Style.RESET_ALL

BANNER = f"""{BR}{M}
▓█████▄  ▄▄▄       ██▀███   ██ ▄█▀ ██▓███   ██▀███   ▒█████   ██▓    
▒██▀ ██▌▒████▄    ▓██ ▒ ██▒ ██▄█▒ ▓██░  ██▒▓██ ▒ ██▒▒██▒  ██▒▓██▒    
░██   █▌▒██  ▀█▄  ▓██ ░▄█ ▒▓███▄░ ▓██░ ██▓▒▓██ ░▄█ ▒▒██░  ██▒▒██░    
░▓█▄   ▌░██▄▄▄▄██ ▒██▀▀█▄  ▓██ █▄ ▒██▄█▓▒ ▒▒██▀▀█▄  ▒██   ██░▒██░    
░▒████▓  ▓█   ▓██▒░██▓ ▒██▒▒██▒ █▄▒██▒ ░  ░░██▓ ▒██▒░ ████▓▒░░██████▒
 ▒▒▓  ▒  ▒▒   ▓▒█░░ ▒▓ ░▒▓░▒ ▒▒ ▓▒▒▓▒░ ░  ░░ ▒▓ ░▒▓░░ ▒░▒░▒░ ░ ▒░▓  ░
 ░ ▒  ▒   ▒   ▒▒ ░  ░▒ ░ ▒░░ ░▒ ▒░░▒ ░       ░▒ ░ ▒░  ░ ▒ ▒░ ░ ░ ▒  ░
 ░ ░  ░   ░   ▒     ░░   ░ ░ ░░ ░ ░░         ░░   ░ ░ ░ ░ ▒    ░ ░   
   ░          ░  ░   ░     ░  ░               ░         ░ ░      ░  ░
{BR}{C}Advanced Port Scanner with Vulnerability Detection v{VERSION}
{BR}{Y}For authorized security testing only. Use responsibly.{RS}
"""

def print_header(text):
    print(f"\n{BR}{C}▶ {text.upper()}{RS}")

def print_success(text):
    print(f"{G}[✓] {text}{RS}")

def print_warning(text):
    print(f"{Y}[!] {text}{RS}")

def print_error(text):
    print(f"{R}[✗] {text}{RS}")

def print_info(text):
    print(f"{B}[i] {text}{RS}")

def check_cve(service_name, version):
    """Check for known vulnerabilities using NVD API"""
    try:
        query = f"{service_name}:{version}"
        encoded_query = quote(query)
        response = requests.get(f"{CVE_API_URL}?keyword={encoded_query}", timeout=TIMEOUT)
        
        if response.status_code == 200:
            data = json.loads(response.text)
            if data['totalResults'] > 0:
                cves = [vuln['cve']['CVE_data_meta']['ID'] 
                       for vuln in data['result']['CVE_Items'][:3]]
                return f"{R}Potential CVEs: {', '.join(cves)}{RS}"
        return f"{G}No known CVEs found{RS}"
    except Exception as e:
        return f"{Y}CVE API error: {str(e)}{RS}"

def check_shodan(ip):
    """Check if target is exposed on Shodan"""
    try:
        response = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=10)
        if response.status_code == 200:
            data = response.json()
            if data.get('ports'):
                return f"{R}Shodan Detected: Ports {', '.join(map(str, data['ports']))} exposed{RS}"
    except:
        pass
    return None

def port_scan(target):
    """Perform comprehensive port scan with service detection"""
    try:
        nm = nmap.PortScanner()
        print_header(f"starting scan on {target}")
        print_info(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print_info(f"Scan Arguments: {SCAN_ARGS}")
        
        # Run the scan
        print_info("Scanning... This may take several minutes")
        scan_result = nm.scan(hosts=target, arguments=SCAN_ARGS)
        
        print_success(f"Scan completed: {scan_result['nmap']['scanstats']['uphosts']} hosts up")
        
        for host in nm.all_hosts():
            print_header(f"scan results for {host}")
            print(f"{BR}{W}Hostname:{RS} {nm[host].hostname() or 'unknown'}")
            print(f"{BR}{W}Status:{RS} {G if nm[host].state() == 'up' else R}{nm[host].state()}{RS}")
            
            # Shodan check
            shodan_info = check_shodan(host)
            if shodan_info:
                print_warning(shodan_info)
            
            for proto in nm[host].all_protocols():
                print(f"\n{BR}{M}Protocol:{RS} {proto}")
                print(f"{D}{'-'*80}{RS}")
                print(f"{BR}{W}PORT\tSTATE\tSERVICE\tVERSION\tVULNERABILITIES{RS}")
                print(f"{D}{'-'*80}{RS}")
                
                for port in sorted(nm[host][proto].keys()):
                    service = nm[host][proto][port]
                    port_info = f"{B}{port}/{proto}{RS}"
                    state = f"{G if service['state'] == 'open' else R}{service['state']}{RS}"
                    service_info = f"{W}{service['name']} {service.get('product', '')} {service.get('version', '')}{RS}".strip()
                    
                    # Vulnerability assessment
                    vuln_info = check_cve(service['name'], service.get('version', '')) if 'version' in service else ""
                    
                    print(f"{port_info}\t{state}\t{service_info}\t{vuln_info}")

    except nmap.PortScannerError as e:
        print_error(f"Scan error: {str(e)}")
    except Exception as e:
        print_error(f"Unexpected error: {str(e)}")

if __name__ == "__main__":
    print(BANNER)
    
    try:
        target = input(f"{BR}{C}Enter target IP/hostname:{RS} ").strip()
        if not target:
            raise ValueError("Target cannot be empty")
            
        port_scan(target)
    except KeyboardInterrupt:
        print_error("\nScan aborted by user")
    except Exception as e:
        print_error(f"Error: {str(e)}")
