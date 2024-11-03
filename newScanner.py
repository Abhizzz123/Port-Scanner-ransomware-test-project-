import socket
import logging
from scapy.all import sr1, IP, TCP, UDP, ICMP
import nmap
import datetime
from colorama import Fore, Style
from concurrent.futures import ThreadPoolExecutor
import warnings
import time
import subprocess
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse 
import re
from utils.vulnerability_database import VulnerabilityDatabase

# Set up logging
logging.basicConfig(filename='scanner.log', level=logging.ERROR,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def scan_port(ip, port, scan_type='tcp'):
    try:
        if scan_type == 'tcp':
            with socket.create_connection((ip, port), timeout=1) as sock:
                sock.sendall(b"GET / HTTP/1.1\r\n\r\n")
                banner = sock.recv(1024).decode('utf-8', 'ignore').strip()

                # OS Detection (using TCP)
                packet = IP(dst=ip)/TCP(dport=port, flags="S")
                response = sr1(packet, timeout=1, verbose=0)
                if response is not None:
                    os_fingerprint = response.sprintf(r"%TCP.options%")
                else:
                    os_fingerprint = None
                return port, True, banner, None, os_fingerprint
        elif scan_type == 'syn':
            packet = IP(dst=ip)/TCP(dport=port, flags="S")
            response = sr1(packet, timeout=1, verbose=0)
            if response is not None and response.haslayer(TCP) and response[TCP].flags == "SA":
                return port, True, None, None, None
            else:
                return port, False, None, None, None
        elif scan_type == 'udp':
            packet = IP(dst=ip)/UDP(dport=port)/ICMP()
            response = sr1(packet, timeout=1, verbose=0)
            if response is None:
                return port, True, None, None, None
            elif response.haslayer(ICMP) and response[ICMP].type == 3 and response[ICMP].code == 3:
                return port, False, None, None, None
            else:
                return port, True, None, None, None
        else:
            return port, False, None, f"Invalid scan type: {scan_type}", None
    except (socket.timeout, ConnectionRefusedError, socket.error) as e:
        logging.error(f"Error scanning port {port}: {e}")
        return port, False, None, str(e), None
def scan_for_sqli(url):
    try:
        print(Fore.YELLOW + Style.BRIGHT + "\n---------------------------------------" + Style.RESET_ALL)
        print(Fore.YELLOW + Style.BRIGHT + "   SQL INJECTION DETAILS" + Style.RESET_ALL)
        print(Fore.YELLOW + Style.BRIGHT + "---------------------------------------\n" + Style.RESET_ALL)
        result = subprocess.run(['ghauri', '-u', url, '--batch'], capture_output=True, text=True)
        output = result.stdout

        if result.returncode != 0:
            print('\n')
            print(Fore.RED + Style.BRIGHT + "  SQL Injection: Error occurred during Ghauri scan." + Style.RESET_ALL)
            return output, "Unknown"

        if "is vulnerable" in output:
            print(Fore.GREEN + Style.BRIGHT + " [✓] SQL Injection: Vulnerable" + Style.RESET_ALL)

            # Extract vulnerable parameters and their details
            param_matches = re.finditer(r"Parameter '(\w+)' is vulnerable", output)
            for match in param_matches:
                param_name = match.group(1)
                print(Fore.GREEN + Style.BRIGHT + f"    Parameter: {param_name}" + Style.RESET_ALL)

            # Extract and print the type of SQL injection (if Ghauri provides this information)
            type_match = re.search(r"Type: (\w+)", output)
            if type_match:
                injection_type = type_match.group(1)
                print(Fore.GREEN + Style.BRIGHT + f"    Type: {injection_type}" + Style.RESET_ALL)

            # Severity assessment (you may need to refine this based on Ghauri's output)
            severity = "High"  # Default to High for SQL Injection
            print(Fore.YELLOW + Style.BRIGHT + f"    Severity: {severity}" + Style.RESET_ALL)

        else:
            severity = "Low"
            print(Fore.GREEN + Style.BRIGHT + "[x] SQL Injection: Not vulnerable" + Style.RESET_ALL)
            print(Fore.GREEN + Style.BRIGHT + f"[*] Severity: {severity}"+ Style.RESET_ALL)
            

        return output, severity

    except FileNotFoundError:
        print(Fore.RED + Style.BRIGHT + "Error: Ghauri not found. Please install Ghauri from its GitHub repository." + Style.RESET_ALL)
        return "", "Unknown"
    except Exception as e:
        print(Fore.RED + Style.BRIGHT + f"  SQL Injection: An unexpected error occurred: {e}" + Style.RESET_ALL)
        return str(e), "Unknown"

def scan_for_xss(url):
    try:
        print(Fore.YELLOW + Style.BRIGHT + "\n---------------------------------------" + Style.RESET_ALL)
        print(Fore.YELLOW + Style.BRIGHT + "   NIKTO SCAN DETAILS" + Style.RESET_ALL)
        print(Fore.YELLOW + Style.BRIGHT + "---------------------------------------\n" + Style.RESET_ALL)
        result = subprocess.run(['nikto', '-h', url, '-Tuning', 'x'], capture_output=True, text=True)
        output = result.stdout
        severity = "Low"

        if result.returncode != 0:
            print(Fore.RED + Style.BRIGHT + "  XSS: Error occurred during Nikto scan." + Style.RESET_ALL)
            return output

        vulnerabilities = []
        for line in output.split('\n'):
            if "OSVDB-" in line and "XSS" in line:
                vulnerabilities.append(line)

        if vulnerabilities:
            print(Fore.GREEN + Style.BRIGHT + "[x] XSS: Vulnerable" + Style.RESET_ALL)
            for vuln in vulnerabilities:
                print(Fore.GREEN + Style.BRIGHT + f"    {vuln}" + Style.RESET_ALL)

            # Severity assessment (example - you may need to refine this)
            severity = "Medium"  # Default to Medium for XSS
            print(Fore.YELLOW + Style.BRIGHT + f"    Severity: {severity}" + Style.RESET_ALL)
        else:
            print(Fore.GREEN + Style.BRIGHT + " [✓] XSS: Not vulnerable" + Style.RESET_ALL)

        return output, severity

    except FileNotFoundError:
        print(Fore.RED + Style.BRIGHT + "Error: Nikto not found. Please install Nikto." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + Style.BRIGHT + f"  XSS: An unexpected error occurred: {e}" + Style.RESET_ALL)

def scan_for_waf(url):
    print(Fore.YELLOW + Style.BRIGHT + "\n---------------------------------------" + Style.RESET_ALL)
    print(Fore.YELLOW + Style.BRIGHT + "   WEB APPLICATION FIREWALL DETAILS" + Style.RESET_ALL)
    print(Fore.YELLOW + Style.BRIGHT + "---------------------------------------\n" + Style.RESET_ALL)
    try:
        result = subprocess.run(['wafw00f', url], capture_output=True, text=True)
        output = result.stdout

        # Parse the output to identify the WAF and its details
        waf_match = re.search(r"Web Application Firewall: (.+)", output)
        if waf_match:
            waf_info = waf_match.group(1).split(" - ")
            waf_name = waf_info[0]
            waf_manufacturer = waf_info[1] if len(waf_info) > 1 else "Unknown"
            print(Fore.BLUE + Style.BRIGHT + f" [×] WAF detected: {waf_name} by {waf_manufacturer}" + Style.RESET_ALL)
        else:
            print(Fore.GREEN + Style.BRIGHT + " [✓] No WAF detected" + Style.RESET_ALL)

    except FileNotFoundError:
        print(Fore.RED + Style.BRIGHT +"Error: wafw00f not found. Please install wafw00f." + Style.RESET_ALL)

    except Exception as e:
        print(Fore.RED + Style.BRIGHT + f"Error scanning for WAF: {e}" + Style.RESET_ALL)
def is_valid_target(url):
    """Check if the input can be processed for subdomain enumeration."""
    try:
        # If it's already a domain without http/https
        if not url.startswith(('http://', 'https://')):
            return url
            
        # If it's a full URL, extract the domain
        parsed = urlparse(url)
        domain = parsed.netloc
        
        # Remove port number if present
        if ':' in domain:
            domain = domain.split(':')[0]
            
        return domain
    except Exception:
        return None
def scan_for_uniscan(target):
    print(Fore.YELLOW + Style.BRIGHT + "\n------------------------------" + Style.RESET_ALL)
    print(Fore.YELLOW + Style.BRIGHT + "  SUBLIST3R DETAILS " + Style.RESET_ALL)
    print(Fore.YELLOW + Style.BRIGHT + "------------------------------\n" + Style.RESET_ALL)
    
    try:
        # Get clean domain from target
        domain = is_valid_target(target)
        if not domain:
            print(Fore.RED + Style.BRIGHT + "Error: Invalid URL or domain format" + Style.RESET_ALL)
            return
        
        # Run Sublist3r
        print(Fore.BLUE + f"Running subdomain enumeration for: {domain}" + Style.RESET_ALL)
        result = subprocess.run(
            ['python3', 'Sublist3r/sublist3r.py', '-d', domain],
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            print(Fore.RED + Style.BRIGHT + "Sublist3r: Error occurred during the scan." + Style.RESET_ALL)
            print(Fore.RED + result.stderr + Style.RESET_ALL)
            return
        
        # Process and display results
        output = result.stdout
        subdomains = [line.strip() for line in output.splitlines() if line.strip() and not line.startswith('*')]
        
        if subdomains:
            print(Fore.GREEN + Style.BRIGHT + "\n[✓] Discovered Subdomains:" + Style.RESET_ALL)
            for subdomain in subdomains:
                print(Fore.WHITE + f"    - {subdomain}" + Style.RESET_ALL)
        else:
            print(Fore.YELLOW + "\n[x ]No subdomains were discovered." + Style.RESET_ALL)
            
    except FileNotFoundError:
        print(Fore.RED + Style.BRIGHT + 
              "Error: Sublist3r not found. Please ensure it's installed in ../Sublist3r/" + 
              Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + Style.BRIGHT + f"An unexpected error occurred: {str(e)}" + Style.RESET_ALL)
def check_robots_txt(url):
    print(Fore.YELLOW + Style.BRIGHT + "\n---------------------------------------" + Style.RESET_ALL)
    print(Fore.YELLOW + Style.BRIGHT + "  ROBOTS.TXT ANALYSIS" + Style.RESET_ALL)
    print(Fore.YELLOW + Style.BRIGHT + "---------------------------------------\n" + Style.RESET_ALL)

    try:
        # Normalize URL and construct robots.txt path
        base_url = url.rstrip('/')
        robots_url = f"{base_url}/robots.txt"

        # Send request with custom headers to avoid blocking
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/plain,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        }

        response = requests.get(robots_url, headers=headers, timeout=10, verify=False)

        if response.status_code == 200:
            print(Fore.BLUE + Style.BRIGHT + f"[+] Robots.txt found: {robots_url}" + Style.RESET_ALL)

            # Parse and analyze robots.txt content
            content = response.text
            disallowed_paths = []
            allowed_paths = []
            sitemaps = []
            user_agents = []

            current_agent = "*"
            for line in content.splitlines():
                line = line.strip().lower()
                if line and not line.startswith('#'):
                    if line.startswith('user-agent:'):
                        current_agent = line.split(':', 1)[1].strip()
                        if current_agent not in user_agents:
                            user_agents.append(current_agent)
                    elif line.startswith('disallow:'):
                        path = line.split(':', 1)[1].strip()
                        if path and path not in disallowed_paths:
                            disallowed_paths.append((current_agent, path))
                    elif line.startswith('allow:'):
                        path = line.split(':', 1)[1].strip()
                        if path and path not in allowed_paths:
                            allowed_paths.append((current_agent, path))
                    elif line.startswith('sitemap:'):
                        sitemap = line.split(':', 1)[1].strip()
                        if sitemap and sitemap not in sitemaps:
                            sitemaps.append(sitemap)

            # Display findings
            if user_agents:
                print(Fore.GREEN + Style.BRIGHT + "\n[+] User Agents:" + Style.RESET_ALL)
                for agent in user_agents:
                    print(f"    - {agent}")

            if disallowed_paths:
                print(Fore.GREEN + "\n[+] Disallowed Paths:" + Style.RESET_ALL)
                for agent, path in disallowed_paths:
                    print(f"    - [{agent}] {path}")

                    # Check for sensitive directories
                    sensitive_patterns = [
                        '/admin', '/backup', '/config', '/db',
                        '/logs', '/test', '/tmp', '/private'
                    ]
                    for pattern in sensitive_patterns:
                        if pattern in path.lower():
                            print(Fore.RED + f"      [!] Potential sensitive directory: {path}" + Style.RESET_ALL)

            if allowed_paths:
                print(Fore.GREEN + Style.BRIGHT +"\n[+] Allowed Paths:" + Style.RESET_ALL)
                for agent, path in allowed_paths:
                    print(f"    - [{agent}] {path}")

            if sitemaps:
                print(Fore.GREEN + Style.BRIGHT +"\n[+] Sitemaps:" + Style.RESET_ALL)
                for sitemap in sitemaps:
                    print(f"    - {sitemap}")
                    # Try to fetch and analyze sitemap
                    try:
                        sitemap_resp = requests.get(sitemap, headers=headers, timeout=10, verify=False)
                        if sitemap_resp.status_code == 200:
                            soup = BeautifulSoup(sitemap_resp.content, 'xml')
                            urls = soup.find_all('loc')
                            if urls:
                                print(f"      Found {len(urls)} URLs in sitemap")
                    except Exception as e:
                        print(Fore.RED + Style.BRIGHT + f"      Error fetching sitemap: {str(e)}" + Style.RESET_ALL)

            # Security Analysis
            print(Fore.GREEN + Style.BRIGHT +"\n[+] Security Analysis:" + Style.RESET_ALL)

            # Check for common security issues
            security_issues = []

            if not any('admin' in path[1].lower() for path in disallowed_paths):
                security_issues.append("Admin paths not explicitly blocked")

            if not any('backup' in path[1].lower() for path in disallowed_paths):
                security_issues.append("Backup directories not explicitly blocked")

            if not disallowed_paths:
                security_issues.append("No disallow rules found - site might be completely open to crawlers")

            if '*' not in user_agents:
                security_issues.append("No default User-Agent (*) rule specified")

            # Report security issues
            if security_issues:
                print(Fore.YELLOW + Style.BRIGHT +"  [!] Potential Security Issues:" + Style.RESET_ALL)
                for issue in security_issues:
                    print(Fore.YELLOW + f"    - {issue}" + Style.RESET_ALL)
            else:
                print(Fore.GREEN + Style.BRIGHT +"  [+] No obvious security issues found" + Style.RESET_ALL)

            # Recommendations
            print(Fore.GREEN + Style.BRIGHT +"\n[+] Recommendations:" + Style.RESET_ALL)
            if security_issues:
                print("  - Consider adding explicit disallow rules for sensitive directories")
                print("  - Add a default User-Agent (*) rule")
                print("  - Review allowed paths for potential security risks")
            else:
                print("  - Continue monitoring robots.txt for changes")
                print("  - Regularly audit allowed paths")

            return {
                'status': 'found',
                'url': robots_url,
                'user_agents': user_agents,
                'disallowed_paths': disallowed_paths,
                'allowed_paths': allowed_paths,
                'sitemaps': sitemaps,
                'security_issues': security_issues
            }

        else:
            print(Fore.RED + Style.BRIGHT + f"[-] Robots.txt not found (Status: {response.status_code})" + Style.RESET_ALL)
            print(Fore.YELLOW + Style.BRIGHT + "\n[!] Recommendations:" + Style.RESET_ALL)
            print("  - Consider implementing robots.txt to control crawler access")
            print("  - Define explicit rules for sensitive directories")
            return {'status': 'not_found', 'code': response.status_code}

    except requests.exceptions.SSLError:
        print(Fore.RED + Style.BRIGHT + "[-] SSL Certificate Verification Failed" + Style.RESET_ALL)
        print(Fore.YELLOW + Style.BRIGHT +"[!] Attempting to continue without verification..." + Style.RESET_ALL)
        # You might want to implement a retry mechanism here

    except requests.exceptions.RequestException as e:
        print(Fore.RED + Style.BRIGHT + f"[-] Error checking robots.txt: {str(e)}" + Style.RESET_ALL)
        return {'status': 'error', 'message': str(e)}

    except Exception as e:
        print(Fore.RED + Style.BRIGHT + f"[-] Unexpected error: {str(e)}" + Style.RESET_ALL)
        return {'status': 'error', 'message': str(e)}

def scan_target(target, port_range="1-1000", thorough=False, scan_type='tcp', url=None):
    nm = nmap.PortScanner()
    scan_args = "-sT"
    if scan_type == 'syn':
        scan_args = "-sS"
    elif scan_type == 'udp':
        scan_args = "-sU"
    if thorough:
        scan_args += " -A -sC --traceroute"

    nm.scan(target, port_range, arguments=scan_args)

    open_ports = []
    script_results = {}
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            ports = list(nm[host][proto].keys())
            for port in ports:
                if nm[host][proto][port]['state'] == 'open':
                    banner = nm[host][proto][port].get('product', 'Unknown')

                    # Refined OS Detection (using nmap)
                    os_matches = nm[host]['osmatch']
                    os_fingerprint = "Unknown"  # Assign a default value here

                    if os_matches:
                        most_likely_os = os_matches[0]
                        os_family = most_likely_os['osclass'][0]['osfamily']
                        os_accuracy = most_likely_os['accuracy']

                        if int(os_accuracy) >= 70:
                            os_fingerprint = f"{os_family} (Accuracy: {os_accuracy}%)"
                        else:
                            os_fingerprint = "Unknown (Low accuracy)"

                    open_ports.append({
                        "port": port,
                        "protocol": proto,
                        "state": nm[host][proto][port]['state'],
                        "reason": nm[host][proto][port]['reason'],
                        "service": nm[host][proto][port]['name'],
                        "version": nm[host][proto][port].get('version', 'N/A'),
                        "product": nm[host][proto][port].get('product', 'N/A'),
                        "cpe": nm[host][proto][port].get('cpe', 'N/A'),
                        "script_results": nm[host][proto][port].get('script', {}),
                        "os": os_fingerprint,
                        "banner": banner
                    })
    web_vulnerabilities = []               
    if url:
        print(Fore.BLUE + Style.BRIGHT +f"Scanning URL: {url}" + Style.RESET_ALL)
        try:
            response = requests.get(url)
            soup = BeautifulSoup(response.content, 'html.parser')

            # Extract technologies used
            scripts = [script['src'] for script in soup.find_all('script', src=True)]
            for script in scripts:
                if 'jquery' in script.lower():
                    print(Fore.GREEN + Style.BRIGHT + "  Technology: jQuery detected" + Style.RESET_ALL)
                if 'angular' in script.lower():
                    print(Fore.GREEN + Style.BRIGHT + "  Technology: AngularJS detected" + Style.RESET_ALL)
                # ... add more checks for other technologies

            # Extract forms
            forms = soup.find_all('form')
            if forms:
                print(Fore.YELLOW + Style.BRIGHT + "  Forms:" + Style.RESET_ALL)
                for form in forms:
                    method = form.get('method', 'GET').upper()
                    action = form.get('action', 'N/A')
                    inputs = [input_.get('name', 'N/A') for input_ in form.find_all('input')]
                    print(Fore.YELLOW + Style.BRIGHT + f"    Method: {method}, Action: {action}, Inputs: {inputs}" + Style.RESET_ALL)

            # Extract links
            links = [link.get('href') for link in soup.find_all('a')]
            if links:
                print(Fore.YELLOW + Style.BRIGHT + "  Links: " + Style.RESET_ALL)
                for link in links:
                    print(Fore.YELLOW + Style.BRIGHT + f"    {link}" + Style.RESET_ALL)
            # ... (process the response to extract web application information - you'll need to add this)
            scan_for_sqli(url)
            scan_for_xss(url)
        except requests.exceptions.RequestException as e:
            print(Fore.RED + Style.BRIGHT + f"Error fetching URL: {e}" + Style.RESET_ALL)

    if nm.all_hosts():
        return {
            "target": target,
            "ip": nm[host]['addresses']['ipv4'],
            "open_ports": open_ports,
            "scanned_ports": port_range,
            "thorough": thorough,
            "os_details": nm[host].get('osmatch', []),
            "traceroute": nm[host].get('tcpts', {}),
            "script_results": script_results,  # Include script scan results
            "web_vulnerabilities": web_vulnerabilities
        }
    else:
        return {
            "target": target,
            "ip": None,
            "open_ports": [],
            "scanned_ports": port_range,
            "thorough": thorough,
            "os_details": [],  # Include an empty list for OS details
            "traceroute": {},  # Include an empty dictionary for traceroute information
            "script_results": {},  # Include an empty dictionary for script scan results
            "web_vulnerabilities": web_vulnerabilities,
            "error": "No hosts found"
        }

def run_scan(target, port_range="1-1000", thorough=False, scan_type='tcp', url=None):
    # ... (existing code)
    if target is None:  # Check if target is None
        print(Fore.RED + Style.BRIGHT + "Error: Could not resolve target. Please check the target and network connectivity." + Style.RESET_ALL)
        return
    vulnerability_count = 0
    high_severity_count = 0
    medium_severity_count = 0
    low_severity_count = 0

    print("\n" + Fore.BLUE + Style.BRIGHT + """
      ██████╗ ███████╗██╗     ███████╗██████╗ 
     ██╔════╝ ██╔════╝██║     ██╔════╝██╔══██╗
     ██║  ███╗█████╗  ██║     █████╗  ██████╔╝
     ██║   ██║██╔══╝  ██║     ██╔══╝  ██╔══██╗
     ╚██████╔╝███████╗███████╗███████╗██║  ██║
      ╚═════╝ ╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝
                                              """ + Style.RESET_ALL)

    print(Fore.YELLOW + Style.BRIGHT + "              Geler - Beta v1.0" + Style.RESET_ALL)
    print(Fore.YELLOW + Style.BRIGHT + "                Made by Triada" + Style.RESET_ALL)
    print("\n")
    print(Fore.BLUE + Style.BRIGHT + "Author     : Elishah" + Style.RESET_ALL)
    print(Fore.BLUE + Style.BRIGHT + "Tool       : Geler - AI-Assisted Penetration Testing Tool" + Style.RESET_ALL)
    print(Fore.BLUE + Style.BRIGHT + "Usage      : python3 geler.py  scan <target> <options: -p, -u > " + Style.RESET_ALL)
    print(Fore.BLUE + Style.BRIGHT + "Description: Geler automates penetration testing processes by integrating core" + Style.RESET_ALL)
    print(Fore.BLUE + Style.BRIGHT + "             scanning techniques and web vulnerability assessments using advanced"+ Style.RESET_ALL)
    print(Fore.BLUE + Style.BRIGHT + "             tools and custom scripts to enhance security analysis."+ Style.RESET_ALL)
    print(Fore.YELLOW + Style.BRIGHT + "\n---------------------------------------" + Style.RESET_ALL)
    print(Fore.YELLOW + Style.BRIGHT + "  SCAN PARAMETERS OVERVIEW" + Style.RESET_ALL)
    print(Fore.YELLOW + Style.BRIGHT + "---------------------------------------\n" + Style.RESET_ALL)
    print(Fore.BLUE + Style.BRIGHT + "[*] Target: " + Style.RESET_ALL + (target or "Unknown"))
    print(Fore.BLUE + Style.BRIGHT + "[*] IP Address: " + Style.RESET_ALL + socket.gethostbyname(target))
    print(Fore.BLUE + Style.BRIGHT + "[*] Scan Type: " + Style.RESET_ALL + scan_type.upper() + " Connect Scan")
    print(Fore.BLUE + Style.BRIGHT + "[*] Port Range: " + Style.RESET_ALL + port_range)
    print(Fore.BLUE + Style.BRIGHT + "[*] Thorough Scan: " + Style.RESET_ALL + ('Yes' if thorough else 'No'))
    print(Fore.BLUE + Style.BRIGHT + "[*] Date: " + Style.RESET_ALL + datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

    if url:

        print(Fore.BLUE + Style.BRIGHT + "[*] URL: " + Style.RESET_ALL + url)
    
    # Run the necessary scans if URL is provid 
        scan_for_waf(url)
        print()
        print(Fore.YELLOW + Style.BRIGHT + "--------------------------------------"+ Style.RESET_ALL)

        do_subdomain_enum = input(Fore.BLUE + Style.BRIGHT + "Perform subdomain enumeration? (y/n): "+ Style.RESET_ALL)
        if do_subdomain_enum.lower() == 'y':
            scan_for_uniscan(url)  # Run Sublist3r

        check_robots_txt(url)
        scan_for_xss(url)
        scan_for_sqli(url)
        

    else:
        print(Fore.YELLOW + Style.BRIGHT + "\n[*] Scanning...\n" + Style.RESET_ALL)

        vulnerability_count = 0
        high_severity_count = 0
        medium_severity_count = 0
        low_severity_count = 0

        print(Fore.BLUE + Style.BRIGHT + "\n------------------------------" + Style.RESET_ALL)
        print(Fore.BLUE + Style.BRIGHT + "    Discovered Open Ports" + Style.RESET_ALL)
        print(Fore.BLUE + Style.BRIGHT + "------------------------------\n" + Style.RESET_ALL)
        print("\n")
        print(Fore.BLUE + Style.BRIGHT + "PORT\tSTATE\tREASON\tSERVICE\tVERSION\tPRODUCT\tCPE" + Style.RESET_ALL)
        results = scan_target(target, port_range, thorough, scan_type, url)
        if results is None:
            print(Fore.RED + Style.BRIGHT + "Scan failed. Exiting." + Style.RESET_ALL)
            return  # Exit the main function

        if results['open_ports']:
            for port_info in results['open_ports']:
                print(Fore.BLUE + Style.BRIGHT + f"{port_info['port']}/{port_info['protocol']}\t{port_info['state']}\t{port_info['reason']}\t"
                    f"{port_info['service']}\t{port_info['version']}\t{port_info['product']}\t\t{port_info['cpe']}" + Style.RESET_ALL)

            # Print OS details
                print(Fore.BLUE + Style.BRIGHT + "\nOS Detection:" + Style.RESET_ALL)
                os_details = results['os_details']
                if os_details:
                    for osmatch in os_details:
                        print(Fore.BLUE + Style.BRIGHT + f"  Name: {osmatch['name']}" + Style.RESET_ALL)
                        print(Fore.BLUE + Style.BRIGHT + f"  Accuracy: {osmatch['accuracy']}" + Style.RESET_ALL)
                else:
                    print(Fore.RED + Style.BRIGHT + "  No OS detected." + Style.RESET_ALL)

            # Print traceroute information
                print(Fore.BLUE + Style.BRIGHT + "\nTraceroute:" + Style.RESET_ALL)
                traceroute = results['traceroute']
                if traceroute:
                    for hop, details in traceroute.items():
                        print(Fore.BLUE + Style.BRIGHT + f"Hop {hop}: {details['ip']} (latency: {details['rtt']}ms)" + Style.RESET_ALL)
                else:
                    print(Fore.RED + Style.BRIGHT + "  No traceroute information available." + Style.RESET_ALL)

            # Print script scan results
                print(Fore.BLUE + Style.BRIGHT + "\nScript Scan Results:" + Style.RESET_ALL)
                script_results = results['script_results']
                if script_results:
                    for script_id, result in script_results.items():
                        print(Fore.BLUE + Style.BRIGHT + f"  - {script_id}: {result}" + Style.RESET_ALL)
                else:
                    print(Fore.RED + Style.BRIGHT + "  No script results available." + Style.RESET_ALL)

                if 'banner' in port_info:
                    print(Fore.BLUE + f"  Banner: {port_info['banner']}" + Style.RESET_ALL)

        # Display vulnerability and exploit results
            results = scan_target(target, port_range, thorough, scan_type, url)
            print(Fore.MAGENTA + Style.BRIGHT + "  Potential Vulnerabilities:" + Style.RESET_ALL)
            print(Fore.YELLOW + Style.BRIGHT + "    (Vulnerability matching requires a vulnerability database)" + Style.RESET_ALL)

            print(Fore.MAGENTA + "  Exploits Found (based on service name):" + Style.RESET_ALL)
            service_name = port_info['service']
            vulnerability_database = VulnerabilityDatabase()
            exploits = vulnerability_database.fetch_exploit_from_exploitdb(service_name)
            if exploits:
                for exploit in exploits:
                    print(Fore.YELLOW + Style.BRIGHT + f"    - Title: {exploit['title']}" + Style.RESET_ALL)
                    print(Fore.YELLOW + Style.BRIGHT + f"      URL: {exploit['url']}" + Style.RESET_ALL)
            else:
                print(Fore.RED + Style.BRIGHT + "    No exploits found for this service." + Style.RESET_ALL)
                print("\n")  # This line should be inside the loop

        else:
            print(Fore.RED + Style.BRIGHT + "No open ports found." + Style.RESET_ALL)

    # Vulnerability summary
        print(Fore.BLUE + Style.BRIGHT +"------------------------------" + Style.RESET_ALL)
        print(Fore.BLUE + Style.BRIGHT +"  Vulnerability Summary" + Style.RESET_ALL)
        print(Fore.BLUE + Style.BRIGHT +"------------------------------\n" + Style.RESET_ALL)
        print(Fore.BLUE + Style.BRIGHT + f" [*] Total Vulnerabilities Found: {vulnerability_count}" + Style.RESET_ALL)
        print(Fore.BLUE + Style.BRIGHT + f" [*] High Severity: {high_severity_count}" + Style.RESET_ALL)
        print(Fore.BLUE + Style.BRIGHT + f" [*] Medium Severity: {medium_severity_count}" + Style.RESET_ALL)
        print(Fore.BLUE + Style.BRIGHT + f" [*] Low Severity: {low_severity_count}" + Style.RESET_ALL)
    
        return results

