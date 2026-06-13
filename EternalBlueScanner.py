#!/usr/bin/python3
# -*- coding: utf-8 -*-
import time
import random
import os
import socket
import sys
import requests
import multiprocessing as mp
from termcolor import colored
from colorama import init, Fore, Style
import nmap
init(autoreset=True)
# ========================= GLOBAL =========================
logo = '''
'########'########'########'########:'##::: ##:::'###:::'##::::::'########:'##::::::'##::::'##'########:
 ##.....:... ##..::##.....::##.... ##:###:: ##::'## ##:::##:::::::##.... ##:##:::::::##:::: ##:##.....::
 ##::::::::: ##::::##:::::::##:::: ##:####: ##:'##:. ##::##:::::::##:::: ##:##:::::::##:::: ##:##:::::::
 ######::::: ##::::######:::########::## ## ##'##:::. ##:##:::::::########::##:::::::##:::: ##:######:::
 ##...:::::: ##::::##...::::##.. ##:::##. ####:#########:##:::::::##.... ##:##:::::::##:::: ##:##...::::
 ##::::::::: ##::::##:::::::##::. ##::##:. ###:##.... ##:##:::::::##:::: ##:##:::::::##:::: ##:##:::::::
 ########::: ##::::########:##:::. ##:##::. ##:##:::: ##:########:########::########. #######::########:
:::::::::::::::::::'######::'######::::'###:::'##::::##'##:::.##'########'########::::::::::::::::::::::
::::::::::::::::::'##... ##'##... ##::'## ##:::###:: ##:###:: ##:##.....::##.... ##:::::::::::::::::::::
:::::::::::::::::::##:::..::##:::..::'##:. ##::####: ##:####: ##:##:::::::##:::: ##:::::::::::::::::::::
::::::::::::::::::. ######::##::::::'##:::. ##:## ## ##:## ## ##:######:::########::::::::::::::::::::::
:::::::::::::::::::..... ##:##:::::::#########:##. ####:##. ####:##...::::##.. ##:::::::::::::::::::::::
::::::::::::::::::'##::: ##:##::: ##:##.... ##:##:. ###:##:. ###:##:::::::##::. ##::::::::::::::::::::::
::::::::::::::::::. ######:. ######::##:::: ##:##::. ##:##::. ##:########:##:::. ##:::::::::::::::::::::
:::::::::::::::::::......:::......::..:::::..:..::::..:..::::..:........:..:::::..::::::::::::::::::::::
Coded By SourceCode347
'''
EternalBlue_Vulnerabilities = "EternalBlue_Vulnerabilities.txt"
def filecreator(file_name):
    if not os.path.exists(file_name):
        with open(file_name, "w", encoding="utf-8") as f:
            f.write("")
filecreator(EternalBlue_Vulnerabilities)
r_args=['-d','--disable','-p','--processes','-h','--help']
printChecking=True
processes=mp.cpu_count()
for arg in range(0,len(sys.argv)):
    if sys.argv[arg-1]=="-d" or sys.argv[arg-1]=="--disable":
        printChecking=False
    if sys.argv[arg-1]=="-p" or sys.argv[arg-1]=="--processes":
        processes=int(sys.argv[arg])
    if sys.argv[arg-1]=="-h" or sys.argv[arg-1]=="--help":
        print(colored(logo, "green"))
        help = '''
        +------------------+------------------------------------------+-------------+
        | Argument         | Info                                     | Default     |
        +------------------+------------------------------------------+-------------+
        | -h , --help      | Printing Help Of Arguments               | NULL        |
        +------------------+------------------------------------------+-------------+
        | -d , --disable   | Disable Printing Of Checking A Random IP | True        |
        +------------------+------------------------------------------+-------------+
        | -p , --processes | Integer Of Processes (eg. -p 64)         | CPU Threads |
        +------------------+------------------------------------------+-------------+

        +------------------+--------------------------------------------------------+
        | Example Command  | python EternalBlueScanner.py -d -p 64                  |
        +---------------------------------------------------------------------------+
        '''
        print(Fore.GREEN +f"{help}")
        sys.exit()
# ====================== FUNCTIONS ======================
def get_random_ip():
    while True:
        start=random.randint(0,255)
        if start!=127:
            return f"{start}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
def check_eternalblue(ip: str) -> dict:
    result = {
        "ip": ip,
        "port_open": False,
        "vulnerable": False,
        "status": "Unknown",
        "details": ""
    }
    try:
        socket.inet_aton(ip)
        nm = nmap.PortScanner()
        print(Fore.CYAN + f"[*] Scanning {ip} for EternalBlue (MS17-010)...")
        nm.scan(ip, '445', arguments='-Pn --script smb-vuln-ms17-010 -T4')
        if ip not in nm.all_hosts():
            result["status"] = "Host not reachable"
            return result
        host = nm[ip]
        if '445' in host['tcp'] and host['tcp'][445]['state'] == 'open':
            result["port_open"] = True
        else:
            result["status"] = "Port 445 closed or filtered"
            return result
        if 'script' in host and 'smb-vuln-ms17-010' in host['script']:
            script_output = host['script']['smb-vuln-ms17-010']
            result["details"] = script_output
            if "VULNERABLE" in script_output or "State: VULNERABLE" in script_output:
                result["vulnerable"] = True
                result["status"] = "VULNERABLE to EternalBlue (MS17-010)"
            elif "NOT VULNERABLE" in script_output or "State: NOT VULNERABLE" in script_output:
                result["vulnerable"] = False
                result["status"] = "NOT vulnerable"
            else:
                result["status"] = "Unknown (check details)"
        else:
            result["status"] = "Script did not return results"
        return result
    except nmap.PortScannerError as e:
        result["status"] = f"Nmap error: {e}"
        return result
    except Exception as e:
        result["status"] = f"Error: {e}"
        return result
def check_sambacry(ip: str) -> dict:
    result = {
        "ip": ip,
        "port_open": False,
        "vulnerable": False,
        "status": "Unknown",
        "details": ""
    }
    try:
        socket.inet_aton(ip)
        nm = nmap.PortScanner()
        print(Fore.CYAN + f"[*] Scanning {ip} for SambaCry (CVE-2017-7494)...")
        nm.scan(ip, '445', arguments='-Pn --script smb-vuln-cve-2017-7494 -T4')
        if ip not in nm.all_hosts():
            result["status"] = "Host not reachable"
            return result
        host = nm[ip]
        if '445' in host['tcp'] and host['tcp'][445]['state'] == 'open':
            result["port_open"] = True
        else:
            result["status"] = "Port 445 closed or filtered"
            return result
        if 'script' in host and 'smb-vuln-cve-2017-7494' in host['script']:
            script_output = host['script']['smb-vuln-cve-2017-7494']
            result["details"] = script_output
            if "VULNERABLE" in script_output or "State: VULNERABLE" in script_output:
                result["vulnerable"] = True
                result["status"] = "VULNERABLE to SambaCry (CVE-2017-7494)"
            elif "NOT VULNERABLE" in script_output or "State: NOT VULNERABLE" in script_output:
                result["vulnerable"] = False
                result["status"] = "NOT vulnerable"
            else:
                result["status"] = "Unknown (check details)"
        else:
            result["status"] = "Script did not return results"
        return result
    except nmap.PortScannerError as e:
        result["status"] = f"Nmap error: {e}"
        return result
    except Exception as e:
        result["status"] = f"Error: {e}"
        return result
def check_doublepulsar(ip: str) -> dict:
    result = {
        "ip": ip,
        "port_open": False,
        "vulnerable": False,
        "status": "Unknown",
        "details": ""
    }
    try:
        socket.inet_aton(ip)
        nm = nmap.PortScanner()
        print(Fore.CYAN + f"[*] Scanning {ip} for DoublePulsar...")
        nm.scan(ip, '445', arguments='-Pn --script smb-double-pulsar-backdoor -T4')
        if ip not in nm.all_hosts():
            result["status"] = "Host not reachable"
            return result
        host = nm[ip]
        if '445' in host['tcp'] and host['tcp'][445]['state'] == 'open':
            result["port_open"] = True
        else:
            result["status"] = "Port 445 closed or filtered"
            return result
        if 'script' in host and 'smb-double-pulsar-backdoor' in host['script']:
            script_output = host['script']['smb-double-pulsar-backdoor']
            result["details"] = script_output
            if "VULNERABLE" in script_output or "State: VULNERABLE" in script_output:
                result["vulnerable"] = True
                result["status"] = "VULNERABLE to DoublePulsar"
            elif "NOT VULNERABLE" in script_output or "State: NOT VULNERABLE" in script_output:
                result["vulnerable"] = False
                result["status"] = "NOT vulnerable"
            else:
                result["status"] = "Unknown (check details)"
        else:
            result["status"] = "Script did not return results"
        return result
    except nmap.PortScannerError as e:
        result["status"] = f"Nmap error: {e}"
        return result
    except Exception as e:
        result["status"] = f"Error: {e}"
        return result
def check_webexec(ip: str) -> dict:
    result = {
        "ip": ip,
        "port_open": False,
        "vulnerable": False,
        "status": "Unknown",
        "details": ""
    }
    try:
        socket.inet_aton(ip)
        nm = nmap.PortScanner()
        print(Fore.CYAN + f"[*] Scanning {ip} for WebExec...")
        nm.scan(ip, '445', arguments='-Pn --script smb-vuln-webexec -T4')
        if ip not in nm.all_hosts():
            result["status"] = "Host not reachable"
            return result
        host = nm[ip]
        if '445' in host['tcp'] and host['tcp'][445]['state'] == 'open':
            result["port_open"] = True
        else:
            result["status"] = "Port 445 closed or filtered"
            return result
        if 'script' in host and 'smb-vuln-webexec' in host['script']:
            script_output = host['script']['smb-vuln-webexec']
            result["details"] = script_output
            if "VULNERABLE" in script_output or "State: VULNERABLE" in script_output:
                result["vulnerable"] = True
                result["status"] = "VULNERABLE to WebExec"
            elif "NOT VULNERABLE" in script_output or "State: NOT VULNERABLE" in script_output:
                result["vulnerable"] = False
                result["status"] = "NOT vulnerable"
            else:
                result["status"] = "Unknown (check details)"
        else:
            result["status"] = "Script did not return results"
        return result
    except nmap.PortScannerError as e:
        result["status"] = f"Nmap error: {e}"
        return result
    except Exception as e:
        result["status"] = f"Error: {e}"
        return result
class PortSpider:
    def __init__(self, start_url, max_depth=1, delay=0.3):
        self.start_url = start_url
        self.max_depth = max_depth
        self.delay = delay
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; PortResearchBot/2.0;)"
        })
    def crawl(self, ip):
        try:
            if printChecking==True:
                print(Fore.CYAN + f"[+] Checking: {ip}")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((ip, 445))
            
            if result == 0:
                print(Fore.YELLOW + f"[+] Port 445 OPEN on {ip}")
                res = check_eternalblue(ip)
                if res["vulnerable"]==True:
                    print(Fore.GREEN + f"✅ Target IP : {ip} is Vulnerable to EternalBlue Exploit (!)")
                    self.saveurl(ip+" : EternalBlue")
                else:
                    print(Fore.RED + f"[-] Target IP : {ip} is Not Vulnerable to EternalBlue Exploit (!)")
                res = check_sambacry(ip)
                if res["vulnerable"]==True:
                    print(Fore.GREEN + f"✅ Target IP : {ip} is Vulnerable to SambaCry Exploit (!)")
                    self.saveurl(ip+" : SambaCry")
                else:
                    print(Fore.RED + f"[-] Target IP : {ip} is Not Vulnerable to SambaCry Exploit (!)")
                res = check_doublepulsar(ip)
                if res["vulnerable"]==True:
                    print(Fore.GREEN + f"✅ Target IP : {ip} is Vulnerable to DoublePulsar Exploit (!)")
                    self.saveurl(ip+" : DoublePulsar")
                else:
                    print(Fore.RED + f"[-] Target IP : {ip} is Not Vulnerable to DoublePulsar Exploit (!)")
                res = check_webexec(ip)
                if res["vulnerable"]==True:
                    print(Fore.GREEN + f"✅ Target IP : {ip} is Vulnerable to WebExec Exploit (!)")
                    self.saveurl(ip+" : WebExec")
                else:
                    print(Fore.RED + f"[-] Target IP : {ip} is Not Vulnerable to WebExec Exploit (!)")
            sock.close()           
        except Exception as e:
            pass
        finally:
            time.sleep(self.delay)
    def saveurl(self, ip):
        try:
            with open(EternalBlue_Vulnerabilities, "r", encoding="utf-8") as f:
                if ip in f.read():
                    return
            with open(EternalBlue_Vulnerabilities, "a", encoding="utf-8") as f:
                f.write(ip + "\n")
        except:
            pass
# ====================== WORKER ======================
def worker(worker_id):
    #print(Fore.GREEN + f"[Process {worker_id}] Started")
    spider = PortSpider(None, max_depth=1, delay=0.3)   
    while True:
        target = get_random_ip()
        spider.crawl(target)
# ====================== MAIN ======================
if __name__ == "__main__":
    print(colored(logo, "green"))
    time.sleep(5)    
    num_processes = processes
    print(Fore.GREEN + f"🚀 Starting {num_processes} Processes")
    print(Fore.YELLOW + "[+] Press Ctrl+C to stop...\n")
    time.sleep(2)
    processes = []
    for i in range(num_processes):
        p = mp.Process(
            target=worker, 
            args=(i+1,),
            name=f"PortSpider-{i+1}",
            daemon=True
        )
        p.start()
        processes.append(p)
        time.sleep(0.1)
    print(Fore.GREEN + f"✅ All {num_processes} processes are running!")
    try:
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        print(Fore.RED + "\n\nStopping all processes...")