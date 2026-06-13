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
# ====================== FUNCTIONS ======================
def get_random_ip():
    return f"{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
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
        # -p 445 --script smb-vuln-ms17-010 -Pn
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
            print(Fore.CYAN + f"[+] Checking: {ip}")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((ip, 445))
            
            if result == 0:
                print(Fore.GREEN + f"✅ Port 445 OPEN on {ip}")
                res = check_eternalblue(ip)
                if res["vulnerable"]==True:
                    print(Fore.GREEN + f"✅ Target IP : {ip} is Vulnerable to EternalBlue Exploit (!)")
                    self.saveurl(ip)
                else:
                    print(Fore.RED + f"[-] Target IP : {ip} is Not Vulnerable to EternalBlue Exploit (!)")
            sock.close()
            
        except Exception as e:
            # Σιωπηλά τα περισσότερα errors για ταχύτητα
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
    print(Fore.GREEN + f"[Process {worker_id}] Started")
    spider = PortSpider(None, max_depth=1, delay=0.3)   
    while True:
        target = get_random_ip()
        spider.crawl(target)
# ====================== MAIN ======================
if __name__ == "__main__":
    print(colored(logo, "green"))    
    num_processes = mp.cpu_count()
    print(Fore.GREEN + f"🚀 Starting {num_processes} Processes (full CPU usage)")
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
    print(Fore.YELLOW + "Press Ctrl+C to stop...\n")
    try:
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        print(Fore.RED + "\n\nStopping all processes...")