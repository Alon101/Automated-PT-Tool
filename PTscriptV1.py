#!/usr/bin/env python3

"""
Project: Pen_Tester (ZX301) — Automated Penetration Testing Tool
Student: Alon Agronov
Student code: s16
Class code: TMagen773642
Lecturer: Natalie Erez
"""
import ipaddress
from pathlib import Path
import subprocess
import shutil 

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"

def check_tools(): 														# does the user have the tools installed
	needed = ["nmap", "hydra", "searchsploit"]
	missing = []
	for tool in needed:
		if shutil.which(tool) is None:  
			missing.append(tool)
	if missing:
		print(f"[!] Missing required tools: {', '.join(missing)}")
		print("[!] Install them and try again.")
		return False
	return True

LOGIN_SERVICES = {"ssh", "ftp", "rdp", "telnet"}

def get_target():
	while True:
		network = input("Please provide a network to scan: ")
		try:
			target = ipaddress.ip_network(network, strict=False) 		# using the ip network library to verify the IP range
			return target
		except ValueError:
			print("Invalid network. Accepted - 192.168.1.0, 192.168.1.0/24 NOT 192.168.1.0-255")

def get_output_dir():
	while True:
		name = input("how should the folder be called? ")
		if not name.strip():
			print("Name can't be empty.")
			continue
		if any(c in name for c in '/\\?*:"<>|'):    
			print("Name can't contain / \\ ? * : \" < > |")
			continue
		folder = Path(name)
		if folder.exists():
			print("That folder already exists. Pick another name.") 	# as to not delete anything that is already there
			continue
		try:
			folder.mkdir()
			return folder
		except OSError:
			print("there was an error")
			continue
			
def get_scan_mode():
	while True:
		scan_type = input("please choose BASIC/FULL ").strip().lower()
		if scan_type in ("basic", "full"):
			return scan_type		
		print("Please Choose between BASIC and FULL")
		
def basic_choise_TCP(target):
	print("[*] Running TCP + service scan...")
	command = ["nmap", "-Pn", "-sV", str(target)]
	result = subprocess.run(command, capture_output=True, text=True) 	# the subprocess library help run commands cleanly
	return result
	
def basic_choice_UDP(target):
    print("[*] Running UDP + service scan...")
    command = ["nmap", "-Pn", "-sU", "-sV", "--top-ports", "20", str(target)]
    result = subprocess.run(command, capture_output=True, text=True) 	# the subprocess library help run commands cleanly
    return result

	
def save_output(text, path): 											#helper function to save RAW output of tools.
	with open(path, "w") as f:
		f.write(text)
	print(f"[+] Saved: {path}")
	print(f"------------------------------")

def nmap_port_parse(output):
	ports = []
	for line in output.splitlines():
		if ("/tcp" in line or "/udp" in line) and "open" in line: 		# parses the open ports found
			fields = line.split()
			port = fields[0]
			service = fields[2]
			version = " ".join(fields[3:])
			record = {"port": port, "service": service, "version": version}
			ports.append(record)
	return ports

def find_login_services(ports):
	found = []
	for record in ports:
		if record["service"] in LOGIN_SERVICES:
			found.append(record)
	return found
	
def hydra_pass(target_ip, service_record, wordlist, username):
	serv_type = service_record["service"]
	port = service_record["port"].split("/")[0]
	print(f"[*] Hydra: {serv_type} on port {port}...")
	hydra_comm = ["hydra", "-l", username, "-P", str(wordlist), "-s", port, target_ip, serv_type]
	try:
		result = subprocess.run(hydra_comm, capture_output=True, text=True, timeout=120)
		return result
	except subprocess.TimeoutExpired:
		print(f"[!] Hydra timed out on {serv_type}:{port} — skipping.")
		print(f"-------------------------------------------------------")
		return None
	
def parse_hydra(output, service_record): 								# used to store the found credentials using hydra
	creds = [] 
	serv = service_record["service"]
	port = service_record["port"].split("/")[0]
	for line in output.splitlines():
		if "login:" in line and "password:" in line:
			fields = line.split()
			username = fields[fields.index("login:") +1]
			password = fields[fields.index("password:")+1]
			record = {"service": serv, "port": port,"login": username, "password": password}
			creds.append(record)
	return creds
	
def get_passlist():
	while True:
		choice = input("Use a [b]uilt in or [o]wn password file? ").strip().lower()
		if choice == "b":
			return Path(__file__).parent / "passlist.txt"
		if choice == "o":                            
			path = Path(input("Path to the file: ").strip())
			if path.is_file():
				return path
			print("File not found. Try again.")
		else:
			print("Please choose 'b' or 'o'.")
	
def nse_scan(target):
	print("[FULL] scan, Searching for vulnerabilites via NSE")
	print(f"------------------------------------------------------")
	command = ["nmap", "--script", "vuln", str(target)]
	result = subprocess.run(command, capture_output=True, text=True)
	return result
	
def searchsploit_scan(ports):
	print("[FULL] Searching Exploit-DB via Searchsploit...")
	print("------------------------------------------------------")
	results = []
	for record in ports:
		version = record["version"]
		if not version:
			continue
		command = ["searchsploit", version]
		result = subprocess.run(command, capture_output=True, text=True)
		results.append({"service": record["service"], "version": version, "output": result.stdout})
	return results
	
def zip_results(output_dir):
	import shutil
	shutil.make_archive(str(output_dir), "zip", output_dir)
	print(f"[+] All results zipped to {output_dir}.zip")
	
def show_results(tcp_ports, udp_ports, all_creds):
	print("\n===== SUMMARY =====")

	print(f"\nOpen TCP ports ({len(tcp_ports)}):")
	for p in tcp_ports:
		print(f"  {p['port']:10} {p['service']:15} {p['version']}")

	print(f"\nOpen UDP ports ({len(udp_ports)}):")
	for p in udp_ports:
		print(f"  {p['port']:10} {p['service']:15} {p['version']}")

	print(f"\nWeak credentials found ({len(all_creds)}):")
	for c in all_creds:
		print(f"  {RED}{c['service']} {c['port']}  {c['login']}:{c['password']}{RESET}")
		
def search_results(output_dir):
	while True:
		term = input("\nSearch results for (type nothing to finish): ").strip()
		if not term:
			return
		for file in output_dir.glob("*.txt"):
			for line in file.read_text().splitlines():
				if term.lower() in line.lower():
					print(f"{file.name}: {line}")
	
def main():
	
	if not check_tools():
		return
	target = get_target()
	output_dir = get_output_dir()
	print("This tool provides two types of scans, a BASIC scan, which scans the network for TCP and UDP, including the service version and weak passwords")
	print("and FULL, which includes all of the above, plus NSE, and Vulnerability analysis.")
	scan_type = get_scan_mode()
	print(f"Target: {target} | Output: {output_dir} | Mode: {scan_type}")
	#-------------------------------------------------------------------
	tcp_result = basic_choise_TCP(target)
	save_output(tcp_result.stdout, output_dir / "tcp_scan.txt")
	tcp_ports = nmap_port_parse(tcp_result.stdout)
	login_services = find_login_services(tcp_ports)
	#-------------------------------------------------------------------
	target_ip = str(target.network_address)
	wordlist = get_passlist()
	username = input("Username to try for login services: ").strip()
	all_creds = []
	#-------------------------------------------------------------------
	for service_record in login_services:
		hydra_result = hydra_pass(target_ip, service_record, wordlist, username)
		if hydra_result is None:
			continue
		
		serv = service_record["service"]
		port = service_record["port"].split("/")[0]
		save_output(hydra_result.stdout, output_dir / f"hydra_{serv}_{port}.txt")
		
		creds = parse_hydra(hydra_result.stdout, service_record)
		all_creds.extend(creds)
	#-------------------------------------------------------------------
	udp_result = basic_choice_UDP(target)
	save_output(udp_result.stdout, output_dir / "udp_scan.txt")
	udp_ports = nmap_port_parse(udp_result.stdout)
	#-------------------------------------------------------------------
	if scan_type == "full":
		nse_result = nse_scan(target)
		save_output(nse_result.stdout, output_dir / "nse_scan.txt")
		
		searchsploit_result = searchsploit_scan(tcp_ports)
		ss_text = ""
		for item in searchsploit_result:
			ss_text += f"\n=== {item['service']} ({item['version']}) ===\n"
			ss_text += item["output"]
		save_output(ss_text, output_dir / "searchsploit.txt")
	#-------------------------------------------------------------------
	show_results(tcp_ports, udp_ports, all_creds)
	zip_results(output_dir)
	search_results(output_dir)
	
if __name__ == "__main__":
	main()
