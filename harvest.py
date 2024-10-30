#!/usr/bin/env python3

from pyfiglet import Figlet
import argparse
import whois
import nmap
import requests
from ping3 import ping


def gen_title():
	f = Figlet(font="slant")
	print(f.renderText("harvest.py"))
	print("[*] An identification and enumeration script")
	print("[*] By Hugo Barea")
	print("[*] github.com/hugobarea/harvest")


def handle_arguments():
	parser = argparse.ArgumentParser()
	parser.add_argument("-target", type=str, required=True, help="The target to enumerate")
	args = parser.parse_args()

	return args.target


def scan_whois(target):
	r_whois = whois.whois(target)
	print("\n-> Scanning WHOIS for target:", target)
	print("-------------------------------------------")
	print(r_whois)

	emails = r_whois.emails
	
	print("\n-> Checking e-mails found for breaches:")
	print("----------------------------------------------")
		
	for email in emails:
		check_leaks(email)


def check_leaks(email):
	url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
	response = requests.get(url)


	if response.status_code == 200:
		breaches = response.json()
		print(f"{email} has been leaked in: ")
		for breach in breaches:
			print(f"- {breach["Name"]}, {breach["BreachDate"]}")
	elif response.status_code == 404:
		print(f"{email} has apparently not been leaked")
	else:
		print("ERROR checking HaveIBeenPwned API:", response.status_code)

def is_live(target):
	try:
		r = ping(target, timeout=2)
		if r is not none:
			return True
		else:
			return False
	except Exception:
		print("Error pinging", target)
		return False

def nmap_scan(target):
	if(is_live(target)):
		print("\n-> Target responds to pings")
	else:
		print("\n-> Target does not appear to respond to pings")
	scanner = nmap.PortScanner()
	options = "--top-ports 10"
	print("\n-> Launching Nmap scan")
	print("------------------------------------")
	scanner.scan(target, arguments=options)

	for host in scanner.all_hosts():
		print("State: ", scanner[host].state())
		for protocol in scanner[host].all_protocols():
			ports = scanner[host][protocol].keys()
			for port in ports:
				print("Port: ", port, "State: ", scanner[host][protocol][port]['state'])

if __name__ == "__main__":
	gen_title()
	target = handle_arguments()
	scan_whois(target)
	nmap_scan(target)