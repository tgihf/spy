#!/usr/bin/python

# Title: spy.py -- a remote recon and enumeration script
# Author: Hunter Friday (tgihf)
# Based On: reconscan.py by Mike Czumak (T_v3rn1x) -- @SecuritySift
# Details: This script is intended to be executed remotely against a list of IPs to discovered services such as http, https, smb, ftp, snmp, smtp, and more.
# Warning: This script should only be used against systems with which you have permission to enumerate.

import argparse
import multiprocessing
import nmap
import os
import socket
import subprocess
import sys
from termcolor import colored

# Spy - driver function
def spy(target_ip, recon_dir):

    # Perform quick scan to find open TCP ports
    # Returns a list of open TCP ports
    open_tcp_ports = nmap_port_finder(target_ip, "tcp", recon_dir)

    # Perform deep scan on open TCP ports to discover versions
    tcp_scan_obj = nmap_port_enumerator(target_ip, open_tcp_ports, "tcp", recon_dir)

    # Perform quick scan of the top 1000 UDP ports to find the open ones
    # Returns a list of open UDP ports
    open_udp_ports = nmap_port_finder(target_ip, "udp", recon_dir)

    # Perform deep scan on open UDP ports to discover versions
    udp_scan_obj = nmap_port_enumerator(target_ip, open_udp_ports, "udp", recon_dir)

    # Initiate deeper enumeration of open TCP and UDP ports
    service_dispatcher(target_ip, tcp_scan_obj, udp_scan_obj)

# unicornscan Open Port Finder
def unicornscan_port_finder(target_ip, proto, recon_dir):

    # Banner
    print str(colored('[*]', 'blue')) + " Initiating Open Port Scan using unicornscan on %s:%s" % (target_ip, port)

    # Establish unicornscan options - TCP or UDP scan
    if proto == 'tcp':
        flag = '-mT'
    else: # proto == 'udp'
        flag = '-mU'

    # Initate unicornscan
    unicornscan_cmd = "unicornscan %s %s:a" % (flag, target_ip)
    unicornscan_output = subprocess.check_output(unicornscan_cmd, shell=True)

    # Parse unicornscan output and return a list of open ports TODO
    open_ports = []
    return open_ports

# Nmap Open Port Finder
def nmap_port_finder(target_ip, proto, recon_dir):

    # Banner
    print str(colored('[*]', 'blue')) + " Initiating Nmap Open %s Port Finder on %s" % (proto.upper(), target_ip)

    # Establish Nmap options - TCP scan or UDP scan
    nm_obj = nmap.PortScanner()
    if proto == "tcp":
        nmap_args = "-Pn -sS -p1-65535 -T4 --max-retries 1 --max-scan-delay 20 --defeat-rst-ratelimit"
    else: # proto == "udp"
        #nmap_args = "-Pn -sU --top-ports=1000 -T4 --max-retries 1"

    # Initiate quick Nmap scan
    nm_obj.scan(hosts=target_ip, arguments=nmap_args)

    # Extract open ports
    lports = nm_obj[target_ip][proto].keys()
    lports.sort()
    open_ports = []
    for port in lports:
        if nm_obj[target_ip][proto][port]['state'] == "open":
            open_ports.append(port)

    # Return the list of open ports
    return open_ports

# Nmap Open Port Enumerator
def nmap_port_enumerator(target_ip, open_ports, proto, recon_dir):

    # Format open TCP ports in to comma separated list
    open_ports_str = ""
    for open_port in open_ports:
        open_ports_str += str(open_port) + ','
    open_ports_str = open_ports_str[:-1]

    # Print open TCP ports
    print str(colored('[*]', 'blue')) + " Performing Service Enumeration on %s's Open %s Ports: %s" % (target_ip, proto.upper(), open_ports_str)

    # Create output directory
    nmap_dir = "%s/nmap" % recon_dir
    mkdir(nmap_dir)

    # Output file names
    nmap_norm = "%s/%s-%s.nmap" % (nmap_dir, target_ip, proto)
    nmap_grepable = "%s/%s-%s.grep" % (nmap_dir, target_ip, proto)
    nmap_xml = "%s/%s-%s.xml" % (nmap_dir, target_ip, proto)

    # Establish Nmap options
    nm_obj = nmap.PortScanner()
    nmap_args = "-nvv -sV -T1 -p%s -oN %s -oG %s --version-intensity 9" % (open_ports_str, nmap_norm, nmap_grepable)

    # Initiate Nmap scan
    nm_obj.scan(hosts=target_ip, arguments=nmap_args)

    # Write XML output
    with open(nmap_xml, 'w') as f:
        f.write(nm_obj.get_nmap_last_output())

    # Notify of completion
    print str(colored('[*]', 'blue')) + " %s Service Enumeration Completed on %s -> %s" % (proto.upper(), target_ip, nmap_dir)

    # Return Nmap scan object
    return nm_obj

# Service Dispatcher
def service_dispatcher(target_ip, tcp_scan_obj, udp_scan_obj):

    # Consolidate open TCP ports
    tcp_ports = tcp_scan_obj[target_ip]['tcp'].keys()

    # Iterate through open ports and dispatch further enumeration
    for port in tcp_ports:

        # If HTTP is running on the port, enumerate further
        if tcp_scan_obj[target_ip]['tcp'][port]['name'] == "http":
            mult_proc(http_enum, target_ip, "http", port, recon_dir)

        # If HTTPS is running on the port, enumerate further
        elif tcp_scan_obj[target_ip]['tcp'][port]['name'] == "https":
            mult_proc(https_enum, target_ip, "https", port, recon_dir)

        # If SMB is running on the port, enumerate further
        elif tcp_scan_obj[target_ip]['tcp'][port]['name'] == "microsoft-ds" or tcp_scan_obj[target_ip]['tcp'][port]['name'] == "netbios-ssn":
            mult_proc(smb_enum, target_ip, "smb", port, recon_dir)

        # If FTP is running on the port, enumerate further
        elif tcp_scan_obj[target_ip]['tcp'][port]['name'] == "ftp":
            mult_proc(ftp_enum, target_ip, "ftp", port, recon_dir)

        # If SMTP is running on the port, enumerate further
        elif tcp_scan_obj[target_ip]['tcp'][port]['name'] == "smtp":
            mult_proc(smtp_enum, target_ip, "smtp", port, recon_dir)

        # If SSH is running on the port, initate brute force
        elif tcp_scan_obj[target_ip]['tcp'][port]['name'] == "ssh":
            mult_proc(ssh_brute, target_ip, "ssh", port, recon_dir)

        # If DNS is running on the port, enumerate further
        elif tcp_scan_obj[target_ip]['tcp'][port]['name'] == "dns":
            mult_proc(dns_enum, target_ip, "dns", port, recon_dir)

        # Else try the next port
        else:
            pass

    # Consolidate open UDP ports
    udp_ports = udp_scan_obj[target_ip]['tcp'].keys() # Weird that key is 'tcp' but it is what it is

    # For each open UDP port
    for port in udp_ports:

        # If SNMP is running on the port, enumerate further
        if udp_scan_obj[target_ip]['tcp'][port]['name'] == "snmp":
            mult_proc(snmp_enum, target_ip, "snmp", port, recon_dir)

        # Else try the next port
        else:
            pass

# HTTP Enumerator
def http_enum(target_ip, proto, port, recon_dir):

     # Create HTTP output directory
     http_dir = "%s/http" % recon_dir
     mkdir(http_dir)

     # Initiate dirb enumeration
     mult_proc(dirb_enum, target_ip, "http", port, http_dir)

     # Initiate Nikto enumeration
     mult_proc(nikto_enum, target_ip, "http", port, http_dir)

     # Initiate HTTP Nmap vulnerability scan
     mult_proc(nmap_http_https_enum, target_ip, "http", port, http_dir)

# HTTPS Enumerator
def https_enum(target_ip, proto, port, output_dir):

     # Create HTTPS output directory
     https_dir = "%s/https" % output_dir
     mkdir(https_dir)

     # Initiate dirb enumeration
     mult_proc(dirb_enum, target_ip, "https", port, https_dir)

     # Initiate Nikto enumeration
     mult_proc(nikto_enum, target_ip, "https", port, https_dir)

     # Initiate HTTP Nmap vulnerability scan
     mult_proc(nmap_http_https_enum, target_ip, "https", port, https_dir)

# dirb Enumerator
def dirb_enum(target_ip, proto, port, output_dir):

    # Set variables
    url = proto + "://" + target_ip + ":" + str(port)
    print str(colored('[dirb]', 'green')) + "\t dirb Enumeration Initiated on %s" % url

    # Quick scan (common.txt)
    dict_path = "/usr/share/wordlists/dirb/common.txt"
    quick_output_file = "%s/%s-dirb-common.txt" % (output_dir, port)
    quick_dirb_cmd = "dirb %s %s -f > %s" % (url, dict_path, quick_output_file)
    subprocess.call(quick_dirb_cmd, shell=True)

    # Deep scan (big.txt)
    dict_path = "/usr/share/wordlists/dirb/big.txt"
    deep_output_file = "%s/%s-dirb-big.txt" % (output_dir, port)
    deep_dirb_cmd = "dirb %s %s -f > %s" % (url, dict_path, deep_output_file)
    subprocess.call(deep_dirb_cmd, shell=True)

    # Print finished banner
    print str(colored('[/dirb]', 'green')) + "\t dirb Enumeration Completed on %s -> %s" % (url, deep_output_file)

# Nikto Enumerator
def nikto_enum(target_ip, proto, port, output_dir):

    # Banner
    url = proto + "://" + target_ip
    print str(colored('[nikto]', 'green')) + "\t Nikto Enumeration Initiated on %s:%s" % (url, port)

    # Initiate scan
    output_file = "%s/%s-nikto.txt" % (output_dir, port)
    nikto_cmd = "nikto -f -p %s -h %s > %s" % (port, url, output_file)
    subprocess.call(nikto_cmd, shell=True)

    # Print finished banner
    print str(colored('[/nikto]', 'green')) + " Nikto Enumeration Completed on %s:%s -> %s" % (url, port, output_file)

# Nmap HTTP/HTTPS Enumerator
def nmap_http_https_enum(target_ip, proto, port, output_dir):

    # Banner
    tag = "[%s]" % proto
    print str(colored(tag, 'green')) + "\t Nmap %s Enumeration Initiated on %s:%s" % (proto.upper(), target_ip, port)

    # Establish Nmap options
    output_file = "%s/%s.nmap" % (output_dir, port)
    nm_obj = nmap.PortScanner()
    nmap_args = "-T3 -p%s --script=http* -oN %s" % (port, output_file)

    # Initiate Nmap HTTP/HTTPS scan
    nm_obj.scan(hosts=target_ip, arguments=nmap_args)

    # Print finished banner
    fin_tag = "[/%s]" % proto
    print str(colored(fin_tag, 'green')) + "\t Nmap %s Enumeration Completed on %s:%s -> %s" % (proto.upper(), target_ip, port, output_file)

# SMB Enumerator
def smb_enum(target_ip, proto, port, output_dir):

    # Banner
    print str(colored('[smb]', 'green')) + "\t Initiating SMB Enumeration on %s:%s" % (target_ip, port)

    # Create SMB output directory
    smb_dir = "%s/smb" % output_dir
    mkdir(smb_dir)

    # Initiate enum4linux SMB enumeration
    output_file = "%s/enum4linux_out.txt" % smb_dir
    enum4linux_cmd = "enum4linux -a %s > %s" % (target_ip, output_file)
    subprocess.call(enum4enum4linux_cmd, shell=True)

    # Initiate Nmap SMB enumeration
    output_file = "%s/smb.nmap" % smb_dir
    nmap_smb_cmd = "nmap -T3 -p%s --script=smb-vuln* -oN %s %s" % (port, output_file, target_ip)
    subprocess.call(nmap_smb_cmd, shell=True)

    # Print finished banner
    print str(colored('[/smb]', 'green')) + "\t Nmap SMB Enumeration Completed on %s:%s -> %s" % (target_ip, port, smb_dir)

# FTP Enumerator
def ftp_enum(target_ip, proto, port, output_dir):

    # Banner
    print str(colored('[ftp]', 'green')) + "\t Initiating FTP Enumeration on %s:%s" % (target_ip, port)

    # Create FTP output directory
    ftp_dir = "%s/ftp" % output_dir
    mkdir(ftp_dir)

    # Initiate Nmap FTP enumeration
    output_file = "%s/ftp.nmap" % ftp_dir
    nmap_ftp_cmd = "nmap -p%s --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 -oN %s %s" % (port, output_file, target_ip)
    subprocess.call(nmap_ftp_cmd, shell=True)

    # Print finished banner
    print str(colored('[/ftp]', 'green')) + "\t Nmap FTP Enumeration Completed on %s:%s -> %s" % (target_ip, port, output_file)

# DNS Enumerator
def dns_enum(target_ip, proto, port, output_dir):

    # Banner
    print str(colored('[dns]', 'green')) + "\t Attempting DNS Zone Transfer on %s:%s" % (target_ip, port)

    # Create DNS output directory
    dns_dir = "%s/dns" % output_dir
    mkdir(dns_dir)

    # Attempt zone transfer against target using dig
    output_file = "%s/dig.txt" % dns_dir
    dig_zt_cmd = "dig %s axfr > %s" % (target_ip, output_file)
    subprocess.call(dig_zt_cmd, shell=True)

    # Notify of completion
    print str(colored('[/dns]', 'green')) + "\t DNS Zone Transfer Attempted on %s:%s -> %s" % (target_ip, port, output_file)

# SMTP Enumerator
def smtp_enum(target_ip, proto, port, output_dir):

    # Banner
    print str(colored('[smtp]', 'green')) + "\t Initiating SMTP User Enumeration on %s:%s" % (target_ip, port)

    # Create SMTP output directory
    smtp_dir = "%s/smtp" % output_dir
    mkdir(smtp_dir)

    # SMTP enumeration output file
    output_file = "%s/smtp_users.txt" % smtp_dir

    # Perform SMTP enumeration
    # Establish connection to SMTP server
    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connect = s.connect((target_ip, port))
    banner = s.recv(1024)
    s.send('HELO test@test.org \r\n')
    result= s.recv(1024)

    # Initiate SMTP user enumeration
    names = open('/usr/share/wordlists/metasploit/unix_users.txt', 'r')
    f = open(output_file, 'w')
    for name in names:
    	s.send('VRFY ' + name.strip() + '\r\n')
    	result = s.recv(1024)
    	if ("not implemented" in result) or ("disallowed" in result):
           		sys.exit(str(colored('[!]', 'red')) + " VRFY Command not implemented on " + target_ip)
    	if (("250" in result) or ("252" in result) and ("Cannot VRFY" not in result)):
    		msg = "[*] SMTP VRFY Account found on " + target_ip + ": " + name.strip()
    		f.write(msg + '\n')
    		f.write('  --->  ' + result)
    		f.write('\n')

    # Notify of completion
    print str(colored('[/smtp]', 'green')) + "\t SMTP User Enumeration Completed on %s:%s -> %s" % (target_ip, port, output_file)

# SSH Brute Forcer
def ssh_brute(target_ip, proto, port, output_dir):

    # Banner
    print str(colored('[ssh]', 'green')) + "\t Initiating SSH Brute Force on %s:%s" % (target_ip, port)

    # Create SSH output directory
    ssh_dir = "%s/ssh" % output_dir
    mkdir(ssh_dir)

    # Initiate Hydra SSH brute force
    output_file = "%s/ssh.hydra" % ssh_dir
    username_file = "/usr/share/wordlists/metasploit/unix_users.txt"
    passwd_file = "/usr/share/wordlists/rockyou.txt"
    hydra_cmd = "hydra -e nsr -f -L %s -P %s %s -s %s -t 2 ssh > %s" % (username_file, passwd_file, target_ip, port, output_file)
    subprocess.call(hydra_cmd, shell=True)

    # Notify of completion
    print str(colored('[/ssh]', 'green')) + "\t SSH Brute Force Completed on %s:%s" % (target_ip, port)

# SNMP Enumerator
def snmp_enum(target_ip, proto, port, output_dir):

    # Banner
    print str(colored('[snmp]', 'green')) + "\t Initiating SNMP Enumeration on %s:%s" % (target_ip, port)

    # Create SNMP output directory
    snmp_dir = "%s/snmp" % output_dir
    mkdir(snmp_dir)

    # Initiate SNMP enumeration with snmp-check
    snmp_check_output_file = "%s/snmp-check.txt" % snmp_dir
    snmp_check_cmd = "snmp-check %s > %s" % (target_ip, snmp_check_output_file)
    subprocess.call(snmp_check_cmd, shell=True)

    # Initiate SNMP enumeration with snmp-walk
    snmp_walk_output_file = "%s/snmp-walk.txt" % snmp_dir
    snmp_walk_cmd = "snmpwalk -c public -v1 %s 1 > %s" % (target_ip, snmp_walk_output_file)
    subprocess.call(snmp_walk_cmd, shell=True)

    # Notify of completion
    print str(colored('[/snmp]', 'green')) + "\t SNMP Enumeration Completed on %s:%s" % (target_ip, port)

# Multi Process utility
def mult_proc(function, target_ip, proto, port, output_dir):
    jobs = []
    p = multiprocessing.Process(target=function, args=(target_ip, proto, port, output_dir))
    jobs.append(p)
    p.start()
    return

# Make directory utility
def mkdir(dir_in):
    try:
        os.makedirs(dir_in)
    except:
        pass

# Scrub input_str for blacklisted OS command injection attempts
def cmd_inj_safe(input_str):
    blacklist = "<>,?:;\'\"|=+~`!@#$%^&*(){}[]"
    for char in blacklist:
        if char in input_str:
            return False
    return True

# Scrub IP address
def valid_ipv4(input_ipv4):
    try:
        socket.inet_aton(input_ipv4)
        return True
    except:
        return False

# Main function
if __name__ == '__main__':

    # Parse command line flags and arguments
    parser = argparse.ArgumentParser(description="spy.py -- remote recon and enumeration")
    parser.add_argument('-T', dest="targets_filename", action='store', required=True, help='File of target IPs')
    parser.add_argument('-d', dest="outputdir", action='store', required=True, help='Output directory')
    args = parser.parse_args()

    # Banner
    print str(colored('[*]', 'blue')) + " Spy - Remote Reconaissance & Enumeration"

    # Process file of target IP addresses one at a time
    # Python-style commenting allowed within the file of target IP addresses
    multiline_comment = False
    f = open(args.targets_filename, 'r')
    target_ips = []
    for target_ip in f:
        if target_ip.strip()[0:3] == "'''" and not multiline_comment:
            multiline_comment = True
            continue
        elif target_ip.strip()[0:3] == "'''" and multiline_comment:
            multiline_comment = False
            continue
        if target_ip.strip()[0] != '#' and not multiline_comment:
            comment_begin = target_ip.find("#")
            target_ip = target_ip[0:comment_begin].strip()
            jobs = []

            # Scrub user inputted target IP address
            if not valid_ipv4(target_ip):
                print str(colored('[!]', 'red')) + " Invalid IPv4 address. Moving on."
                continue

            # Scrub user inputted output directory
            if not cmd_inj_safe(args.outputdir):
                print str(colored('[!]', 'red')) + " Command injection detected. Exiting."
                sys.exit(1)

            # Create base directory for target
            target_dir = "%s/%s" % (args.outputdir, target_ip)
            mkdir(target_dir)

            # Create loot subdirectory
            loot_dir = "%s/loot" % target_dir
            mkdir(loot_dir)

            # Create recon subdirectory
            recon_dir = "%s/recon" % target_dir
            mkdir(recon_dir)

            # Create recon/privesc subdirectory
            privesc_dir = "%s/privesc" % recon_dir
            mkdir(privesc_dir)

            # Create exploit subdirectory
            exploit_dir = "%s/exploit" % target_dir
            mkdir(exploit_dir)

            # Begin spying
            p = multiprocessing.Process(target=spy, args=(target_ip, recon_dir))
            jobs.append(p)
            p.start()

    f.close()
