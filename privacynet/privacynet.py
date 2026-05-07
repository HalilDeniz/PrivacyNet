#!/usr/bin/env python3
"""
PrivacyNet - Advanced Tor-based anonymization tool
- Routing all TCP traffic through Tor
- IPv6 leak protection
- IP renewal with NEWNYM signal (stem library)
- Automatic Tor user UID detection
- Configuration file support (JSON)
- Whitelist port feature (for SSH, etc.)
- Detailed logging
"""

import subprocess
import sys
import os
import pwd
import json
import atexit
import logging
import time
import socket
from argparse import ArgumentParser
from urllib.request import urlopen
from urllib.error import URLError
from logging.handlers import RotatingFileHandler

# Colorama and third-party libraries
try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)  # Reset style after each print
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False
    # Fallback empty strings
    class Fore: RED=''; GREEN=''; YELLOW=''; CYAN=''; MAGENTA=''; WHITE=''; RESET=''
    class Back: RED=''; GREEN=''; YELLOW=''; RESET=''
    class Style: BRIGHT=''; RESET_ALL=''; DIM=''

try:
    import requests
    from stem.control import Controller
    from stem import Signal
    STEM_AVAILABLE = True
except ImportError:
    STEM_AVAILABLE = False

class TorIptables:
    def __init__(self, config_file=None):
        # Default values
        self.trans_port = "9040"
        self.local_dnsport = "53"
        self.virtual_net = "10.0.0.0/10"
        self.local_loopback = "127.0.0.1"
        self.non_tor_net = ["192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"]
        self.non_tor = ["127.0.0.0/9", "127.128.0.0/10"]
        self.control_port = 9051
        self.tor_config_file = '/etc/tor/torrc'
        self.whitelist_ports = []
        self.block_ipv6 = True
        
        # Logging setup
        self.log_file = "/var/log/privacynet.log"
        if not os.access('/var/log', os.W_OK):
            self.log_file = os.path.expanduser("~/.privacynet.log")
        self._setup_logging()
        
        # Load configuration file if exists
        self.config_path = config_file or os.path.expanduser("~/.privacynet.json")
        self.load_config()
        
        self.tor_uid = self._get_tor_uid()
        self._ensure_torrc_config()
        atexit.register(self._restart_tor_at_exit)
        
        self.logger.info("PrivacyNet started. Tor UID: %s", self.tor_uid)
    
    def _setup_logging(self):
        self.logger = logging.getLogger('PrivacyNet')
        self.logger.setLevel(logging.INFO)
        file_handler = RotatingFileHandler(self.log_file, maxBytes=5*1024*1024, backupCount=3)
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(logging.Formatter('%(message)s'))
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
    
    def load_config(self):
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    cfg = json.load(f)
                self.trans_port = str(cfg.get('trans_port', self.trans_port))
                self.local_dnsport = str(cfg.get('dns_port', self.local_dnsport))
                self.virtual_net = cfg.get('virtual_net', self.virtual_net)
                self.non_tor_net = cfg.get('non_tor_nets', self.non_tor_net)
                self.non_tor = cfg.get('non_tor_ips', self.non_tor)
                self.control_port = cfg.get('control_port', self.control_port)
                self.block_ipv6 = cfg.get('block_ipv6', True)
                self.logger.info("Configuration loaded from: %s", self.config_path)
            except Exception as e:
                self.logger.warning("Failed to read config file: %s", e)
    
    def save_config(self):
        cfg = {
            'trans_port': self.trans_port,
            'dns_port': self.local_dnsport,
            'virtual_net': self.virtual_net,
            'non_tor_nets': self.non_tor_net,
            'non_tor_ips': self.non_tor,
            'control_port': self.control_port,
            'block_ipv6': self.block_ipv6
        }
        try:
            with open(self.config_path, 'w') as f:
                json.dump(cfg, f, indent=4)
            self.logger.info("Configuration saved to: %s", self.config_path)
        except Exception as e:
            self.logger.error("Failed to save config: %s", e)
    
    def _get_tor_uid(self):
        possible_users = ['debian-tor', 'tor', '_tor']
        for user in possible_users:
            try:
                uid = pwd.getpwnam(user).pw_uid
                self.logger.info("Tor user found: %s (UID=%s)", user, uid)
                return uid
            except KeyError:
                continue
        try:
            pidof = subprocess.run(['pidof', 'tor'], capture_output=True, text=True)
            if pidof.returncode == 0 and pidof.stdout.strip():
                pid = pidof.stdout.split()[0]
                uid_line = subprocess.run(['ps', '-o', 'uid=', '-p', pid], capture_output=True, text=True)
                uid = int(uid_line.stdout.strip())
                self.logger.warning("Tor UID obtained from process: %s", uid)
                return uid
        except:
            pass
        raise RuntimeError("Tor user not found.")
    
    def _ensure_torrc_config(self):
        needed_lines = [
            f"VirtualAddrNetwork {self.virtual_net}",
            "AutomapHostsOnResolve 1",
            f"TransPort {self.trans_port}",
            f"DNSPort {self.local_dnsport}",
            f"ControlPort {self.control_port}",
            "CookieAuthentication 1"
        ]
        if not os.path.exists(self.tor_config_file):
            self.logger.error("Tor configuration file not found: %s", self.tor_config_file)
            return
        with open(self.tor_config_file, 'r') as f:
            content = f.read()
        modified = False
        with open(self.tor_config_file, 'a') as f:
            for line in needed_lines:
                if line not in content:
                    f.write(line + "\n")
                    modified = True
            if modified:
                self.logger.info("Added necessary lines to Tor configuration.")
    
    def _restart_tor_at_exit(self):
        pass
    
    def _run_iptables(self, args):
        try:
            subprocess.run(args, check=True, capture_output=True, text=True)
            self.logger.debug("IPTables command succeeded: %s", ' '.join(args))
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error("IPTables error: %s - %s", ' '.join(args), e.stderr)
            return False
    
    def flush_iptables_rules(self):
        self._run_iptables(["iptables", "-F"])
        self._run_iptables(["iptables", "-t", "nat", "-F"])
        self._run_iptables(["iptables", "-X"])
        if self.block_ipv6:
            self._run_iptables(["ip6tables", "-F"])
            self._run_iptables(["ip6tables", "-P", "INPUT", "ACCEPT"])
            self._run_iptables(["ip6tables", "-P", "OUTPUT", "ACCEPT"])
            self._run_iptables(["ip6tables", "-P", "FORWARD", "ACCEPT"])
            self.logger.info("IPv6 rules flushed and set to ACCEPT.")
        self.logger.info("All iptables rules flushed.")
    
    def load_iptables_rules(self):
        self.flush_iptables_rules()
        if self.block_ipv6:
            self._run_iptables(["ip6tables", "-F"])
            self._run_iptables(["ip6tables", "-P", "INPUT", "DROP"])
            self._run_iptables(["ip6tables", "-P", "OUTPUT", "DROP"])
            self._run_iptables(["ip6tables", "-P", "FORWARD", "DROP"])
            self.logger.info("IPv6 traffic completely blocked.")
        # Drop dangerous TCP flags (FIN/ACK and RST/ACK)
        self._run_iptables(["iptables", "-I", "OUTPUT", "!", "-o", "lo", "!", "-d", self.local_loopback,
                           "!", "-s", self.local_loopback, "-p", "tcp", "-m", "tcp", "--tcp-flags", "ACK,FIN", "ACK,FIN", "-j", "DROP"])
        self._run_iptables(["iptables", "-I", "OUTPUT", "!", "-o", "lo", "!", "-d", self.local_loopback,
                           "!", "-s", self.local_loopback, "-p", "tcp", "-m", "tcp", "--tcp-flags", "ACK,RST", "ACK,RST", "-j", "DROP"])
        # Don't NAT Tor user traffic
        self._run_iptables(["iptables", "-t", "nat", "-A", "OUTPUT", "-m", "owner",
                           "--uid-owner", str(self.tor_uid), "-j", "RETURN"])
        # Redirect DNS to Tor DNSPort
        self._run_iptables(["iptables", "-t", "nat", "-A", "OUTPUT", "-p", "udp",
                           "--dport", self.local_dnsport, "-j", "REDIRECT", "--to-ports", self.local_dnsport])
        # Allow non-Tor networks to bypass
        for net in self.non_tor + self.non_tor_net:
            self._run_iptables(["iptables", "-t", "nat", "-A", "OUTPUT", "-d", net, "-j", "RETURN"])
        # Whitelist ports
        for port in self.whitelist_ports:
            self._run_iptables(["iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "--dport", str(port), "-j", "RETURN"])
            self.logger.info("Port %s added to whitelist, will not go through Tor.", port)
        # Redirect remaining TCP SYNs to Tor TransPort
        self._run_iptables(["iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "--syn",
                           "-j", "REDIRECT", "--to-ports", self.trans_port])
        # Allow established connections
        self._run_iptables(["iptables", "-A", "OUTPUT", "-m", "state",
                           "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
        # Allow non-Tor networks
        for net in self.non_tor + self.non_tor_net:
            self._run_iptables(["iptables", "-A", "OUTPUT", "-d", net, "-j", "ACCEPT"])
        # Allow Tor user traffic
        self._run_iptables(["iptables", "-A", "OUTPUT", "-m", "owner",
                           "--uid-owner", str(self.tor_uid), "-j", "ACCEPT"])
        # Reject everything else
        self._run_iptables(["iptables", "-A", "OUTPUT", "-j", "REJECT"])
        
        self.logger.info("IPTables rules loaded successfully. Anonymization ACTIVE.")
        self._restart_tor_service()
    
    def _restart_tor_service(self):
        fnull = open(os.devnull, 'w')
        try:
            subprocess.check_call(["service", "tor", "restart"], stdout=fnull, stderr=fnull)
            self.logger.info("Tor service restarted.")
        except:
            try:
                subprocess.check_call(["systemctl", "restart", "tor"], stdout=fnull, stderr=fnull)
                self.logger.info("Tor service restarted (systemctl).")
            except Exception as e:
                self.logger.warning("Could not restart Tor service: %s", e)
    
    def get_public_ip(self):
        services = [
            'https://check.torproject.org/api/ip',
            'https://icanhazip.com',
            'https://api.ipify.org',
            'https://ifconfig.co/ip'
        ]
        for service in services:
            try:
                if 'check.torproject.org' in service:
                    data = requests.get(service, timeout=10).json()
                    ip = data.get('IP')
                else:
                    ip = requests.get(service, timeout=10).text.strip()
                if ip and '.' in ip:
                    return ip
            except Exception:
                continue
        try:
            ip = subprocess.run(['wget', '-qO-', 'ifconfig.me'], capture_output=True, text=True, timeout=10).stdout.strip()
            if ip:
                return ip
        except:
            pass
        return None
    
    def geolocate_ip(self, ip):
        try:
            resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
            data = resp.json()
            if data.get('status') == 'success':
                return data.get('country'), data.get('city')
        except Exception as e:
            self.logger.debug("Geolocation error: %s", e)
        return None, None
    
    def show_ip_info(self):
        """Display current public IP with colors"""
        print(f" {Fore.GREEN}*{Style.RESET_ALL} {Fore.YELLOW}Getting public IP, please wait...{Style.RESET_ALL}")
        ip = self.get_public_ip()
        if not ip:
            print(f" {Fore.RED}[!]{Style.RESET_ALL} Could not get public IP! Is Tor running?")
            self.logger.error("Failed to get public IP.")
            return False
        
        country, city = self.geolocate_ip(ip)
        print(f" {Style.BRIGHT}{Fore.GREEN}[+]{Style.RESET_ALL} Your IP address: {Fore.GREEN}{ip}{Style.RESET_ALL}")
        if country and city:
            print(f" {Style.BRIGHT}{Fore.GREEN}[+]{Style.RESET_ALL} Country: {Fore.GREEN}{country}{Style.RESET_ALL}")
            print(f" {Style.BRIGHT}{Fore.GREEN}[+]{Style.RESET_ALL} City: {Fore.GREEN}{city}{Style.RESET_ALL}")
            self.logger.info(f"Public IP: {ip} ({country}/{city})")
        else:
            print(f" {Style.BRIGHT}{Fore.YELLOW}[!]{Style.RESET_ALL} Could not geolocate IP.")
            self.logger.info(f"Public IP: {ip}")
        return True
    
    def change_ip(self):
        """Request a new Tor circuit (NEWNYM) or fallback to kill -HUP"""
        if STEM_AVAILABLE:
            try:
                with Controller.from_port(port=self.control_port) as ctrl:
                    ctrl.authenticate()
                    ctrl.signal(Signal.NEWNYM)
                    self.logger.info("NEWNYM signal sent (via stem).")
                    time.sleep(2)
                    self.show_ip_info()
                    return True
            except Exception as e:
                self.logger.warning("Stem NEWNYM failed: %s, falling back to kill -HUP.", e)
        try:
            pid = subprocess.run(['pidof', 'tor'], capture_output=True, text=True).stdout.strip()
            if pid:
                subprocess.run(['kill', '-HUP', pid.split()[0]], check=True)
                self.logger.info("Sent HUP signal to Tor.")
                time.sleep(2)
                self.show_ip_info()
                return True
        except Exception as e:
            self.logger.error("IP change failed: %s", e)
        return False


def main():
    parser = ArgumentParser(description="PrivacyNet - Advanced Tor anonymization tool")
    parser.add_argument('-l', '--load', action='store_true', help='Load iptables rules and enable Tor anonymization')
    parser.add_argument('-f', '--flush', action='store_true', help='Flush all iptables rules (disable anonymization)')
    parser.add_argument('-r', '--refresh', action='store_true', help='Renew Tor circuit and get a new IP')
    parser.add_argument('-i', '--ip', action='store_true', help='Show current public IP address')
    parser.add_argument('-a', '--auto', type=int, nargs='?', const=3600, metavar='SECONDS',
                        help='Enable automatic IP change every SECONDS (default: 3600)')
    parser.add_argument('-c', '--config', metavar='FILE', help='JSON configuration file path')
    parser.add_argument('-w', '--whitelist-port', type=int, action='append', default=[],
                        help='Whitelist a TCP port (e.g., 22 for SSH). Can be used multiple times.')
    parser.add_argument('--no-ipv6-block', action='store_false', dest='block_ipv6',
                        help='Disable IPv6 blocking (default: block IPv6)')
    
    args = parser.parse_args()
    
    if os.geteuid() != 0:
        print(f"{Fore.RED}[!]{Style.RESET_ALL} This program requires root privileges. Please run with sudo.")
        sys.exit(1)
    
    try:
        privacy = TorIptables(config_file=args.config)
        if args.whitelist_port:
            privacy.whitelist_ports = args.whitelist_port
        if not args.block_ipv6:
            privacy.block_ipv6 = False
        
        if args.load:
            privacy.load_iptables_rules()
            print(f" {Fore.GREEN}[+]{Style.RESET_ALL} Anonymizer status {Fore.GREEN}[ACTIVE]{Style.RESET_ALL}")
            time.sleep(1)
            privacy.show_ip_info()
        elif args.flush:
            privacy.flush_iptables_rules()
            print(f" {Fore.YELLOW}[!]{Style.RESET_ALL} Anonymizer status {Fore.RED}[INACTIVE]{Style.RESET_ALL}")
            privacy.logger.info("Anonymizer disabled.")
        elif args.refresh:
            privacy.change_ip()
        elif args.ip:
            privacy.show_ip_info()
        elif args.auto is not None:
            interval = args.auto
            print(f" {Fore.GREEN}[*]{Style.RESET_ALL} Automatic IP change started, interval: {interval} seconds. Press Ctrl+C to stop.")
            try:
                while True:
                    privacy.change_ip()
                    print(f" {Fore.GREEN}[*]{Style.RESET_ALL} IP changed successfully. Next change in {interval} seconds.\n")
                    time.sleep(interval)
            except KeyboardInterrupt:
                print(f"\n {Fore.YELLOW}[!]{Style.RESET_ALL} Program terminated by user.")
                privacy.logger.info("Automatic refresh stopped.")
        else:
            parser.print_help()
    except Exception as e:
        print(f"{Fore.RED}[!]{Style.RESET_ALL} Error: {e}")
        logging.getLogger('PrivacyNet').error("Main error: %s", e, exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
