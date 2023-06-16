#!/usr/bin/env python3
# Update by Deniz version 3.x

from subprocess import call, check_call, CalledProcessError
from os.path import isfile, basename
from os import devnull
from sys import exit, stdout, stderr
from atexit import register
from argparse import ArgumentParser
from json import load
from urllib.request import urlopen
from urllib.error import URLError
from time import sleep
import subprocess
import requests


class TorIptables(object):
    def __init__(self):
        self.local_dnsport = "53"  # DNSPort
        self.virtual_net = "10.0.0.0/10"  # VirtualAddrNetwork
        self.local_loopback = "127.0.0.1"  # Local loopback
        self.non_tor_net = ["192.168.0.0/16", "172.16.0.0/12"]
        self.non_tor = ["127.0.0.0/9", "127.128.0.0/10", "127.0.0.0/8"]
        self.tor_uid = subprocess.getoutput("id -ur debian-tor")  # Tor user uid
        self.trans_port = "9040"  # Tor port
        self.tor_config_file = '/etc/tor/torrc'
        self.torrc = r'''
## Inserted by %s for tor iptables rules set
## Transparently route all traffic thru tor on port %s
VirtualAddrNetwork %s
AutomapHostsOnResolve 1
TransPort %s
DNSPort %s
''' % (basename(__file__), self.trans_port, self.virtual_net, self.trans_port, self.local_dnsport)

        self.log_file = "privacynet.log"  # Günlük dosyasının adı
        self.log = open(self.log_file, "a")  # Günlük dosyasını oluşturmak ve açmak

    def __del__(self):
        if self.log:
            self.log.close()  # Program sonlandığında günlük dosyasını kapat

    def write_log(self, message):
        if self.log:
            self.log.write(message + "\n")  # Günlük dosyasına yaz

    def flush_iptables_rules(self):
        call(["iptables", "-F"])
        call(["iptables", "-t", "nat", "-F"])

        self.write_log("[+] Flushed iptables rules")  # Günlük

    def load_iptables_rules(self):
        self.flush_iptables_rules()
        self.non_tor.extend(self.non_tor_net)

        @register
        def restart_tor():
            fnull = open(devnull, 'w')
            try:
                tor_restart = check_call(
                    ["service", "tor", "restart"],
                    stdout=fnull, stderr=fnull)

                if tor_restart == 0:
                    print(" {0}".format(
                        "[+] Anonymizer status [ON]"))
                    self.get_ip()
            except CalledProcessError as err:
                print("[!] Command failed: %s" % ' '.join(err.cmd))

        # See https://trac.torproject.org/projects/tor/wiki/doc/TransparentProxy#WARNING
        # See https://lists.torproject.org/pipermail/tor-talk/2014-March/032503.html
        call(["iptables", "-I", "OUTPUT", "!", "-o", "lo", "!", "-d", self.local_loopback, "!", "-s", self.local_loopback, "-p", "tcp", "-m", "tcp", "--tcp-flags", "ACK,FIN", "ACK,FIN", "-j", "DROP"])
        call(["iptables", "-I", "OUTPUT", "!", "-o", "lo", "!", "-d", self.local_loopback, "!", "-s", self.local_loopback, "-p", "tcp", "-m", "tcp", "--tcp-flags", "ACK,RST", "ACK,RST", "-j", "DROP"])
        call(["iptables", "-t", "nat", "-A", "OUTPUT", "-m", "owner", "--uid-owner", "%s" % self.tor_uid, "-j", "RETURN"])
        call(["iptables", "-t", "nat", "-A", "OUTPUT", "-p", "udp", "--dport", self.local_dnsport, "-j", "REDIRECT", "--to-ports", self.local_dnsport])

        for net in self.non_tor:
            call(["iptables", "-t", "nat", "-A", "OUTPUT", "-d", "%s" % net, "-j", "RETURN"])

        call(["iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "--syn", "-j", "REDIRECT", "--to-ports", "%s" % self.trans_port])
        call(["iptables", "-A", "OUTPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
        for net in self.non_tor:
            call(["iptables", "-A", "OUTPUT", "-d", "%s" % net, "-j", "ACCEPT"])

        call(["iptables", "-A", "OUTPUT", "-m", "owner", "--uid-owner", "%s" % self.tor_uid, "-j", "ACCEPT"])
        call(["iptables", "-A", "OUTPUT", "-j", "REJECT"])

        self.write_log("[+] Loaded iptables rules")  # Günlük

    def geolocate_ip(self, ip):
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}")
            data = response.json()
            country = data["country"]
            city = data["city"]
            return country, city
        except Exception as e:
            print(f"Error geolocating IP: {e}")
            return None, None

    def get_ip(self):
        print(" [\033[92m*\033[0m] \033[93mGetting public IP, please wait...\033[0m")
        retries = 0
        my_public_ip = None
        while retries < 12 and not my_public_ip:
            retries += 1
            try:
                my_public_ip = load(urlopen('https://check.torproject.org/api/ip'))['IP']
            except URLError:
                sleep(5)
                print(" [\033[93m?\033[0m] Still waiting for IP address...")
            except ValueError:
                break
        if not my_public_ip:
            my_public_ip = subprocess.getoutput('wget -qO - ifconfig.me')
        if not my_public_ip:
            exit(" \033[91m[!]\033[0m Can't get public ip address!")

        country, city = self.geolocate_ip(my_public_ip)
        if country and city:
            print(" {0}".format("[\033[92m+\033[0m] Your IP is \033[92m%s\033[0m" % my_public_ip))
            print(" {0}".format("[\033[92m+\033[0m] Country: \033[92m%s\033[0m" % country))
            print(" {0}".format("[\033[92m+\033[0m] City: \033[92m%s\033[0m" % city))
            self.write_log(f"[+] Your IP is {my_public_ip}\n[+] Country: {country}\n[+] City: {city}")  # Günlük
        else:
            print(" {0}".format("[\033[92m+\033[0m] Your IP is \033[92m%s\033[0m" % my_public_ip))
            print(" {0}".format("[\033[93m!\033[0m] Error geolocating IP"))
            self.write_log(f"[+] Your IP is {my_public_ip}\n[!] Error geolocating IP")  # Günlük

    def change_ip(self):
        call(['kill', '-HUP', '%s' % subprocess.getoutput('pidof tor')])
        self.get_ip()


if __name__ == '__main__':
    parser = ArgumentParser(
        description=
        'PrivacyNet is an anonymization tool for loading and unloading iptables rules')
    parser.add_argument('-l', '--load', action='store_true', help='This option will load tor iptables rules')
    parser.add_argument('-f', '--flush', action='store_true', help='This option flushes the iptables rules to default')
    parser.add_argument('-r', '--refresh', action='store_true', help='This option will change the circuit and gives new IP')
    parser.add_argument('-i', '--ip', action='store_true', help='This option will output the current public IP address')
    parser.add_argument('-a', '--auto', action='store_true', help='This option enables automatic IP change every X seconds')
    parser.add_argument('-t', '--interval', type=int, default=3600, help='Interval for automatic IP change in seconds (default: 3600)')
    args = parser.parse_args()

    try:
        privacy_net = TorIptables()
        if isfile(privacy_net.tor_config_file):
            if not 'VirtualAddrNetwork' in open(privacy_net.tor_config_file).read():
                with open(privacy_net.tor_config_file, 'a+') as torrconf:
                    torrconf.write(privacy_net.torrc)

        if args.load:
            privacy_net.load_iptables_rules()
        elif args.flush:
            privacy_net.flush_iptables_rules()
            print(" {0}".format("[\033[93m!\033[0m] Anonymizer status \033[91m[OFF]\033[0m"))
            privacy_net.write_log("[!] Anonymizer status [OFF]")  # Günlük
        elif args.ip:
            privacy_net.get_ip()
        elif args.refresh:
            privacy_net.change_ip()
        elif args.auto:
            interval = args.interval
            try:
                while True:
                    privacy_net.change_ip()
                    print(" {0}".format("[\033[92m*\033[0m] IP changed successfully\n"))
                    sleep(interval)
            except KeyboardInterrupt:
                print("\n[\033[91m!\033[0m] Program terminated by user")
        else:
            parser.print_help()
    except Exception as err:
        print(f"[!] Run as super user: {err[1]}")
        privacy_net.write_log(f"[!] Run as super user: {err[1]}")  # Günlük


