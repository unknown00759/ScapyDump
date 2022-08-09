from cgitb import reset

from colorama import init, Fore
from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.http import HTTPRequest, TCP
import colorama

init()

red = Fore.RED
blue = Fore.BLUE
green = Fore.GREEN
yellow = Fore.YELLOW


def sniff_packet(iface):
    if iface:
        sniff(prn=process_packets, iface=iface, store=False)

    else:
        sniff(prn = process_packets , store=False)


def process_packets(packet):
    if packet.haslayer(TCP):
        src_ip= packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        print(f"{blue}[+] {src_ip} is using port {src_port} to connect {dst_ip} on port {dst_port}{reset}")

    if packet.haslayer(HTTPRequest):
        url= packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        method= packet[HTTPRequest].Method.decode()
        print(f"{green} [+] {src_port} is making HTTP request tp {url} with method {method}{reset}")

        print(f"[+] HTTP Data:")
        print(f"{yellow} {packet[HTTPRequest].show()}")
        if packet.haslayer(Raw):
            print(f"{red} [+] Useful Raw Data :{packet.getlayer(Raw).load.decode()}{reset}")



sniff_packet('eth0')



