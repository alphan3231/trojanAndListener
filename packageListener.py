import scapy.all as scapy
from scapy_http import http
import optparse

def option():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", default="eth0", type="int")
    (options, args) = parser.parse_args()
    return options

def listenPacket():
    scapy.sniff(iface=option(),store=False,prn=analyze_packets)


def analyze_packets(packet):
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            print(packet[scapy.Raw].load)

listenPacket()