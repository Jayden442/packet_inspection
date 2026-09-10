from packet_info import PacketInfo
from scapy.layers.inet import IP, Ether, TCP, UDP, ICMP, DNS, DNSQR
from scapy.layers.inet6 import IPv6
from datetime import datetime

def analyze_packet(packet):
    src_mac = None
    dst_mac = None
    src_ip = None
    dst_ip = None
    ip_version = None
    protocol = "UNKNOWN"
    src_port = None
    dst_port = None
    tcp_flags = None
    icmp_type = None
    icmp_code = None
    dns_is_response = None
    dns_query = None
    dns_query_length = None
    if packet.haslayer(DNS):
        dns = packet[DNS]

        dns_is_response = bool(dns.qr)

        if packet.haslayer(DNSQR):
            query = packet[DNSQR].qname

            if isinstance(query, bytes):
                query = query.decode(errors="replace")

            dns_query = query
            dns_query_length = len(query)
    if IP not in packet and IPv6 not in packet:
        return None
    elif IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        ip_version = 4
    elif IPv6 in packet:
        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst
        ip_version = 6
    if Ether in packet:
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst
    if TCP in packet:
        protocol = 'TCP'
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        tcp_flags = packet[TCP].flags
    elif UDP in packet:
        protocol = 'UDP'
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    elif ICMP in packet:
        icmp_type = packet[ICMP].type
        icmp_code = packet[ICMP].code
    return PacketInfo(
        timestamp=packet.time,
        src_mac=src_mac,
        dst_mac=dst_mac,
        src_ip=src_ip,
        dst_ip=dst_ip,
        ip_version=ip_version,
        protocol=protocol,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=tcp_flags,
        icmp_type=icmp_type,
        icmp_code=icmp_code,
        dns_is_response=dns_is_response,
        dns_query=dns_query,
        dns_query_length=dns_query_length
    )
