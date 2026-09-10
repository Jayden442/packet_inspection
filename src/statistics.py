from packet_info import PacketInfo
from collections import deque
from source_ip import SourceIP
import time

class DNSStatistics:
    def __init__(self, ip):
        self.query_count = 0
        self.total_query_length = 0
        self.unique_subdomains = set()
        self.total_entropy = 0.0

    def add_dest(self, packet_info):
        if packet_info.dns_is_response:
            return
        
        if not packet_info.dns_query:
            return
        query = packet_info.dns_query.rstrip(".")

    def update(self, packet_info):
        # Only track DNS queries, not responses
        if packet_info.dns_is_response:
            return

        if not packet_info.dns_query:
            return

        query = packet_info.dns_query.rstrip(".")

        self.query_count += 1
        self.total_query_length += len(query)

        subdomain = self.get_subdomain(query)

        if subdomain:
            self.unique_subdomains.add(subdomain)

            entropy = self.calculate_entropy(subdomain)
            self.total_subdomain_entropy += entropy
    @property
    def average_subdomain_entropy(self):
        if self.query_count == 0:
            return 0

        return (
            self.total_subdomain_entropy /
            self.query_count
        )

    def get_subdomain(self, query):
        parts = query.split(".")

        if len(parts) <= 2:
            return None

        return ".".join(parts[:-2])

        

class TrafficStatistics:
    def __init__(self,time_window=10):
        self.time_window = time_window
        self.packets = deque()
        self.ips = dict()
        self.dns_statistics = {}

    def add_packet(self, packet_info: PacketInfo | None):
        if packet_info is None:
            return
        self.packets.append(packet_info)
        ip = packet_info.src_ip
        if ip is None:
            return
        if ip not in self.ips:
            self.ips[ip] = SourceIP(ip)
        self.ips[ip].update(packet_info)
        self.ips[ip].add_dest(packet_info)
        if ip not in self.dns_statistics:
            self.dns_statistics[ip] = DNSStatistics()
        self.remove_outdated_packets()

    def remove_outdated_packets(self):
        cur_time = time.time()
        while (
            self.packets and cur_time - self.packets[0].timestamp > self.time_window
        ):
            outdated_ip = self.packets[0].src_ip
            self.packets.popleft()
            
            if outdated_ip in self.ips:
                self.ips[outdated_ip].remove_outdated_packets(self.time_window)
        for ip, source_ip in list(self.ips.items()):
            source_ip.remove_outdated_packets(self.time_window)
            if source_ip.packet_count == 0:
                del self.ips[ip]

    def get_num_packets(self):
        self.remove_outdated_packets()
        return len(self.packets)

    def print_stats(self):
        num_packets = self.get_num_packets()
        print(f'Monitoring window: {self.time_window}\nTotal packets:{num_packets}\nPackets per second: {num_packets/self.time_window}\n')
        print("Source IP                 Destination Ports                         Packet Count")
        for ip, source_ip in self.ips.items():
            print(f'{ip:<25} {", ".join(str(port) for port in source_ip.dest_ports):<42} {source_ip.packet_count}')
        print("\n")

    def get_source_ips(self):
        self.remove_outdated_packets()
        return list(self.ips.values())
