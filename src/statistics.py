from packet_info import PacketInfo
from collections import deque, Counter
from source_ip import SourceIP
import time
import math

# DNS Stats for a specific source IP
class DNSStatistics:
    def __init__(self, time_window=10):
        self.query_count = 0
        self.total_query_length = 0
        self.subdomain_counter = Counter()
        self.total_subdomain_entropy = 0.0
        self.packet_info_list = deque()
        self.time_window = time_window

    def add_packet(self, packet_info):
        if not packet_info: 
            return
        
        if packet_info.dns_is_response:
            return
        
        if not packet_info.dns_query:
            return
        self.packet_info_list.append(packet_info)
        self.update(packet_info)
    
    def remove_outdated_packets(self):
        cur_time = time.time()
        while (self.packet_info_list and cur_time - self.packet_info_list[0].timestamp > self.time_window):
            last_packet = self.packet_info_list[0]
            query = last_packet.dns_query.rstrip(".")
            self.total_query_length -= len(query)
            self.query_count -= 1
            subdomain = self.get_subdomain(query)
            if subdomain:
                self.total_subdomain_entropy -= self.calculate_entropy(subdomain)
                self.subdomain_counter[subdomain] -= 1
                if self.subdomain_counter[subdomain] == 0:
                    del self.subdomain_counter[subdomain]
            self.packet_info_list.popleft()

    def update(self, packet_info):
        if not packet_info:
            return
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
            self.subdomain_counter[subdomain] += 1
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
    def calculate_entropy(self, subdomain):
        if not subdomain:
            return 0
        freq_dict = {}
        entropy = 0.0
        for char in subdomain:
            freq_dict[char] = freq_dict.get(char, 0) + 1
        for count in freq_dict.values():
            probability = count / len(subdomain)
            entropy -= probability * math.log2(probability)
        return entropy

    @property
    def average_query_length(self):
        if self.query_count == 0:
            return 0
        return self.total_query_length / self.query_count
    
    @property
    def unique_subdomains(self):
        return len(self.subdomain_counter)

            


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
            self.remove_outdated_packets()
            return
        if ip not in self.ips:
            self.ips[ip] = SourceIP(ip)
        self.ips[ip].update(packet_info)
        self.ips[ip].add_dest(packet_info)
        if ip not in self.dns_statistics:
            self.dns_statistics[ip] = DNSStatistics(time_window=self.time_window)
        self.dns_statistics[ip].add_packet(packet_info)
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
        for dns_stats in self.dns_statistics.values():
            dns_stats.remove_outdated_packets()

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
