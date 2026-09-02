from packet_info import PacketInfo
from collections import deque
from source_ip import SourceIP
import time

class TrafficStatistics:
    def __init__(self,time_window=10):
        self.time_window = time_window
        self.packets = deque()
        self.ips = dict()

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