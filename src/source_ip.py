from packet_info import PacketInfo
import time
from collections import deque

class SourceIP:
    def __init__(self, ip_address):
        self.ip_address = ip_address
        self.packet_count = 0
        self.dest_ports = dict()
        self.packets = deque()
        self.first_seen = None
        self.last_seen = None

    def update(self, packet_info: PacketInfo):
        self.packet_count += 1
        if self.first_seen is None:
            self.first_seen = packet_info.timestamp
        self.last_seen = packet_info.timestamp
        self.packets.append(packet_info)

    def add_dest(self, packet_info: PacketInfo):
        if packet_info.dst_port not in self.dest_ports:
            self.dest_ports[packet_info.dst_port] = packet_info.timestamp

    def remove_outdated_packets(self, time_window):
        cur_time = time.time()
        while self.packets and cur_time - self.packets[0].timestamp > time_window:
            self.packets.popleft()
            self.packet_count -= 1
        while self.dest_ports and cur_time - min(self.dest_ports.values()) > time_window:
            outdated_port = min(self.dest_ports, key=self.dest_ports.get)
            del self.dest_ports[outdated_port]

    def get_dest_port_count(self):
        return len(self.dest_ports)