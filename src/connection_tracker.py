from dataclasses import dataclass
from enum import Enum

class ConnectionState(Enum):
    SYN_SENT = 1
    SYN_ACK_RECEIVED = 2
    ESTABLISHED = 3

@dataclass
class Connection:
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int

    start_time: float

    syn_received: bool = False
    syn_ack_received: bool = False
    ack_received: bool = False

    state: 'ConnectionState' = ConnectionState.SYN_SENT

class ConnectionTracker:
    def __init__(self):
        self.connections = {}

    def add_connection(self, connection: Connection):
        key = (connection.src_ip, connection.src_port, connection.dst_ip, connection.dst_port)
        self.connections[key] = connection

    def update_connection(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, syn_received=False, syn_ack_received=False, ack_received=False):
        key = (src_ip, src_port, dst_ip, dst_port)
        reverse_key = (dst_ip, dst_port, src_ip, src_port)
        key_match = False
        if key in self.connections:
            connection = self.connections[key]
            key_match = True
        if reverse_key in self.connections:
            connection = self.connections[reverse_key]
            key_match = True
        if key_match:
            if syn_received:
                connection.syn_received = True
                connection.state = ConnectionState.SYN_SENT
            if syn_ack_received:
                connection.syn_ack_received = True
                connection.state = ConnectionState.SYN_ACK_RECEIVED
            if ack_received:
                connection.ack_received = True
                connection.state = ConnectionState.ESTABLISHED

    def remove_connection(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int):
        key = (src_ip, src_port, dst_ip, dst_port)
        if key in self.connections:
            del self.connections[key]

    def get_connection(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int):
        key = (src_ip, src_port, dst_ip, dst_port)
        return self.connections.get(key)

    def get_all_connections(self):
        return list(self.connections.values())

    def process_packet(self, packet_info):
        if packet_info.protocol != 'TCP':
            return

        src_ip = packet_info.src_ip
        src_port = packet_info.src_port
        dst_ip = packet_info.dst_ip
        dst_port = packet_info.dst_port
        flags = packet_info.tcp_flags
        if 'S' in flags and not 'A' in flags:
            connection = Connection(src_ip, src_port, dst_ip, dst_port, start_time=packet_info.timestamp)
            self.add_connection(connection)
        elif 'S' in flags and 'A' in flags:
            self.update_connection(dst_ip, dst_port, src_ip, src_port, syn_ack_received=True)
        elif 'A' in flags and not 'S' in flags:
            self.update_connection(src_ip, src_port, dst_ip, dst_port, ack_received=True)

