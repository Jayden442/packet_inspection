from dataclasses import dataclass
from enum import Enum
from collections import deque

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
    last_activity: float
    expired_at: float | None = None

    syn_received: bool = False
    syn_ack_received: bool = False
    ack_received: bool = False

    state: 'ConnectionState' = ConnectionState.SYN_SENT

class ConnectionTracker:
    def __init__(self, timeout):
        self.connections = {}
        self.timeout = timeout
        self.incomplete_connections = deque()
        self.incomplete_count = 0

    def add_connection(self, connection: Connection):
        key = (connection.src_ip, connection.src_port, connection.dst_ip, connection.dst_port)
        self.connections[key] = connection

    def update_connection(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, syn_received=False, syn_ack_received=False, ack_received=False):
        key = (src_ip, src_port, dst_ip, dst_port)
        reverse_key = (dst_ip, dst_port, src_ip, src_port)
        if key in self.connections:
            connection = self.connections[key]
        elif reverse_key in self.connections:
            connection = self.connections[reverse_key]
        else:
            if key in self.incomplete_connections or reverse_key in self.incomplete_connections:
                print("This connection already timed out")
            return
        if syn_received:
            connection.syn_received = True
            connection.state = ConnectionState.SYN_SENT
        if syn_ack_received and connection.state == ConnectionState.SYN_SENT:
            connection.syn_ack_received = True
            connection.state = ConnectionState.SYN_ACK_RECEIVED
        if ack_received and connection.state == ConnectionState.SYN_ACK_RECEIVED:
            connection.ack_received = True
            connection.state = ConnectionState.ESTABLISHED

    def remove_connection(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int):
        key = (src_ip, src_port, dst_ip, dst_port)
        if key in self.connections:
            del self.connections[key]

    def get_connection(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int):
        key = (src_ip, src_port, dst_ip, dst_port)
        return self.connections.get(key)

    def get_current_connections(self) -> list[Connection]:
        return list(self.connections.values())

    def get_incomplete_connections(self) -> list[Connection]:
        return list(self.incomplete_connections)

    def get_connection_state(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int):
        connection = self.get_connection(src_ip, src_port, dst_ip, dst_port)
        if connection:
            return connection.state
        return None

    def expire_connections(self, current_time):
        expired = []

        # cleanup incomplete connections first
        while self.incomplete_connections and self.incomplete_connections[0].expired_at and current_time - self.incomplete_connections[0].expired_at > self.connection_timeout * 2:
            self.incomplete_connections.popleft()

        for key, connection in self.connections.items():
            if connection.state != ConnectionState.ESTABLISHED:
                if current_time - connection.last_activity > self.connection_timeout:
                    expired.append(key)
                    self.connections[key].expired_at = current_time

        for key in expired:
            self.incomplete_count += 1
            self.incomplete_connections.append(self.connections[key])
            del self.connections[key]

    def process_packet(self, packet_info):
        self.expire_connections(packet_info.timestamp)
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
            if self.get_connection_state(src_ip, src_port, dst_ip, dst_port) == ConnectionState.SYN_SENT:
                self.update_connection(src_ip, src_port, dst_ip, dst_port, syn_ack_received=True)
        elif 'A' in flags and not 'S' in flags:
            if self.get_connection_state(src_ip, src_port, dst_ip, dst_port) == ConnectionState.SYN_ACK_RECEIVED:
                self.update_connection(src_ip, src_port, dst_ip, dst_port, ack_received=True)
