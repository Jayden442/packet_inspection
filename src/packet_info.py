from datetime import datetime
from dataclasses import dataclass

@dataclass
class PacketInfo:
    timestamp: datetime

    src_mac: str | None = None
    dst_mac: str | None = None

    src_ip: str | None = None
    dst_ip: str | None = None
    ip_version: int | None = None

    protocol: str = "UNKNOWN"

    src_port: int | None = None
    dst_port: int | None = None

    tcp_flags: str | None = None

    icmp_type: int | None = None
    icmp_code: int | None = None
