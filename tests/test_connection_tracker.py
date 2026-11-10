from importlib import import_module
from pathlib import Path
import sys
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

connection_tracker = import_module("connection_tracker")
Connection = connection_tracker.Connection
ConnectionState = connection_tracker.ConnectionState
ConnectionTracker = connection_tracker.ConnectionTracker


CLIENT_IP = "192.0.2.1"
SERVER_IP = "198.51.100.2"
CLIENT_PORT = 49152
SERVER_PORT = 443


def make_connection(**overrides):
    values = {
        "src_ip": CLIENT_IP,
        "src_port": CLIENT_PORT,
        "dst_ip": SERVER_IP,
        "dst_port": SERVER_PORT,
        "start_time": 1,
        "last_activity": 1,
    }
    values.update(overrides)
    return Connection(**values)


def make_packet(timestamp, src_ip=CLIENT_IP, src_port=CLIENT_PORT,
                dst_ip=SERVER_IP, dst_port=SERVER_PORT, flags="", protocol="TCP"):
    return SimpleNamespace(
        timestamp=timestamp,
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        tcp_flags=flags,
        protocol=protocol,
    )


def test_add_and_get_connection():
    tracker = ConnectionTracker(timeout=10)
    connection = make_connection()

    tracker.add_connection(connection)

    assert tracker.get_connection(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT) is connection
    assert tracker.get_connection_state(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT) == ConnectionState.SYN_SENT
    assert tracker.get_current_connections() == [connection]


def test_get_missing_connection_returns_none():
    tracker = ConnectionTracker(timeout=10)

    assert tracker.get_connection(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT) is None
    assert tracker.get_connection_state(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT) is None


def test_remove_connection_removes_it():
    tracker = ConnectionTracker(timeout=10)
    tracker.add_connection(make_connection())

    tracker.remove_connection(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT)

    assert tracker.get_current_connections() == []
    assert tracker.get_connection(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT) is None


def test_update_activity_accepts_either_packet_direction():
    tracker = ConnectionTracker(timeout=10)
    connection = make_connection()
    tracker.add_connection(connection)

    tracker.update_activity(SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT, timestamp=2)

    assert connection.last_activity == 2


def test_update_activity_without_timestamp_does_not_change_connection():
    tracker = ConnectionTracker(timeout=10)
    connection = make_connection()
    tracker.add_connection(connection)

    tracker.update_activity(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT)

    assert connection.last_activity == 1


def test_update_connection_advances_tcp_handshake():
    tracker = ConnectionTracker(timeout=10)
    connection = make_connection()
    tracker.add_connection(connection)

    tracker.update_connection(
        SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT,
        syn_ack_received=True, timestamp=2,
    )
    assert connection.state == ConnectionState.SYN_ACK_RECEIVED
    assert connection.syn_ack_received is True
    assert connection.last_activity == 2

    tracker.update_connection(
        CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT,
        ack_received=True, timestamp=3,
    )
    assert connection.state == ConnectionState.ESTABLISHED
    assert connection.ack_received is True
    assert connection.last_activity == 3


def test_update_connection_ignores_out_of_order_flags():
    tracker = ConnectionTracker(timeout=10)
    connection = make_connection()
    tracker.add_connection(connection)

    tracker.update_connection(
        CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT,
        ack_received=True,
    )

    assert connection.state == ConnectionState.SYN_SENT
    assert connection.ack_received is False


def test_expire_connections_moves_stale_incomplete_connection():
    tracker = ConnectionTracker(timeout=10)
    connection = make_connection()
    tracker.add_connection(connection)

    tracker.expire_connections(current_time=12)

    assert tracker.get_current_connections() == []
    assert tracker.get_incomplete_connections() == [connection]
    assert tracker.incomplete_count == 1
    assert connection.expired_at == 12


def test_expire_connections_keeps_recent_and_established_connections():
    tracker = ConnectionTracker(timeout=10)
    recent = make_connection(last_activity=5)
    established = make_connection(
        src_ip="192.0.2.3",
        src_port=49153,
        state=ConnectionState.ESTABLISHED,
        last_activity=1,
    )
    tracker.add_connection(recent)
    tracker.add_connection(established)

    tracker.expire_connections(current_time=15)

    assert tracker.get_current_connections() == [recent, established]
    assert tracker.get_incomplete_connections() == []


def test_expire_connections_removes_old_incomplete_entries():
    tracker = ConnectionTracker(timeout=10)
    old = make_connection(expired_at=5)
    recent = make_connection(src_port=49153, expired_at=15)
    tracker.incomplete_connections.extend([old, recent])

    tracker.expire_connections(current_time=26)

    assert tracker.get_incomplete_connections() == [recent]


def test_process_packet_ignores_none_and_non_tcp_packets():
    tracker = ConnectionTracker(timeout=10)

    tracker.process_packet(None)
    tracker.process_packet(make_packet(1, protocol="UDP", flags="S"))

    assert tracker.get_current_connections() == []


def test_process_packet_tracks_syn_syn_ack_and_ack_handshake():
    tracker = ConnectionTracker(timeout=10)

    tracker.process_packet(make_packet(1, flags="S"))
    connection = tracker.get_connection(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT)
    assert connection is not None
    assert connection.start_time == 1
    assert connection.state == ConnectionState.SYN_SENT

    tracker.process_packet(make_packet(
        2, src_ip=SERVER_IP, src_port=SERVER_PORT,
        dst_ip=CLIENT_IP, dst_port=CLIENT_PORT, flags="SA",
    ))
    assert connection.state == ConnectionState.SYN_ACK_RECEIVED
    assert connection.last_activity == 2

    tracker.process_packet(make_packet(3, flags="A"))
    assert connection.state == ConnectionState.ESTABLISHED
    assert connection.last_activity == 3


def test_process_packet_updates_activity_for_established_connection():
    tracker = ConnectionTracker(timeout=10)
    connection = make_connection(state=ConnectionState.ESTABLISHED)
    tracker.add_connection(connection)

    tracker.process_packet(make_packet(
        2, src_ip=SERVER_IP, src_port=SERVER_PORT,
        dst_ip=CLIENT_IP, dst_port=CLIENT_PORT, flags="P",
    ))

    assert connection.last_activity == 2