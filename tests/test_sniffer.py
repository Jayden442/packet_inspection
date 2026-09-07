from importlib import import_module
import sys
from pathlib import Path
from unittest.mock import Mock, call

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

sniffer = import_module("sniffer")


def test_sniff_packet_starts_sniffing_without_storing_packets(monkeypatch):
    sniff_mock = Mock()
    monkeypatch.setattr(sniffer, "sniff", sniff_mock)

    statistics_callback = Mock()
    connection_tracker_callback = Mock()

    sniffer.sniff_packet(statistics_callback, connection_tracker_callback)

    sniff_mock.assert_called_once_with(prn=sniff_mock.call_args.kwargs["prn"], store=False)
    assert callable(sniff_mock.call_args.kwargs["prn"])


def test_processes_packet_and_notifies_callbacks_in_order(monkeypatch):
    sniff_mock = Mock()
    analyze_packet_mock = Mock(return_value=object())
    events = []
    statistics_callback = Mock(side_effect=lambda packet_info: events.append(("statistics", packet_info)))
    connection_tracker_callback = Mock(
        side_effect=lambda packet_info: events.append(("connection_tracker", packet_info))
    )
    monkeypatch.setattr(sniffer, "sniff", sniff_mock)
    monkeypatch.setattr(sniffer, "analyze_packet", analyze_packet_mock)

    sniffer.sniff_packet(statistics_callback, connection_tracker_callback)
    packet = object()
    sniff_mock.call_args.kwargs["prn"](packet)

    packet_info = analyze_packet_mock.return_value
    analyze_packet_mock.assert_called_once_with(packet)
    statistics_callback.assert_called_once_with(packet_info)
    connection_tracker_callback.assert_called_once_with(packet_info)
    assert events == [
        ("statistics", packet_info),
        ("connection_tracker", packet_info),
    ]


def test_processes_each_captured_packet_independently(monkeypatch):
    sniff_mock = Mock()
    analyze_packet_mock = Mock(side_effect=["first-info", "second-info"])
    statistics_callback = Mock()
    connection_tracker_callback = Mock()
    monkeypatch.setattr(sniffer, "sniff", sniff_mock)
    monkeypatch.setattr(sniffer, "analyze_packet", analyze_packet_mock)

    sniffer.sniff_packet(statistics_callback, connection_tracker_callback)
    process_packet = sniff_mock.call_args.kwargs["prn"]
    first_packet = object()
    second_packet = object()
    process_packet(first_packet)
    process_packet(second_packet)

    assert analyze_packet_mock.call_args_list == [call(first_packet), call(second_packet)]
    assert statistics_callback.call_args_list == [call("first-info"), call("second-info")]
    assert connection_tracker_callback.call_args_list == [call("first-info"), call("second-info")]