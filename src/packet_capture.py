"""
Packet Capture and Processing Module

Handles both live network interface capture and pcap file reading.
Extracts NetFlow-style features for ML analysis.
"""

import logging
import os
import queue
import time
from typing import Iterable, Iterator, Optional, Dict, Any, List, Tuple
from dataclasses import dataclass
from collections import defaultdict
import struct
import socket

try:
    from scapy.all import AsyncSniffer, PcapReader, IP, TCP, UDP, ICMP, Raw
except ImportError:
    raise ImportError("Scapy not installed. Install with: pip install scapy")
from scapy.error import Scapy_Exception

from src.detection_agent import FlowFeatures

logger = logging.getLogger(__name__)


class PcapReadError(ValueError):
    """Raised when a capture file exists but can't be read as pcap/pcapng."""


@dataclass
class PacketMetadata:
    """Metadata extracted from a single packet."""
    timestamp: float
    src_ip: str
    dst_ip: str
    protocol: int
    src_port: int
    dst_port: int
    packet_length: int
    flags: Dict[str, bool]
    tcp_window: Optional[int] = None  # TCP header window field; None for non-TCP


class FlowAggregator:
    """
    Aggregates packets into network flows.
    A flow is bidirectional communication between two hosts.
    """

    def __init__(self, timeout: float = 30.0, sweep_interval: float = 1.0):
        """
        Initialize flow aggregator.

        Args:
            timeout: Idle timeout in seconds. A flow with no packets for
                this long is considered complete.
            sweep_interval: Minimum seconds (of capture time) between scans
                of the whole flow table for idle flows. Scanning on every
                packet is O(packets x flows) and very slow on big captures.
        """
        self.flows: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            "packets_fwd": [],
            "packets_bwd": [],
            "timestamps_fwd": [],
            "timestamps_bwd": [],
            "flags_fwd": defaultdict(int),
            "flags_bwd": defaultdict(int),
            "protocol": None,
            "src_ip": None,
            "dst_ip": None,
            "src_port": None,
            "dst_port": None,
            "first_timestamp": None,
            "last_timestamp": None,
            "closed": False,
            # Window of the first TCP packet seen in each direction
            "init_win_fwd": None,
            "init_win_bwd": None,
        })
        self.timeout = timeout
        # Latest time seen, taken from packet timestamps so that pcap replay
        # expires flows on capture time rather than wall-clock time
        self.current_time: Optional[float] = None
        self.sweep_interval = sweep_interval
        self._last_sweep: Optional[float] = None
        logger.info(f"FlowAggregator initialized (timeout={timeout}s)")

    def advance_clock(self, timestamp: float) -> None:
        """
        Move the aggregator clock forward (never backward).

        Args:
            timestamp: Packet or wall-clock time in epoch seconds
        """
        if self.current_time is None or timestamp > self.current_time:
            self.current_time = timestamp

    def _is_expired(self, flow: Dict[str, Any]) -> bool:
        """Return True if the flow has been idle longer than the timeout."""
        return (
            self.current_time is not None
            and self.current_time - flow["last_timestamp"] > self.timeout
        )

    @staticmethod
    def is_finished(flow: Dict[str, Any]) -> bool:
        """Return True if the flow's TCP connection was reset or closed."""
        reset = flow["flags_fwd"]["RST"] > 0 or flow["flags_bwd"]["RST"] > 0
        return reset or flow["closed"]

    def flow_key(self, metadata: PacketMetadata) -> str:
        """Return the canonical flow key for a packet."""
        return self._get_flow_key(
            metadata.src_ip,
            metadata.dst_ip,
            metadata.protocol,
            metadata.src_port,
            metadata.dst_port
        )

    def get_expired_flows(self, force: bool = False) -> List[Tuple[str, Dict[str, Any]]]:
        """
        Return flows idle longer than the timeout.

        The full-table scan runs at most once per sweep_interval of capture
        time, unless force is True.

        Args:
            force: Scan even if the sweep interval hasn't elapsed

        Returns:
            List of (flow_key, flow_data)
        """
        if self.current_time is None:
            return []
        if (not force and self._last_sweep is not None
                and self.current_time - self._last_sweep < self.sweep_interval):
            return []

        self._last_sweep = self.current_time
        return [
            (key, flow) for key, flow in self.flows.items()
            if flow["last_timestamp"] is not None and self._is_expired(flow)
        ]

    def _get_flow_key(
        self,
        src_ip: str,
        dst_ip: str,
        protocol: int,
        src_port: int,
        dst_port: int
    ) -> str:
        """
        Generate canonical flow key (same key for both directions).

        Args:
            src_ip: Source IP
            dst_ip: Destination IP
            protocol: IP protocol number
            src_port: Source port
            dst_port: Destination port

        Returns:
            Canonical flow key
        """
        # Normalize IPs and ports for bidirectional flows
        ips = tuple(sorted([src_ip, dst_ip]))
        ports = tuple(sorted([src_port, dst_port]))

        return f"{ips[0]}-{ips[1]}-{protocol}-{ports[0]}-{ports[1]}"

    def add_packet(self, metadata: PacketMetadata) -> str:
        """
        Add a packet to the appropriate flow.

        Args:
            metadata: PacketMetadata object

        Returns:
            The flow key the packet was added to
        """
        key = self.flow_key(metadata)
        flow = self.flows[key]

        # Initialize flow metadata. The sender of the first packet is treated
        # as the initiator, so "forward" means initiator -> responder.
        if flow["first_timestamp"] is None:
            flow["first_timestamp"] = metadata.timestamp
            flow["protocol"] = metadata.protocol
            flow["src_ip"] = metadata.src_ip
            flow["dst_ip"] = metadata.dst_ip
            flow["src_port"] = metadata.src_port
            flow["dst_port"] = metadata.dst_port

        flow["last_timestamp"] = metadata.timestamp

        is_forward = (
            metadata.src_ip == flow["src_ip"]
            and metadata.src_port == flow["src_port"]
        )

        # Record the first TCP window seen in each direction
        if metadata.tcp_window is not None:
            direction = "init_win_fwd" if is_forward else "init_win_bwd"
            if flow[direction] is None:
                flow[direction] = metadata.tcp_window

        # Add packet to appropriate direction
        if is_forward:
            flow["packets_fwd"].append(metadata.packet_length)
            flow["timestamps_fwd"].append(metadata.timestamp)
        else:
            flow["packets_bwd"].append(metadata.packet_length)
            flow["timestamps_bwd"].append(metadata.timestamp)

        # The ACK after both sides sent FIN finishes the TCP teardown
        if (flow["flags_fwd"]["FIN"] > 0 and flow["flags_bwd"]["FIN"] > 0
                and metadata.flags.get("ACK")):
            flow["closed"] = True

        # Aggregate flags
        for flag_name, flag_value in metadata.flags.items():
            if flag_value:
                if is_forward:
                    flow["flags_fwd"][flag_name] += 1
                else:
                    flow["flags_bwd"][flag_name] += 1

        return key

    def get_completed_flows(self) -> Iterator[Tuple[str, Dict[str, Any]]]:
        """
        Yield flows that are complete.

        A flow is complete when either side sends RST, both sides have
        sent FIN and the final ACK has arrived, or it has been idle longer
        than the timeout. Anything left is emitted by get_all_flows() when
        capture ends.

        Yields:
            Tuple of (flow_key, flow_data)
        """
        for key, flow in list(self.flows.items()):
            if flow["last_timestamp"] is None:
                continue

            if self.is_finished(flow) or self._is_expired(flow):
                yield key, flow

    def get_all_flows(self) -> Iterator[Tuple[str, Dict[str, Any]]]:
        """
        Yield every flow that has seen at least one packet, regardless of
        completion criteria. Used to flush state when capture ends.

        Yields:
            Tuple of (flow_key, flow_data)
        """
        for key, flow in list(self.flows.items()):
            if flow["last_timestamp"] is not None:
                yield key, flow

    def clear_completed_flows(self, keys: List[str]) -> None:
        """
        Remove completed flows from memory.

        Args:
            keys: List of flow keys to remove
        """
        for key in keys:
            del self.flows[key]
        logger.debug(f"Cleared {len(keys)} completed flows")


class FlowFeatureExtractor:
    """
    Extracts NetFlow-style features from aggregated flows.
    """

    @staticmethod
    def extract_features(
        src_ip: str,
        dst_ip: str,
        flow_data: Dict[str, Any]
    ) -> Tuple[FlowFeatures, str, str]:
        """
        Extract features from a flow.

        Args:
            src_ip: Initiator IP (the flow's forward direction)
            dst_ip: Responder IP
            flow_data: Flow data from FlowAggregator

        Returns:
            Tuple of (FlowFeatures, src_ip, dst_ip)
        """
        import numpy as np

        # FlowAggregator already stores packets relative to the initiator
        forward_packets = flow_data["packets_fwd"]
        backward_packets = flow_data["packets_bwd"]
        fwd_timestamps = flow_data["timestamps_fwd"]
        bwd_timestamps = flow_data["timestamps_bwd"]
        flags_fwd = flow_data["flags_fwd"]
        flags_bwd = flow_data["flags_bwd"]

        # Basic metrics
        flow_duration = flow_data["last_timestamp"] - flow_data["first_timestamp"]
        total_fwd_packets = len(forward_packets)
        total_bwd_packets = len(backward_packets)
        total_fwd_length = sum(forward_packets) if forward_packets else 0
        total_bwd_length = sum(backward_packets) if backward_packets else 0

        # Packet length statistics (forward)
        fwd_pkt_lengths = forward_packets if forward_packets else [0]
        fwd_max = max(fwd_pkt_lengths)
        fwd_min = min(fwd_pkt_lengths)
        fwd_mean = np.mean(fwd_pkt_lengths)
        fwd_std = np.std(fwd_pkt_lengths)

        # Packet length statistics (backward)
        bwd_pkt_lengths = backward_packets if backward_packets else [0]
        bwd_max = max(bwd_pkt_lengths)
        bwd_min = min(bwd_pkt_lengths)
        bwd_mean = np.mean(bwd_pkt_lengths)
        bwd_std = np.std(bwd_pkt_lengths)

        # Inter-arrival time (flow level)
        all_timestamps = sorted(fwd_timestamps + bwd_timestamps)
        if len(all_timestamps) > 1:
            flow_iats = np.diff(all_timestamps)
            flow_iat_mean = np.mean(flow_iats)
            flow_iat_std = np.std(flow_iats)
            flow_iat_max = np.max(flow_iats)
            flow_iat_min = np.min(flow_iats)
        else:
            flow_iats = np.array([])
            flow_iat_mean = flow_iat_std = flow_iat_max = flow_iat_min = 0

        # Forward inter-arrival time
        if len(fwd_timestamps) > 1:
            fwd_iats = np.diff(fwd_timestamps)
            fwd_iat_total = np.sum(fwd_iats)
            fwd_iat_mean = np.mean(fwd_iats)
            fwd_iat_std = np.std(fwd_iats)
            fwd_iat_max = np.max(fwd_iats)
            fwd_iat_min = np.min(fwd_iats)
        else:
            fwd_iat_total = fwd_iat_mean = fwd_iat_std = fwd_iat_max = fwd_iat_min = 0

        # Backward inter-arrival time
        if len(bwd_timestamps) > 1:
            bwd_iats = np.diff(bwd_timestamps)
            bwd_iat_total = np.sum(bwd_iats)
            bwd_iat_mean = np.mean(bwd_iats)
            bwd_iat_std = np.std(bwd_iats)
            bwd_iat_max = np.max(bwd_iats)
            bwd_iat_min = np.min(bwd_iats)
        else:
            bwd_iat_total = bwd_iat_mean = bwd_iat_std = bwd_iat_max = bwd_iat_min = 0

        # Flags
        fwd_psh = flags_fwd.get("PSH", 0)
        bwd_psh = flags_bwd.get("PSH", 0)
        fwd_urg = flags_fwd.get("URG", 0)
        bwd_urg = flags_bwd.get("URG", 0)
        fwd_rst = flags_fwd.get("RST", 0)
        bwd_rst = flags_bwd.get("RST", 0)
        fwd_syn = flags_fwd.get("SYN", 0)
        bwd_syn = flags_bwd.get("SYN", 0)
        fwd_fin = flags_fwd.get("FIN", 0)
        bwd_fin = flags_bwd.get("FIN", 0)
        fwd_ack = flags_fwd.get("ACK", 0)
        bwd_ack = flags_bwd.get("ACK", 0)
        fwd_cwr = flags_fwd.get("CWR", 0)
        bwd_cwr = flags_bwd.get("CWR", 0)
        fwd_ece = flags_fwd.get("ECE", 0)
        bwd_ece = flags_bwd.get("ECE", 0)

        # Ratio metrics
        down_up_ratio = total_bwd_length / total_fwd_length if total_fwd_length > 0 else 0
        avg_pkt_size = (total_fwd_length + total_bwd_length) / (total_fwd_packets + total_bwd_packets) if (total_fwd_packets + total_bwd_packets) > 0 else 0

        # Initial TCP window per direction; -1 means no TCP packet was seen
        # in that direction (same convention as CICFlowMeter)
        init_fwd_win = flow_data.get("init_win_fwd")
        init_bwd_win = flow_data.get("init_win_bwd")
        init_fwd_win = -1 if init_fwd_win is None else init_fwd_win
        init_bwd_win = -1 if init_bwd_win is None else init_bwd_win

        # Active/Idle times (simplified)
        active_times = flow_iats if len(flow_iats) > 0 else [0]
        active_mean = np.mean(active_times[::2]) if len(active_times) > 1 else 0
        active_std = np.std(active_times[::2]) if len(active_times) > 1 else 0
        active_max = np.max(active_times[::2]) if len(active_times) > 1 else 0
        active_min = np.min(active_times[::2]) if len(active_times) > 1 else 0

        idle_times = active_times[1::2] if len(active_times) > 1 else [0]
        idle_mean = np.mean(idle_times) if len(idle_times) > 0 else 0
        idle_std = np.std(idle_times) if len(idle_times) > 0 else 0
        idle_max = np.max(idle_times) if len(idle_times) > 0 else 0
        idle_min = np.min(idle_times) if len(idle_times) > 0 else 0

        features = FlowFeatures(
            duration=flow_duration,
            protocol=flow_data["protocol"],
            src_port=flow_data["src_port"],
            dst_port=flow_data["dst_port"],
            flow_duration=flow_duration,
            total_fwd_packets=total_fwd_packets,
            total_bwd_packets=total_bwd_packets,
            total_length_of_fwd_packets=total_fwd_length,
            total_length_of_bwd_packets=total_bwd_length,
            fwd_packet_length_max=fwd_max,
            fwd_packet_length_min=fwd_min,
            fwd_packet_length_mean=fwd_mean,
            fwd_packet_length_std=fwd_std,
            bwd_packet_length_max=bwd_max,
            bwd_packet_length_min=bwd_min,
            bwd_packet_length_mean=bwd_mean,
            bwd_packet_length_std=bwd_std,
            flow_iat_mean=flow_iat_mean,
            flow_iat_std=flow_iat_std,
            flow_iat_max=flow_iat_max,
            flow_iat_min=flow_iat_min,
            fwd_iat_total=fwd_iat_total,
            fwd_iat_mean=fwd_iat_mean,
            fwd_iat_std=fwd_iat_std,
            fwd_iat_max=fwd_iat_max,
            fwd_iat_min=fwd_iat_min,
            bwd_iat_total=bwd_iat_total,
            bwd_iat_mean=bwd_iat_mean,
            bwd_iat_std=bwd_iat_std,
            bwd_iat_max=bwd_iat_max,
            bwd_iat_min=bwd_iat_min,
            fwd_psh_flags=fwd_psh,
            bwd_psh_flags=bwd_psh,
            fwd_urg_flags=fwd_urg,
            bwd_urg_flags=bwd_urg,
            fwd_rst_flags=fwd_rst,
            bwd_rst_flags=bwd_rst,
            fwd_syn_flags=fwd_syn,
            bwd_syn_flags=bwd_syn,
            fwd_fin_flags=fwd_fin,
            bwd_fin_flags=bwd_fin,
            fwd_cwr_flags=fwd_cwr,
            bwd_cwr_flags=bwd_cwr,
            fwd_ece_flags=fwd_ece,
            bwd_ece_flags=bwd_ece,
            fwd_ack_flags=fwd_ack,
            bwd_ack_flags=bwd_ack,
            down_up_ratio=down_up_ratio,
            pkt_size_avg=avg_pkt_size,
            init_fwd_win_byts=init_fwd_win,
            init_bwd_win_byts=init_bwd_win,
            active_mean=active_mean,
            active_std=active_std,
            active_max=active_max,
            active_min=active_min,
            idle_mean=idle_mean,
            idle_std=idle_std,
            idle_max=idle_max,
            idle_min=idle_min,
        )

        return features, src_ip, dst_ip


class PacketCapture:
    """
    Handles packet capture from live interface or pcap files.
    """

    def __init__(self):
        """Initialize packet capture."""
        self.flow_aggregator = FlowAggregator()
        self.feature_extractor = FlowFeatureExtractor()
        logger.info("PacketCapture initialized")

    def _extract_packet_info(self, packet) -> Optional[PacketMetadata]:
        """
        Extract relevant information from a Scapy packet.

        Args:
            packet: Scapy packet object

        Returns:
            PacketMetadata or None if not analyzable
        """
        try:
            if not packet.haslayer(IP):
                return None

            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            protocol = ip_layer.proto
            # Scapy uses EDecimal, which numpy cannot mix with its own types
            timestamp = float(packet.time)

            # Extract ports and flags
            src_port = 0
            tcp_window = None
            dst_port = 0
            flags = {
                "SYN": False, "ACK": False, "FIN": False, "RST": False,
                "PSH": False, "URG": False, "CWR": False, "ECE": False
            }

            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                tcp_window = tcp_layer.window
                flags["SYN"] = bool(tcp_layer.flags & 0x02)
                flags["ACK"] = bool(tcp_layer.flags & 0x10)
                flags["FIN"] = bool(tcp_layer.flags & 0x01)
                flags["RST"] = bool(tcp_layer.flags & 0x04)
                flags["PSH"] = bool(tcp_layer.flags & 0x08)
                flags["URG"] = bool(tcp_layer.flags & 0x20)
                flags["ECE"] = bool(tcp_layer.flags & 0x40)
                flags["CWR"] = bool(tcp_layer.flags & 0x80)

            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                src_port = udp_layer.sport
                dst_port = udp_layer.dport

            elif packet.haslayer(ICMP):
                # ICMP doesn't have ports, use type and code
                icmp_layer = packet[ICMP]
                src_port = icmp_layer.type
                dst_port = icmp_layer.code

            packet_length = len(packet)

            return PacketMetadata(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol,
                src_port=src_port,
                dst_port=dst_port,
                packet_length=packet_length,
                flags=flags,
                tcp_window=tcp_window
            )

        except Exception as e:
            logger.debug(f"Failed to extract packet info: {e}")
            return None

    def read_pcap(
        self,
        pcap_file: str,
        callback=None
    ) -> Iterator[Tuple[FlowFeatures, str, str]]:
        """
        Read and process packets from a pcap file.

        Args:
            pcap_file: Path to pcap file
            callback: Optional callback function for each packet

        Yields:
            Tuple of (FlowFeatures, src_ip, dst_ip) for completed flows

        Raises:
            FileNotFoundError: If the file doesn't exist
            PermissionError: If the file isn't readable
            PcapReadError: If the path is not a regular file or not a
                valid pcap/pcapng capture
        """
        self._check_pcap_path(pcap_file)

        try:
            reader = PcapReader(pcap_file)
        except Scapy_Exception as e:
            raise PcapReadError(
                f"Not a valid pcap/pcapng file: {pcap_file} ({e})"
            ) from None

        packet_count = 0
        # Stream packets one at a time; rdpcap() would load the whole
        # file into memory, which fails on multi-GB captures
        with reader:
            for packet in reader:
                packet_count += 1
                if callback:
                    callback(packet)

                metadata = self._extract_packet_info(packet)
                if metadata:
                    yield from self._process_packet(metadata)

        logger.info(f"Read {packet_count} packets from {pcap_file}")

        # End of file: analyze flows that never met the completion criteria
        yield from self._emit_flows(self.flow_aggregator.get_all_flows())

    @staticmethod
    def _check_pcap_path(pcap_file: str) -> None:
        """
        Fail early with a clear error if the capture file can't be opened.

        Args:
            pcap_file: Path to the capture file

        Raises:
            FileNotFoundError, PermissionError, PcapReadError
        """
        if not os.path.exists(pcap_file):
            raise FileNotFoundError(f"Capture file not found: {pcap_file}")
        if not os.path.isfile(pcap_file):
            raise PcapReadError(f"Capture path is not a regular file: {pcap_file}")
        if not os.access(pcap_file, os.R_OK):
            raise PermissionError(f"Capture file is not readable: {pcap_file}")
        if os.path.getsize(pcap_file) == 0:
            raise PcapReadError(f"Capture file is empty: {pcap_file}")

    def _process_packet(
        self,
        metadata: PacketMetadata
    ) -> Iterator[Tuple[FlowFeatures, str, str]]:
        """
        Add a packet to its flow and yield any flows that are now complete.

        Only the packet's own flow is checked for FIN/RST completion; the
        rest of the table is swept for idle flows at most once per
        sweep_interval. This keeps per-packet cost independent of the
        number of open flows.

        Args:
            metadata: PacketMetadata for the incoming packet

        Yields:
            Tuple of (FlowFeatures, src_ip, dst_ip) for completed flows
        """
        aggregator = self.flow_aggregator
        aggregator.advance_clock(metadata.timestamp)
        key = aggregator.flow_key(metadata)

        # A packet arriving after its flow went idle starts a new flow
        # instead of extending the old one
        existing = aggregator.flows.get(key)
        if existing is not None and aggregator._is_expired(existing):
            yield from self._emit_flows([(key, existing)])

        yield from self._emit_flows(aggregator.get_expired_flows())

        aggregator.add_packet(metadata)
        flow = aggregator.flows[key]
        if aggregator.is_finished(flow):
            yield from self._emit_flows([(key, flow)])

    def _emit_flows(
        self,
        flows: Iterable[Tuple[str, Dict[str, Any]]]
    ) -> Iterator[Tuple[FlowFeatures, str, str]]:
        """
        Extract features for the given flows, yield them, and evict them.

        Args:
            flows: (flow_key, flow_data) pairs to emit

        Yields:
            Tuple of (FlowFeatures, src_ip, dst_ip) for each flow
        """
        done_keys = []
        for flow_key, flow_data in list(flows):
            # Evict even on failure, so a bad flow isn't retried forever
            done_keys.append(flow_key)
            try:
                features, src_ip, dst_ip = self.feature_extractor.extract_features(
                    flow_data["src_ip"], flow_data["dst_ip"], flow_data
                )
            except Exception as e:
                logger.warning(f"Feature extraction failed for flow {flow_key}: {e}")
                continue
            yield features, src_ip, dst_ip

        self.flow_aggregator.clear_completed_flows(done_keys)

    def capture_live(
        self,
        interface: Optional[str] = None,
        packet_count: int = 0,
        callback=None
    ) -> Iterator[Tuple[FlowFeatures, str, str]]:
        """
        Capture packets from a live network interface.

        Args:
            interface: Network interface (e.g., 'eth0'). If None, uses default.
            packet_count: Number of packets to capture (0 = unlimited)
            callback: Optional callback function for each packet

        Yields:
            Tuple of (FlowFeatures, src_ip, dst_ip) for completed flows
        """
        # Sniff in a background thread and hand packets over through a queue,
        # so this generator can yield flows while capture is still running.
        packet_queue: "queue.Queue[Any]" = queue.Queue()
        sniffer = AsyncSniffer(
            iface=interface,
            prn=packet_queue.put,
            count=packet_count if packet_count > 0 else 0,
            store=False
        )

        try:
            logger.info(f"Starting live capture on {interface or 'default interface'}")
            sniffer.start()

            while sniffer.thread.is_alive() or not packet_queue.empty():
                try:
                    packet = packet_queue.get(timeout=1.0)
                except queue.Empty:
                    # No traffic: still expire idle flows on wall-clock time
                    self.flow_aggregator.advance_clock(time.time())
                    yield from self._emit_flows(self.flow_aggregator.get_expired_flows())
                    continue

                if callback:
                    callback(packet)

                metadata = self._extract_packet_info(packet)
                if metadata:
                    yield from self._process_packet(metadata)

            # Capture finished (packet_count reached): flush remaining flows
            yield from self._emit_flows(self.flow_aggregator.get_all_flows())

        except Exception as e:
            logger.error(f"Live capture failed: {e}")
            raise
        finally:
            # `running` stays True if the sniff thread crashed (e.g. no root),
            # and stop() then raises, so check the thread itself.
            if sniffer.thread is not None and sniffer.thread.is_alive():
                sniffer.stop()


# ==================== Example Usage ====================
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    import os

    # Create a sample pcap file path (would come from CIC-IDS2017 or similar)
    sample_pcap = "/tmp/sample.pcap"

    if os.path.exists(sample_pcap):
        capture = PacketCapture()
        print("\nProcessing pcap file...")
        flow_count = 0

        for features, src_ip, dst_ip in capture.read_pcap(sample_pcap):
            print(f"Flow: {src_ip} -> {dst_ip} | "
                  f"Packets: {features.total_fwd_packets}/{features.total_bwd_packets}")
            flow_count += 1

            if flow_count > 5:
                break

        print(f"\nProcessed {flow_count} flows")
    else:
        print(f"Sample pcap file not found at {sample_pcap}")
        print("To test, provide a real pcap file from CIC-IDS2017 or similar dataset")
