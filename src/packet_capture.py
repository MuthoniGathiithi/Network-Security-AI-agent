"""
Packet Capture and Processing Module

Handles both live network interface capture and pcap file reading.
Extracts NetFlow-style features for ML analysis.
"""

import logging
from typing import Iterator, Optional, Dict, Any, List, Tuple
from dataclasses import dataclass
from collections import defaultdict
import struct
import socket

try:
    from scapy.all import sniff, rdpcap, IP, TCP, UDP, ICMP, Raw
except ImportError:
    raise ImportError("Scapy not installed. Install with: pip install scapy")

from src.detection_agent import FlowFeatures

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


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
    is_forward: bool  # True if forward, False if backward


class FlowAggregator:
    """
    Aggregates packets into network flows.
    A flow is bidirectional communication between two hosts.
    """

    def __init__(self, timeout: float = 30.0):
        """
        Initialize flow aggregator.

        Args:
            timeout: Flow timeout in seconds
        """
        self.flows: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            "packets_fwd": [],
            "packets_bwd": [],
            "timestamps_fwd": [],
            "timestamps_bwd": [],
            "flags_fwd": defaultdict(int),
            "flags_bwd": defaultdict(int),
            "protocol": None,
            "src_port": None,
            "dst_port": None,
            "first_timestamp": None,
            "last_timestamp": None,
        })
        self.timeout = timeout
        logger.info(f"FlowAggregator initialized (timeout={timeout}s)")

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

    def add_packet(self, metadata: PacketMetadata) -> None:
        """
        Add a packet to the appropriate flow.

        Args:
            metadata: PacketMetadata object
        """
        key = self._get_flow_key(
            metadata.src_ip,
            metadata.dst_ip,
            metadata.protocol,
            metadata.src_port,
            metadata.dst_port
        )

        flow = self.flows[key]

        # Initialize flow metadata
        if flow["first_timestamp"] is None:
            flow["first_timestamp"] = metadata.timestamp
            flow["protocol"] = metadata.protocol
            flow["src_port"] = metadata.src_port
            flow["dst_port"] = metadata.dst_port

        flow["last_timestamp"] = metadata.timestamp

        # Add packet to appropriate direction
        if metadata.is_forward:
            flow["packets_fwd"].append(metadata.packet_length)
            flow["timestamps_fwd"].append(metadata.timestamp)
        else:
            flow["packets_bwd"].append(metadata.packet_length)
            flow["timestamps_bwd"].append(metadata.timestamp)

        # Aggregate flags
        for flag_name, flag_value in metadata.flags.items():
            if flag_value:
                if metadata.is_forward:
                    flow["flags_fwd"][flag_name] += 1
                else:
                    flow["flags_bwd"][flag_name] += 1

    def get_completed_flows(self) -> Iterator[Tuple[str, Dict[str, Any]]]:
        """
        Yield flows that have exceeded timeout or have significant activity.

        Yields:
            Tuple of (flow_key, flow_data)
        """
        current_time = None

        for key, flow in list(self.flows.items()):
            if flow["last_timestamp"] is None:
                continue

            # Yield flows with activity (at least 1 packet each direction)
            if len(flow["packets_fwd"]) > 0 and len(flow["packets_bwd"]) > 0:
                yield key, flow
            # Yield unidirectional flows after some threshold
            elif (len(flow["packets_fwd"]) + len(flow["packets_bwd"])) > 5:
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
            src_ip: Source IP
            dst_ip: Destination IP
            flow_data: Flow data from FlowAggregator

        Returns:
            Tuple of (FlowFeatures, src_ip, dst_ip)
        """
        import numpy as np

        # Determine original direction (which IP initiated)
        # For simplicity, use alphabetically sorted IP
        if src_ip < dst_ip:
            forward_packets = flow_data["packets_fwd"]
            backward_packets = flow_data["packets_bwd"]
            fwd_timestamps = flow_data["timestamps_fwd"]
            bwd_timestamps = flow_data["timestamps_bwd"]
            flags_fwd = flow_data["flags_fwd"]
            flags_bwd = flow_data["flags_bwd"]
        else:
            forward_packets = flow_data["packets_bwd"]
            backward_packets = flow_data["packets_fwd"]
            fwd_timestamps = flow_data["timestamps_bwd"]
            bwd_timestamps = flow_data["timestamps_fwd"]
            flags_fwd = flow_data["flags_bwd"]
            flags_bwd = flow_data["flags_fwd"]
            # Swap IPs for consistency
            src_ip, dst_ip = dst_ip, src_ip

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

        # Ratio metrics
        down_up_ratio = total_bwd_length / total_fwd_length if total_fwd_length > 0 else 0
        avg_pkt_size = (total_fwd_length + total_bwd_length) / (total_fwd_packets + total_bwd_packets) if (total_fwd_packets + total_bwd_packets) > 0 else 0

        # Window sizes (placeholder)
        init_fwd_win = 65535
        init_bwd_win = 65535

        # Active/Idle times (simplified)
        active_times = flow_iats if len(flow_iats) > 0 else [0]
        active_mean = np.mean(active_times[::2]) if len(active_times) > 1 else 0
        active_std = np.std(active_times[::2]) if len(active_times) > 1 else 0
        active_max = np.max(active_times[::2]) if len(active_times) > 1 else 0
        active_min = np.min(active_times[::2]) if len(active_times) > 1 else 0

        idle_times = active_times[1::2] if len(active_times) > 1 else [0]
        idle_mean = np.mean(idle_times) if idle_times else 0
        idle_std = np.std(idle_times) if idle_times else 0
        idle_max = np.max(idle_times) if idle_times else 0
        idle_min = np.min(idle_times) if idle_times else 0

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
            fwd_cwr_flags=0,
            bwd_cwr_flags=0,
            fwd_ece_flags=0,
            bwd_ece_flags=0,
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
            timestamp = packet.time

            # Extract ports and flags
            src_port = 0
            dst_port = 0
            flags = {
                "SYN": False, "ACK": False, "FIN": False, "RST": False,
                "PSH": False, "URG": False, "CWR": False, "ECE": False
            }

            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                flags["SYN"] = bool(tcp_layer.flags & 0x02)
                flags["ACK"] = bool(tcp_layer.flags & 0x10)
                flags["FIN"] = bool(tcp_layer.flags & 0x01)
                flags["RST"] = bool(tcp_layer.flags & 0x04)
                flags["PSH"] = bool(tcp_layer.flags & 0x08)
                flags["URG"] = bool(tcp_layer.flags & 0x20)

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

            # Determine direction (simple heuristic: lower IP initiates)
            is_forward = src_ip < dst_ip

            return PacketMetadata(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol,
                src_port=src_port,
                dst_port=dst_port,
                packet_length=packet_length,
                flags=flags,
                is_forward=is_forward
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
        """
        try:
            packets = rdpcap(pcap_file)
            logger.info(f"Loaded {len(packets)} packets from {pcap_file}")

            for packet in packets:
                if callback:
                    callback(packet)

                metadata = self._extract_packet_info(packet)
                if metadata:
                    self.flow_aggregator.add_packet(metadata)

                    # Yield completed flows
                    completed_keys = []
                    for flow_key, flow_data in self.flow_aggregator.get_completed_flows():
                        # Extract original IPs from flow key
                        parts = flow_key.split("-")
                        src_ip, dst_ip = parts[0], parts[1]

                        try:
                            features, _, _ = self.feature_extractor.extract_features(
                                src_ip, dst_ip, flow_data
                            )
                            yield features, src_ip, dst_ip
                            completed_keys.append(flow_key)
                        except Exception as e:
                            logger.debug(f"Feature extraction failed: {e}")

                    self.flow_aggregator.clear_completed_flows(completed_keys)

        except Exception as e:
            logger.error(f"Failed to read pcap file: {e}")
            raise

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
        def packet_handler(packet):
            if callback:
                callback(packet)

            metadata = self._extract_packet_info(packet)
            if metadata:
                self.flow_aggregator.add_packet(metadata)

        try:
            logger.info(f"Starting live capture on {interface or 'default interface'}")

            # Note: sniff is blocking. In production, use threading.
            sniff(
                iface=interface,
                prn=packet_handler,
                count=packet_count if packet_count > 0 else 0,
                store=False
            )

        except Exception as e:
            logger.error(f"Live capture failed: {e}")
            raise


# ==================== Example Usage ====================
if __name__ == "__main__":
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
