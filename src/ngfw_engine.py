from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from statistics import mean, pstdev
from typing import Deque, Dict, Iterable, List, Set, Tuple


@dataclass(frozen=True)
class Packet:
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    bytes_out: int
    tls_version: str
    ja3_hash: str
    user_id: str
    device_id: str


@dataclass(frozen=True)
class IdentityContext:
    user_id: str
    device_id: str
    user_trust: float  # 0.0-1.0
    device_trust: float  # 0.0-1.0
    mfa_verified: bool
    geo_velocity_risky: bool


@dataclass
class ThreatIntel:
    malicious_ja3: Set[str] = field(default_factory=set)
    blocked_ips: Set[str] = field(default_factory=set)
    suspicious_ports: Set[int] = field(default_factory=lambda: {4444, 3389, 5985})

    def update_from_iocs(
        self,
        ja3_hashes: Iterable[str] = (),
        ips: Iterable[str] = (),
        ports: Iterable[int] = (),
    ) -> None:
        self.malicious_ja3.update(ja3_hashes)
        self.blocked_ips.update(ips)
        self.suspicious_ports.update(ports)


@dataclass
class DetectionResult:
    encrypted_flow_score: float
    anomaly_score: float
    graph_risk_score: float
    identity_risk_score: float
    threat_intel_score: float
    final_risk_score: float
    decision: str
    explanation: str


class OnlineAnomalyDetector:
    """Simple online detector using rolling z-score style logic."""

    def __init__(self, window: int = 100):
        self.window = window
        self._sizes: Deque[int] = deque(maxlen=window)

    def score(self, packet_size: int) -> float:
        self._sizes.append(packet_size)
        if len(self._sizes) < 5:
            return 0.1

        mu = mean(self._sizes)
        sigma = pstdev(self._sizes) or 1.0
        z = abs((packet_size - mu) / sigma)
        return min(1.0, z / 6.0)


class CommunicationGraphMonitor:
    """Tracks east-west communication and flags unusual fan-out."""

    def __init__(self):
        self._edges: Dict[str, Set[str]] = defaultdict(set)

    def score(self, src_ip: str, dst_ip: str) -> float:
        known_neighbors = self._edges[src_ip]
        novelty = 0.8 if dst_ip not in known_neighbors and len(known_neighbors) > 10 else 0.1
        known_neighbors.add(dst_ip)

        fan_out = len(known_neighbors)
        fan_out_score = min(1.0, fan_out / 100.0)
        return min(1.0, max(novelty, fan_out_score))


class NGFWEngine:
    def __init__(self):
        self.intel = ThreatIntel()
        self.anomaly = OnlineAnomalyDetector(window=200)
        self.graph = CommunicationGraphMonitor()

    @staticmethod
    def classify_encrypted_flow(packet: Packet) -> float:
        """
        Lightweight encrypted-flow classification surrogate.
        Returns 0.0-1.0 malicious likelihood.
        """
        score = 0.0
        if packet.tls_version in {"TLS1.0", "TLS1.1"}:
            score += 0.25
        if packet.protocol.upper() == "QUIC" and packet.dst_port not in {443, 8443}:
            score += 0.25
        if packet.bytes_out > 2_000_000:
            score += 0.2
        if packet.dst_port in {22, 3389, 4444, 5985}:
            score += 0.2
        if packet.ja3_hash.startswith("dead"):
            score += 0.2
        return min(1.0, score)

    @staticmethod
    def compute_identity_risk(identity: IdentityContext) -> float:
        risk = (1 - identity.user_trust) * 0.4 + (1 - identity.device_trust) * 0.4
        if not identity.mfa_verified:
            risk += 0.15
        if identity.geo_velocity_risky:
            risk += 0.15
        return min(1.0, risk)

    def compute_threat_intel_score(self, packet: Packet) -> float:
        score = 0.0
        if packet.ja3_hash in self.intel.malicious_ja3:
            score += 0.6
        if packet.dst_ip in self.intel.blocked_ips:
            score += 0.6
        if packet.dst_port in self.intel.suspicious_ports:
            score += 0.2
        return min(1.0, score)

    def evaluate_packet(self, packet: Packet, identity: IdentityContext) -> DetectionResult:
        encrypted_flow_score = self.classify_encrypted_flow(packet)
        anomaly_score = self.anomaly.score(packet.bytes_out)
        graph_risk_score = self.graph.score(packet.src_ip, packet.dst_ip)
        identity_risk_score = self.compute_identity_risk(identity)
        threat_intel_score = self.compute_threat_intel_score(packet)

        final = (
            encrypted_flow_score * 0.25
            + anomaly_score * 0.2
            + graph_risk_score * 0.15
            + identity_risk_score * 0.2
            + threat_intel_score * 0.2
        )

        if final >= 0.8:
            decision = "block"
        elif final >= 0.6:
            decision = "quarantine"
        elif final >= 0.4:
            decision = "step_up_auth"
        else:
            decision = "allow"

        explanation = (
            f"risk={final:.2f}; encrypted={encrypted_flow_score:.2f}; "
            f"anomaly={anomaly_score:.2f}; graph={graph_risk_score:.2f}; "
            f"identity={identity_risk_score:.2f}; intel={threat_intel_score:.2f}"
        )

        return DetectionResult(
            encrypted_flow_score=encrypted_flow_score,
            anomaly_score=anomaly_score,
            graph_risk_score=graph_risk_score,
            identity_risk_score=identity_risk_score,
            threat_intel_score=threat_intel_score,
            final_risk_score=final,
            decision=decision,
            explanation=explanation,
        )

    @staticmethod
    def federated_average(weight_updates: List[Tuple[int, Dict[str, float]]]) -> Dict[str, float]:
        """Federated aggregation by weighted mean on sample count."""
        if not weight_updates:
            return {}

        totals: Dict[str, float] = defaultdict(float)
        total_samples = 0

        for sample_count, weights in weight_updates:
            total_samples += sample_count
            for key, value in weights.items():
                totals[key] += value * sample_count

        if total_samples == 0:
            return {k: 0.0 for k in totals}
        return {k: v / total_samples for k, v in totals.items()}

    @staticmethod
    def soar_actions(decision: str) -> List[str]:
        mapping = {
            "allow": ["log_traffic"],
            "step_up_auth": ["trigger_mfa", "limit_session_scope", "log_alert"],
            "quarantine": ["move_to_quarantine_vlan", "open_ticket", "notify_soc"],
            "block": ["drop_flow", "isolate_host", "push_ioc_update", "notify_soc_high"],
        }
        return mapping.get(decision, ["log_alert"])
