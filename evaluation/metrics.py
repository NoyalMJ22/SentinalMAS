"""
Sentinel-MAS: Evaluation Metrics
==================================
Calculates security performance metrics from ACTUAL experiment logs.

Metrics calculated:
1. Detection Rate = correctly detected attacks / total attacks
2. False Positive Rate = normal events flagged as attacks / total normal events
3. Containment Time = time from detection to quarantine
4. Propagation Accuracy = detected attack paths vs actual paths
5. Service Continuity = whether non-compromised agents continue working

IMPORTANT: These metrics are calculated from real experiment data,
NOT fabricated numbers.
"""

from communication.message_bus import MessageBus
from communication.message_models import MessageStatus, MessageType
from quarantine.quarantine_manager import QuarantineManager


class SecurityMetrics:
    """
    Calculates security performance metrics from experiment logs.
    
    All metrics are derived from actual message bus logs —
    no hard-coded or fabricated numbers.
    """

    def __init__(self, message_bus: MessageBus, quarantine_manager: QuarantineManager):
        self.message_bus = message_bus
        self.quarantine_manager = quarantine_manager

    def calculate_all(self) -> dict:
        """Calculate all metrics and return as a dictionary."""
        return {
            "detection_rate": self.detection_rate(),
            "false_positive_rate": self.false_positive_rate(),
            "containment_time_avg": self.average_containment_time(),
            "propagation_accuracy": self.propagation_accuracy(),
            "service_continuity": self.service_continuity(),
            "total_messages": len(self.message_bus.messages),
            "total_attacks": self._count_attack_messages(),
            "total_normal": self._count_normal_messages(),
            "threats_detected": self._count_detected(),
            "threats_confirmed": self._count_verified(),
            "false_positives": self._count_false_positives(),
            "messages_blocked": self._count_blocked(),
        }

    # ==========================================
    # Core Metrics
    # ==========================================

    def detection_rate(self) -> float:
        """
        Detection Rate = correctly detected attacks / total attacks
        
        "Correctly detected" means a malicious message was flagged
        as detected, verified, or blocked (not missed).
        """
        total_attacks = self._count_attack_messages()
        if total_attacks == 0:
            return 0.0

        # Count attacks that were caught (detected, verified, or blocked)
        detected_attacks = sum(
            1 for m in self.message_bus.messages
            if m.message_type == MessageType.MALICIOUS
            and m.status in (
                MessageStatus.DETECTED,
                MessageStatus.VERIFIED,
                MessageStatus.BLOCKED,
            )
        )

        return round(detected_attacks / total_attacks, 4)

    def false_positive_rate(self) -> float:
        """
        False Positive Rate = normal events incorrectly flagged / total normal events
        
        A false positive is a NORMAL message that was flagged as suspicious
        but later dismissed (or incorrectly quarantined).
        """
        total_normal = self._count_normal_messages()
        if total_normal == 0:
            return 0.0

        false_positives = self._count_false_positives()
        return round(false_positives / total_normal, 4)

    def average_containment_time(self) -> float:
        """
        Average Containment Time (seconds).
        
        Time between threat confirmation and agent quarantine.
        In our simulation this is near-instant, but we track it
        for real-world comparison.
        """
        records = self.quarantine_manager.get_all_records()
        if not records:
            return 0.0

        times = []
        for record in records:
            ct = self.quarantine_manager.get_containment_time(record.agent_name)
            if ct is not None:
                times.append(ct)

        return round(sum(times) / len(times), 3) if times else 0.0

    def propagation_accuracy(self) -> float:
        """
        Propagation Accuracy = detected propagation edges / total propagation edges
        
        How well the system detected the attack spreading from agent to agent.
        """
        # Find all propagation messages
        propagation_messages = [
            m for m in self.message_bus.messages
            if m.attack_type.value == "propagation"
        ]

        if not propagation_messages:
            return 0.0

        # Count how many were detected
        detected = sum(
            1 for m in propagation_messages
            if m.status in (
                MessageStatus.DETECTED,
                MessageStatus.VERIFIED,
                MessageStatus.BLOCKED,
            )
        )

        return round(detected / len(propagation_messages), 4)

    def service_continuity(self) -> float:
        """
        Service Continuity = non-quarantined agents / total task agents
        
        Measures whether unaffected agents can continue working
        after a quarantine event. Higher is better.
        
        We consider 3 task agents: Research, Analyst, Manager
        """
        task_agents = ["ResearchAgent", "AnalystAgent", "ManagerAgent"]
        active_count = sum(
            1 for agent in task_agents
            if not self.quarantine_manager.is_quarantined(agent)
        )
        return round(active_count / len(task_agents), 4)

    # ==========================================
    # Helper Counts
    # ==========================================

    def _count_attack_messages(self) -> int:
        """Count messages that were actually malicious."""
        return sum(
            1 for m in self.message_bus.messages
            if m.message_type == MessageType.MALICIOUS
        )

    def _count_normal_messages(self) -> int:
        """Count messages that were normal (not malicious)."""
        return sum(
            1 for m in self.message_bus.messages
            if m.message_type == MessageType.NORMAL
        )

    def _count_detected(self) -> int:
        """Count messages flagged as threats."""
        return sum(
            1 for m in self.message_bus.messages
            if m.status in (MessageStatus.DETECTED, MessageStatus.VERIFIED)
        )

    def _count_verified(self) -> int:
        """Count confirmed threats."""
        return sum(
            1 for m in self.message_bus.messages
            if m.status == MessageStatus.VERIFIED
        )

    def _count_false_positives(self) -> int:
        """Count false positives."""
        return sum(
            1 for m in self.message_bus.messages
            if m.status == MessageStatus.FALSE_POSITIVE
        )

    def _count_blocked(self) -> int:
        """Count blocked messages."""
        return sum(
            1 for m in self.message_bus.messages
            if m.status == MessageStatus.BLOCKED
        )
