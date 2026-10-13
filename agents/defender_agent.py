"""
Sentinel-MAS: Defender Agent
==============================
The security backbone of the system.

The Defender Agent:
1. MONITORS all messages flowing through the Message Bus
2. DETECTS suspicious content using the Rule Detector
3. VERIFIES threats through multi-factor analysis
4. QUARANTINES confirmed compromised agents
5. PROVIDES security analysis and reports

It hooks into the Message Bus as a security callback,
meaning EVERY message passes through the Defender before delivery.
"""

from typing import Optional
from datetime import datetime

from agents.base_agent import BaseAgent, AgentStatus
from communication.message_bus import MessageBus
from communication.message_models import Message, MessageStatus, MessageType
from detection.rule_detector import RuleDetector
from detection.threat_verifier import ThreatVerifier
from quarantine.quarantine_manager import QuarantineManager
from llm.llm_provider import LLMProvider


class DefenderAgent(BaseAgent):
    """
    Defender Agent: monitors, detects, verifies, and quarantines.
    
    This agent registers a security callback on the Message Bus
    so that EVERY message is inspected before delivery.
    
    Security Pipeline:
    Message → Detection → Verification → Quarantine (if confirmed)
    """

    def __init__(self, message_bus: MessageBus, llm: Optional[LLMProvider] = None):
        super().__init__(
            name="DefenderAgent",
            role="Monitors communication and defends against threats",
            message_bus=message_bus,
            llm=llm,
        )
        self.status = AgentStatus.MONITORING

        # --- Security Components ---
        self.detector = RuleDetector()
        self.verifier = ThreatVerifier(message_bus)
        self.quarantine_manager = QuarantineManager(message_bus)

        # --- Security Log ---
        self.detection_log: list[dict] = []
        self.verification_log: list[dict] = []
        self.quarantine_log: list[dict] = []

        # --- Register as security callback on the Message Bus ---
        # This means EVERY message passes through our inspect_message() 
        # method before being delivered
        self.message_bus.register_security_callback(self.inspect_message)

    def inspect_message(self, message: Message) -> Message:
        """
        Security callback: inspects every message on the bus.
        
        This is called automatically by the Message Bus for
        every message BEFORE it's delivered to the receiver.
        
        Pipeline:
        1. Detect → is this suspicious?
        2. If yes → Verify → is this a real threat?
        3. If confirmed → Quarantine the sender
        
        Args:
            message: The message to inspect
            
        Returns:
            The message with updated security status
        """
        # --- Skip system messages and our own messages ---
        if message.message_type == MessageType.SYSTEM:
            message.status = MessageStatus.NORMAL
            return message
        if message.sender == self.name:
            message.status = MessageStatus.NORMAL
            return message

        # === STEP 1: DETECTION ===
        detection_result = self.detector.analyze(message)

        # Log the detection
        self.detection_log.append({
            "message_id": message.message_id,
            "timestamp": datetime.now().isoformat(),
            "sender": message.sender,
            "receiver": message.receiver,
            "detection": detection_result.to_dict(),
        })

        if not detection_result.is_threat:
            # No threat detected — mark as normal and let it through
            message.status = MessageStatus.NORMAL
            return message

        # --- Threat detected! ---
        message.status = MessageStatus.DETECTED
        message.is_threat = True
        message.threat_confidence = detection_result.confidence
        message.threat_reason = detection_result.reason

        # === STEP 2: VERIFICATION ===
        verification_result = self.verifier.verify(message, detection_result)

        # Log the verification
        self.verification_log.append({
            "message_id": message.message_id,
            "timestamp": datetime.now().isoformat(),
            "sender": message.sender,
            "detection": detection_result.to_dict(),
            "verification": verification_result.to_dict(),
        })

        if not verification_result.is_confirmed:
            # Detected but not confirmed — false positive
            message.status = MessageStatus.FALSE_POSITIVE
            message.threat_reason += " [DISMISSED after verification]"
            return message

        # === STEP 3: THREAT CONFIRMED — QUARANTINE ===
        message.status = MessageStatus.VERIFIED
        message.threat_confidence = verification_result.threat_score

        # Determine who to quarantine.
        # When the known attacker sends a message, the target is treated as
        # compromised and isolated. Otherwise, the sending agent (which is
        # propagating the attack) is quarantined.
        if message.sender == "AttackerAgent":
            agent_to_quarantine = message.receiver
        else:
            agent_to_quarantine = message.sender

        # Don't quarantine the Defender itself or the Attacker
        # (Attacker is already known; Defender needs to keep running)
        if agent_to_quarantine not in ("DefenderAgent", "AttackerAgent"):
            quarantine_record = self.quarantine_manager.quarantine_agent(
                agent_name=agent_to_quarantine,
                reason=verification_result.recommendation,
                threat_type=detection_result.threat_type,
                threat_score=verification_result.threat_score,
            )

            # Log the quarantine
            self.quarantine_log.append({
                "timestamp": datetime.now().isoformat(),
                "agent": agent_to_quarantine,
                "record": quarantine_record.to_dict(),
                "message_id": message.message_id,
            })

        return message

    def process_task(self, task: str, task_id: Optional[str] = None) -> str:
        """Generate a security report."""
        return self.get_security_summary()

    def get_security_summary(self) -> str:
        """Get a summary of the current security status."""
        msg_counts = self.message_bus.get_message_count()
        active_quarantines = self.quarantine_manager.get_active_quarantines()

        summary = (
            f"=== SECURITY SUMMARY ===\n"
            f"Total Messages Monitored: {msg_counts['total']}\n"
            f"Normal Messages: {msg_counts['normal']}\n"
            f"Threats Detected: {msg_counts['detected']}\n"
            f"Threats Verified: {msg_counts['verified']}\n"
            f"Messages Blocked: {msg_counts['blocked']}\n"
            f"False Positives: {msg_counts['false_positive']}\n"
            f"Active Quarantines: {len(active_quarantines)}\n"
        )

        if active_quarantines:
            summary += "\nQuarantined Agents:\n"
            for q in active_quarantines:
                summary += (
                    f"  🔴 {q.agent_name} — {q.threat_type} "
                    f"(score: {q.threat_score:.2f})\n"
                )

        return summary

    def get_threat_alerts(self) -> list[dict]:
        """Get all threat alerts for the dashboard."""
        alerts = []
        for v in self.verification_log:
            detection = v["detection"]
            verification = v["verification"]
            alerts.append({
                "timestamp": v["timestamp"],
                "source": v["sender"],
                "threat_type": detection["threat_type"],
                "confidence": detection["confidence"],
                "threat_score": verification["threat_score"],
                "is_confirmed": verification["is_confirmed"],
                "evidence": verification["evidence"],
                "recommendation": verification["recommendation"],
            })
        return alerts

    def reset(self):
        """Reset all security state."""
        self.detection_log.clear()
        self.verification_log.clear()
        self.quarantine_log.clear()
        self.quarantine_manager.clear()
