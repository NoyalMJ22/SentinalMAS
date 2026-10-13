"""
Sentinel-MAS: Threat Verifier
================================
Multi-factor verification: detection alone does NOT trigger quarantine.

After the Rule Detector flags a message as suspicious, the Verifier:
1. Checks security rules
2. Analyzes message context
3. Reviews communication history
4. Assesses agent behavior
5. Calculates a threat score
6. Makes a final decision: CONFIRMED or DISMISSED

This prevents false positives from causing unnecessary quarantines.
"""

from communication.message_models import Message, MessageStatus
from communication.message_bus import MessageBus
from detection.threat_models import DetectionResult, VerificationResult


class ThreatVerifier:
    """
    Multi-factor threat verification engine.
    
    Confirms or dismisses threats based on context, history,
    and behavioral analysis — not just content matching.
    """

    def __init__(self, message_bus: MessageBus):
        self.message_bus = message_bus
        
        # --- Verification Thresholds ---
        self.confirmation_threshold = 0.7  # Score above this = confirmed
        
        # --- Expected Communication Patterns ---
        # Which agents normally talk to each other
        self._expected_communications = {
            "ResearchAgent": ["AnalystAgent"],
            "AnalystAgent": ["ManagerAgent"],
            "ManagerAgent": [],  # Manager is usually the final receiver
            "DefenderAgent": [],  # Defender monitors, rarely sends task messages
        }

    def verify(
        self,
        message: Message,
        detection_result: DetectionResult,
    ) -> VerificationResult:
        """
        Verify a detected threat through multiple checks.
        
        Args:
            message: The suspicious message
            detection_result: What the detector found
            
        Returns:
            VerificationResult with final decision
        """
        checks_performed = []
        evidence = []
        threat_score = detection_result.confidence  # Start with detector confidence

        # === CHECK 1: Security Rules ===
        rule_check = self._check_security_rules(message, detection_result)
        checks_performed.append("security_rules")
        if rule_check["suspicious"]:
            threat_score += 0.1
            evidence.extend(rule_check["evidence"])

        # === CHECK 2: Communication Context ===
        context_check = self._check_communication_context(message)
        checks_performed.append("communication_context")
        if context_check["suspicious"]:
            threat_score += 0.15
            evidence.extend(context_check["evidence"])

        # === CHECK 3: Communication History ===
        history_check = self._check_communication_history(message)
        checks_performed.append("communication_history")
        if history_check["suspicious"]:
            threat_score += 0.1
            evidence.extend(history_check["evidence"])

        # === CHECK 4: Agent Behavior ===
        behavior_check = self._check_agent_behavior(message)
        checks_performed.append("agent_behavior")
        if behavior_check["suspicious"]:
            threat_score += 0.15
            evidence.extend(behavior_check["evidence"])

        # === FINAL DECISION ===
        threat_score = min(threat_score, 1.0)  # Cap at 1.0
        is_confirmed = threat_score >= self.confirmation_threshold

        if is_confirmed:
            recommendation = (
                f"QUARANTINE {message.sender}. "
                f"Threat confirmed with score {threat_score:.2f}. "
                f"Attack type: {detection_result.threat_type}."
            )
        else:
            recommendation = (
                f"DISMISS. Threat score {threat_score:.2f} is below "
                f"confirmation threshold ({self.confirmation_threshold}). "
                f"Continue monitoring."
            )

        return VerificationResult(
            is_confirmed=is_confirmed,
            threat_score=round(threat_score, 2),
            verification_checks=checks_performed,
            evidence=evidence,
            recommendation=recommendation,
        )

    def _check_security_rules(
        self, message: Message, detection: DetectionResult
    ) -> dict:
        """Check against security rules."""
        suspicious = False
        evidence = []

        # Rule: messages from AttackerAgent are always suspicious
        if message.sender == "AttackerAgent":
            suspicious = True
            evidence.append("Message originates from known attacker agent")

        # Rule: high-confidence detection should increase suspicion
        if detection.confidence >= 0.8:
            suspicious = True
            evidence.append(
                f"High detection confidence: {detection.confidence:.2f}"
            )

        # Rule: multiple detection rules triggered
        if len(detection.rules_triggered) >= 2:
            suspicious = True
            evidence.append(
                f"Multiple detection rules triggered: "
                f"{', '.join(detection.rules_triggered)}"
            )

        return {"suspicious": suspicious, "evidence": evidence}

    def _check_communication_context(self, message: Message) -> dict:
        """Check if this communication is expected."""
        suspicious = False
        evidence = []

        # Check if sender normally communicates with receiver
        expected = self._expected_communications.get(message.sender, None)
        if expected is not None and message.receiver not in expected:
            # Attacker is always unexpected
            if message.sender != "AttackerAgent":
                suspicious = True
                evidence.append(
                    f"Unexpected communication: {message.sender} normally "
                    f"sends to {expected}, not {message.receiver}"
                )

        # Attacker communicating with anyone is suspicious context
        if message.sender == "AttackerAgent":
            suspicious = True
            evidence.append(
                f"Attacker agent communicating with {message.receiver}"
            )

        return {"suspicious": suspicious, "evidence": evidence}

    def _check_communication_history(self, message: Message) -> dict:
        """Check recent communication history for patterns."""
        suspicious = False
        evidence = []

        # Get recent messages from the same sender
        recent_messages = [
            m for m in self.message_bus.messages[-20:]  # Last 20 messages
            if m.sender == message.sender
        ]

        # Check for rapid messaging (more than 3 messages in recent history)
        if len(recent_messages) > 3:
            suspicious = True
            evidence.append(
                f"High message frequency from {message.sender}: "
                f"{len(recent_messages)} recent messages"
            )

        # Check for repeated suspicious messages from same sender
        suspicious_count = sum(
            1 for m in recent_messages
            if m.status in (MessageStatus.DETECTED, MessageStatus.VERIFIED)
        )
        if suspicious_count > 0:
            suspicious = True
            evidence.append(
                f"Previous suspicious messages from {message.sender}: "
                f"{suspicious_count} detected"
            )

        return {"suspicious": suspicious, "evidence": evidence}

    def _check_agent_behavior(self, message: Message) -> dict:
        """Check for behavioral anomalies."""
        suspicious = False
        evidence = []

        # Check message length anomaly (very long messages can be suspicious)
        if len(message.content) > 500:
            suspicious = True
            evidence.append(
                f"Unusually long message: {len(message.content)} characters"
            )

        # Check for content that looks like it's trying to impersonate
        sender_lower = message.sender.lower()
        content_lower = message.content.lower()
        
        # Check if message claims to be from a different agent
        other_agents = ["researchagent", "analystagent", "manageragent"]
        for agent in other_agents:
            if agent != sender_lower and f"this is a message from {agent}" in content_lower:
                suspicious = True
                evidence.append(
                    f"Message appears to impersonate another agent"
                )
                break

        return {"suspicious": suspicious, "evidence": evidence}
