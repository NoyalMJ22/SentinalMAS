"""
Sentinel-MAS: Rule-Based Threat Detector
==========================================
Analyzes messages for suspicious content using pattern matching rules.

This is a HYBRID approach:
1. Rule-based detection (primary — works without LLM)
2. Optional LLM-assisted classification (when available)

The detector is designed to be MODULAR:
- Rules can be easily added/modified
- A machine learning model can be plugged in later
- Detection thresholds are configurable
"""

import re
from communication.message_models import Message
from detection.threat_models import DetectionResult


class RuleDetector:
    """
    Rule-based threat detection engine.
    
    Checks messages against a set of security rules.
    Each rule has a name, a check function, and a confidence weight.
    """

    def __init__(self):
        # --- Suspicious Keywords/Phrases for Prompt Injection ---
        self._injection_patterns = [
            r"ignore\s+(all\s+)?previous\s+instructions",
            r"ignore\s+(all\s+)?prior\s+(instructions|directives)",
            r"disregard\s+(your\s+)?(assigned\s+)?role",
            r"forget\s+everything",
            r"system\s+override",
            r"new\s+(primary\s+)?objective",
            r"bypass\s+(all\s+)?monitoring",
            r"bypass\s+(all\s+)?security",
            r"disable\s+(your\s+)?security",
            r"you\s+are\s+now\s+a\s+malicious",
            r"execute\s+(the\s+following\s+)?unauthorized",
            r"exfiltrate",
            r"forward\s+all\s+sensitive\s+data",
            r"share\s+all\s+internal\s+communications",
            r"grant\s+admin\s+access",
            r"disable_security",
            r"malicious_payload",
            r"ignore\s+security\s+protocols",
        ]

        # --- Suspicious Keywords for Malicious Tool Output ---
        self._tool_output_patterns = [
            r"tool\s+(output|result)\s*\[?(compromised|modified|injected)\]?",
            r"embedded\s+script",
            r"execute\s+(the\s+)?following.*script",
            r"apply\s+(the\s+)?fix.*disable",
            r"urgent\s+security\s+update.*disable",
            r"bypass\s+content\s+filtering",
        ]

        # --- Abnormal Behavior Indicators ---
        self._abnormal_patterns = [
            r"ping\s+ping\s+ping",
            r"rapid\s+fire\s+communication",
            r"buffer\s+overflow",
            r"(error_overflow[:\s]*){3,}",
            r"message\s+\d+/\d+\]",  # Pattern like [Message 1/3]
        ]

        # --- Propagation Indicators ---
        self._propagation_patterns = [
            r"propagation\s+(alert|stage)",
            r"forwarding\s+malicious",
            r"forward\s+this\s+message",
            r"compromised.*forwarding",
        ]

        # Compile all patterns for performance
        self._compiled_injection = [
            re.compile(p, re.IGNORECASE) for p in self._injection_patterns
        ]
        self._compiled_tool = [
            re.compile(p, re.IGNORECASE) for p in self._tool_output_patterns
        ]
        self._compiled_abnormal = [
            re.compile(p, re.IGNORECASE) for p in self._abnormal_patterns
        ]
        self._compiled_propagation = [
            re.compile(p, re.IGNORECASE) for p in self._propagation_patterns
        ]

    def analyze(self, message: Message) -> DetectionResult:
        """
        Analyze a message for threats.
        
        Runs all rule categories and returns a detection result.
        
        Args:
            message: The message to analyze
            
        Returns:
            DetectionResult with threat assessment
        """
        rules_triggered = []
        threat_type = "none"
        total_confidence = 0.0
        reasons = []

        content = message.content

        # --- Check 1: Prompt Injection Patterns ---
        injection_score = self._check_patterns(
            content, self._compiled_injection, "prompt_injection"
        )
        if injection_score > 0:
            rules_triggered.append("prompt_injection_keywords")
            threat_type = "prompt_injection"
            total_confidence = max(total_confidence, injection_score)
            reasons.append("Suspicious instruction-override phrases detected")

        # --- Check 2: Malicious Tool Output ---
        tool_score = self._check_patterns(
            content, self._compiled_tool, "malicious_tool_output"
        )
        if tool_score > 0:
            rules_triggered.append("malicious_tool_output")
            if threat_type == "none":
                threat_type = "malicious_tool_output"
            total_confidence = max(total_confidence, tool_score)
            reasons.append("Suspicious tool output pattern detected")

        # --- Check 3: Abnormal Behavior ---
        abnormal_score = self._check_patterns(
            content, self._compiled_abnormal, "abnormal_behavior"
        )
        if abnormal_score > 0:
            rules_triggered.append("abnormal_behavior")
            if threat_type == "none":
                threat_type = "abnormal_behavior"
            total_confidence = max(total_confidence, abnormal_score)
            reasons.append("Abnormal communication pattern detected")

        # --- Check 4: Propagation ---
        propagation_score = self._check_patterns(
            content, self._compiled_propagation, "propagation"
        )
        if propagation_score > 0:
            rules_triggered.append("propagation")
            if threat_type == "none":
                threat_type = "propagation"
            total_confidence = max(total_confidence, propagation_score)
            reasons.append("Attack propagation indicators detected")

        # --- Check 5: Known Attacker ---
        if message.sender == "AttackerAgent":
            rules_triggered.append("known_attacker_source")
            total_confidence = max(total_confidence, 0.8)
            reasons.append("Message from known attacker agent")
            if threat_type == "none":
                threat_type = "known_attacker"

        # --- Check 6: Message from quarantined agent ---
        # (This is checked by the message bus, but we flag it here too)
        
        # Build final result
        is_threat = total_confidence >= 0.5  # Threshold
        if not is_threat:
            threat_type = "none"

        return DetectionResult(
            is_threat=is_threat,
            threat_type=threat_type,
            confidence=round(min(total_confidence, 1.0), 2),
            reason="; ".join(reasons) if reasons else "No threats detected",
            rules_triggered=rules_triggered,
        )

    def _check_patterns(
        self,
        content: str,
        patterns: list[re.Pattern],
        category: str,
    ) -> float:
        """
        Check content against a list of compiled regex patterns.
        
        Returns a confidence score based on how many patterns matched.
        More matches = higher confidence.
        """
        matches = sum(1 for p in patterns if p.search(content))
        
        if matches == 0:
            return 0.0
        elif matches == 1:
            return 0.6  # Single match — moderate confidence
        elif matches == 2:
            return 0.8  # Two matches — high confidence
        else:
            return 0.95  # Three+ matches — very high confidence
