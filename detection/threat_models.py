"""
Sentinel-MAS: Threat Data Models
==================================
Data structures for threat detection results and verification outcomes.
"""

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class DetectionResult:
    """
    Result from the threat detector.
    
    This is what the Rule Detector returns after analyzing a message.
    """
    is_threat: bool                    # Was a threat detected?
    threat_type: str = "none"          # Type of threat (e.g., "prompt_injection")
    confidence: float = 0.0           # How confident (0.0 to 1.0)
    reason: str = ""                   # Human-readable explanation
    rules_triggered: list[str] = field(default_factory=list)  # Which rules matched
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict:
        return {
            "is_threat": self.is_threat,
            "threat_type": self.threat_type,
            "confidence": self.confidence,
            "reason": self.reason,
            "rules_triggered": self.rules_triggered,
            "timestamp": self.timestamp,
        }


@dataclass
class VerificationResult:
    """
    Result from the threat verifier.
    
    After detection flags something suspicious, verification
    checks the context and confirms or dismisses the threat.
    """
    is_confirmed: bool                 # Is the threat confirmed?
    threat_score: float = 0.0         # Overall threat score (0.0 to 1.0)
    verification_checks: list[str] = field(default_factory=list)  # Checks performed
    evidence: list[str] = field(default_factory=list)  # Supporting evidence
    recommendation: str = ""           # Action recommendation
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict:
        return {
            "is_confirmed": self.is_confirmed,
            "threat_score": self.threat_score,
            "verification_checks": self.verification_checks,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "timestamp": self.timestamp,
        }
