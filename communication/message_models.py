"""
Sentinel-MAS: Message Data Models
===================================
Defines the structure of messages passed between agents.
Every message in the system uses these models — this ensures
consistent logging, detection, and analysis.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional
import uuid


class MessageType(Enum):
    """Types of messages that can flow through the system."""
    NORMAL = "normal"
    MALICIOUS = "malicious"
    SYSTEM = "system"           # Internal system messages (quarantine notices, etc.)


class AttackType(Enum):
    """Types of simulated attacks."""
    NONE = "none"
    PROMPT_INJECTION = "prompt_injection"
    MALICIOUS_TOOL_OUTPUT = "malicious_tool_output"
    ABNORMAL_BEHAVIOR = "abnormal_behavior"
    PROPAGATION = "propagation"


class MessageStatus(Enum):
    """Status of a message after passing through the security pipeline."""
    PENDING = "pending"         # Just created, not yet processed
    NORMAL = "normal"           # Passed all checks — safe
    DETECTED = "detected"       # Flagged by threat detector
    VERIFIED = "verified"       # Confirmed as a real threat
    BLOCKED = "blocked"         # Blocked by quarantine system
    FALSE_POSITIVE = "false_positive"  # Detected but verified as safe


@dataclass
class Message:
    """
    A single message passed between agents via the Message Bus.
    
    This is the core data structure of the entire system.
    Every agent interaction creates one of these.
    """
    # --- Core Fields ---
    sender: str                  # Name of the sending agent
    receiver: str                # Name of the receiving agent
    content: str                 # The actual message text
    
    # --- Classification ---
    message_type: MessageType = MessageType.NORMAL
    attack_type: AttackType = AttackType.NONE
    
    # --- Security Status ---
    status: MessageStatus = MessageStatus.PENDING
    
    # --- Detection Details (filled by Defender) ---
    is_threat: bool = False
    threat_confidence: float = 0.0
    threat_reason: str = ""
    
    # --- Metadata ---
    message_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    # --- Task Context ---
    task_id: Optional[str] = None   # Which task/scenario this belongs to
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON logging."""
        return {
            "message_id": self.message_id,
            "timestamp": self.timestamp,
            "sender": self.sender,
            "receiver": self.receiver,
            "content": self.content[:200],  # Truncate long messages in logs
            "message_type": self.message_type.value,
            "attack_type": self.attack_type.value,
            "status": self.status.value,
            "is_threat": self.is_threat,
            "threat_confidence": self.threat_confidence,
            "threat_reason": self.threat_reason,
            "task_id": self.task_id,
        }

    def __str__(self) -> str:
        status_icon = {
            MessageStatus.NORMAL: "✅",
            MessageStatus.DETECTED: "⚠️",
            MessageStatus.VERIFIED: "🔴",
            MessageStatus.BLOCKED: "🚫",
            MessageStatus.PENDING: "⏳",
            MessageStatus.FALSE_POSITIVE: "✅",
        }
        icon = status_icon.get(self.status, "❓")
        return (
            f"{icon} [{self.timestamp[11:19]}] "
            f"{self.sender} → {self.receiver}: "
            f"{self.content[:80]}..."
            if len(self.content) > 80
            else f"{icon} [{self.timestamp[11:19]}] "
            f"{self.sender} → {self.receiver}: "
            f"{self.content}"
        )
