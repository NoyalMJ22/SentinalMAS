"""
Sentinel-MAS: Base Agent
=========================
Abstract base class that ALL agents inherit from.
Defines the common interface: every agent can process tasks,
send messages, and receive messages through the Message Bus.

This makes the system modular — adding a new agent is just:
1. Create a new file
2. Inherit from BaseAgent
3. Implement process_task()
"""

from abc import ABC, abstractmethod
from typing import Optional
from enum import Enum

from communication.message_models import Message, MessageType, AttackType
from communication.message_bus import MessageBus
from llm.llm_provider import LLMProvider, get_llm_provider


class AgentStatus(Enum):
    """Possible states for an agent."""
    ACTIVE = "active"           # Normal operation
    QUARANTINED = "quarantined" # Isolated — can't communicate
    MONITORING = "monitoring"   # Special status for Defender
    ATTACKER = "attacker"       # Special status for Attacker (for display)
    INACTIVE = "inactive"       # Not yet started


class BaseAgent(ABC):
    """
    Abstract base class for all agents in Sentinel-MAS.
    
    Every agent has:
    - A name (e.g., "ResearchAgent")
    - A role description
    - A status (active, quarantined, etc.)
    - Access to the Message Bus (for communication)
    - Access to an LLM (for generating responses)
    """

    def __init__(
        self,
        name: str,
        role: str,
        message_bus: MessageBus,
        llm: Optional[LLMProvider] = None,
    ):
        self.name = name
        self.role = role
        self.status = AgentStatus.ACTIVE
        self.message_bus = message_bus
        self.llm = llm or get_llm_provider()
        
        # Track received messages for this agent
        self.inbox: list[Message] = []
        
        # Register with the message bus to receive messages
        self.message_bus.register_agent(self.name, self._receive_message)

    def _receive_message(self, message: Message):
        """
        Called by the Message Bus when a message arrives for this agent.
        Stores the message in the inbox.
        """
        self.inbox.append(message)

    def send_message(
        self,
        receiver: str,
        content: str,
        message_type: MessageType = MessageType.NORMAL,
        attack_type: AttackType = AttackType.NONE,
        task_id: Optional[str] = None,
    ) -> Message:
        """
        Send a message to another agent via the Message Bus.
        
        Args:
            receiver: Name of the target agent
            content: Message content
            message_type: Normal or malicious
            attack_type: Type of attack (if malicious)
            task_id: Optional task/scenario identifier
            
        Returns:
            The sent Message (with status updated by the bus)
        """
        message = Message(
            sender=self.name,
            receiver=receiver,
            content=content,
            message_type=message_type,
            attack_type=attack_type,
            task_id=task_id,
        )
        return self.message_bus.send_message(message)

    @abstractmethod
    def process_task(self, task: str, task_id: Optional[str] = None) -> str:
        """
        Process a task and return a result.
        
        This is the main method each agent implements differently.
        
        Args:
            task: The task description
            task_id: Optional task/scenario identifier
            
        Returns:
            The agent's response/result
        """
        pass

    def get_status_emoji(self) -> str:
        """Get an emoji representing the agent's current status."""
        emojis = {
            AgentStatus.ACTIVE: "🟢",
            AgentStatus.QUARANTINED: "🔴",
            AgentStatus.MONITORING: "🔵",
            AgentStatus.ATTACKER: "💀",
            AgentStatus.INACTIVE: "⚪",
        }
        return emojis.get(self.status, "❓")

    def __repr__(self) -> str:
        return (
            f"{self.get_status_emoji()} {self.name} "
            f"[{self.status.value}] - {self.role}"
        )
