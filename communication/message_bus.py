"""
Sentinel-MAS: Message Bus
==========================
Central communication hub for all agent-to-agent messages.

Instead of agents talking directly:
    Agent A → Agent B

Everything goes through the Message Bus:
    Agent A → Message Bus → Agent B

This lets us:
1. LOG every message automatically
2. INSPECT messages for threats (via Defender)
3. BLOCK messages from quarantined agents
4. RECORD communication in the graph database

Think of it as a "post office" that also acts as a security checkpoint.
"""

import json
import os
from typing import Callable, Optional

from communication.message_models import Message, MessageStatus
from config.settings import settings


class MessageBus:
    """
    Central message router and logger.
    
    All agent communication passes through here.
    The bus maintains:
    - A log of ALL messages
    - A list of quarantined agents (can't send/receive)
    - Callbacks for security inspection
    """

    def __init__(self):
        # --- Message Storage ---
        self.messages: list[Message] = []         # All messages ever sent
        
        # --- Quarantine Registry ---
        self.quarantined_agents: set[str] = set() # Names of quarantined agents
        
        # --- Security Callback ---
        # This function is called for every message BEFORE delivery
        # The Defender agent sets this up to inspect messages
        self._security_callback: Optional[Callable[[Message], Message]] = None
        
        # --- Message Delivery ---
        # Agents register here to receive messages
        # Key: agent name, Value: callback function
        self._agent_handlers: dict[str, Callable[[Message], None]] = {}
        
        # --- Logging ---
        self._log_file = settings.LOG_DIR / "communication_log.json"
        self._ensure_log_file()

    def _ensure_log_file(self):
        """Create the log directory and file if they don't exist."""
        self._log_file.parent.mkdir(parents=True, exist_ok=True)
        if not self._log_file.exists() or self._log_file.stat().st_size == 0:
            with open(self._log_file, "w", encoding="utf-8") as f:
                json.dump([], f)

    # ==========================================
    # Agent Registration
    # ==========================================

    def register_agent(self, agent_name: str, handler: Callable[[Message], None]):
        """
        Register an agent to receive messages.
        
        Args:
            agent_name: The name of the agent (e.g., "ResearchAgent")
            handler: Function to call when a message arrives for this agent
        """
        self._agent_handlers[agent_name] = handler
        
    def register_security_callback(self, callback: Callable[[Message], Message]):
        """
        Register the security inspection function.
        Called on every message BEFORE delivery.
        The Defender agent uses this.
        """
        self._security_callback = callback

    # ==========================================
    # Message Sending
    # ==========================================

    def send_message(self, message: Message) -> Message:
        """
        Send a message through the bus.
        
        Pipeline:
        1. Check if sender is quarantined → block if yes
        2. Check if receiver is quarantined → block if yes
        3. Run security callback (threat detection)
        4. Log the message
        5. Deliver to receiver (if not blocked)
        
        Args:
            message: The Message to send
            
        Returns:
            The message (with updated status after security checks)
        """
        # --- Step 1: Check sender quarantine ---
        if message.sender in self.quarantined_agents:
            message.status = MessageStatus.BLOCKED
            message.threat_reason = f"Sender '{message.sender}' is quarantined"
            self._log_message(message)
            self.messages.append(message)
            return message

        # --- Step 2: Check receiver quarantine ---
        if message.receiver in self.quarantined_agents:
            message.status = MessageStatus.BLOCKED
            message.threat_reason = f"Receiver '{message.receiver}' is quarantined"
            self._log_message(message)
            self.messages.append(message)
            return message

        # --- Step 3: Security inspection ---
        if self._security_callback:
            message = self._security_callback(message)

        # --- Step 4: Log the message ---
        self._log_message(message)
        self.messages.append(message)

        # --- Step 5: Deliver (if not blocked by security) ---
        if message.status not in (MessageStatus.BLOCKED, MessageStatus.VERIFIED):
            if message.status == MessageStatus.PENDING:
                message.status = MessageStatus.NORMAL
            handler = self._agent_handlers.get(message.receiver)
            if handler:
                handler(message)

        return message

    # ==========================================
    # Quarantine Management
    # ==========================================

    def quarantine_agent(self, agent_name: str):
        """Add an agent to the quarantine list."""
        self.quarantined_agents.add(agent_name)

    def release_agent(self, agent_name: str):
        """Remove an agent from the quarantine list."""
        self.quarantined_agents.discard(agent_name)

    def is_quarantined(self, agent_name: str) -> bool:
        """Check if an agent is quarantined."""
        return agent_name in self.quarantined_agents

    # ==========================================
    # Logging
    # ==========================================

    def _log_message(self, message: Message):
        """
        Append a message to the JSON log file.

        The log is rewritten atomically (write to a temp file, then replace)
        so that an interrupted or concurrent write can never leave the log
        in a half-written state. If the existing log is missing, empty or
        corrupted, we recover by starting a fresh list instead of failing
        on every subsequent message.
        """
        try:
            logs = []
            if self._log_file.exists():
                try:
                    with open(self._log_file, "r", encoding="utf-8") as f:
                        content = f.read().strip()
                    if content:
                        logs = json.loads(content)
                    if not isinstance(logs, list):
                        logs = [logs]
                except (json.JSONDecodeError, ValueError, OSError):
                    # Corrupted or unreadable log — recover with a fresh list.
                    logs = []

            # Append new message
            logs.append(message.to_dict())

            # Write to a temp file first, then atomically replace the log.
            tmp_file = self._log_file.with_suffix(".json.tmp")
            with open(tmp_file, "w", encoding="utf-8") as f:
                json.dump(logs, f, indent=2)
            os.replace(tmp_file, self._log_file)
        except Exception as e:
            print(f"[WARN] Error writing log: {e}")

    # ==========================================
    # Query Methods
    # ==========================================

    def get_messages(
        self,
        sender: Optional[str] = None,
        receiver: Optional[str] = None,
        message_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> list[Message]:
        """
        Query messages with optional filters.
        
        Args:
            sender: Filter by sender name
            receiver: Filter by receiver name
            message_type: Filter by message type (e.g., "normal", "malicious")
            status: Filter by status (e.g., "detected", "blocked")
            
        Returns:
            List of matching messages
        """
        results = self.messages.copy()
        
        if sender:
            results = [m for m in results if m.sender == sender]
        if receiver:
            results = [m for m in results if m.receiver == receiver]
        if message_type:
            results = [m for m in results if m.message_type.value == message_type]
        if status:
            results = [m for m in results if m.status.value == status]
        
        return results

    def get_threat_messages(self) -> list[Message]:
        """Get all messages that were detected or verified as threats."""
        return [
            m for m in self.messages
            if m.status in (
                MessageStatus.DETECTED,
                MessageStatus.VERIFIED,
                MessageStatus.BLOCKED,
            )
        ]

    def get_message_count(self) -> dict:
        """Get counts of messages by status."""
        counts = {
            "total": len(self.messages),
            "normal": 0,
            "detected": 0,
            "verified": 0,
            "blocked": 0,
            "false_positive": 0,
        }
        for msg in self.messages:
            key = msg.status.value
            if key in counts:
                counts[key] += 1
        return counts

    def clear(self):
        """Reset the message bus (clear all messages and quarantines)."""
        self.messages.clear()
        self.quarantined_agents.clear()
        # Reset log file
        with open(self._log_file, "w", encoding="utf-8") as f:
            json.dump([], f)

    def __repr__(self) -> str:
        counts = self.get_message_count()
        return (
            f"MessageBus(messages={counts['total']}, "
            f"quarantined={len(self.quarantined_agents)})"
        )
