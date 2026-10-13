"""
Sentinel-MAS: Analyst Agent
==============================
Receives information from the Research Agent, analyzes it,
and sends the analysis to the Manager Agent.
"""

from typing import Optional
from agents.base_agent import BaseAgent
from communication.message_bus import MessageBus
from llm.llm_provider import LLMProvider


class AnalystAgent(BaseAgent):
    """
    Analyst Agent: reviews and analyzes research findings.
    
    In the normal workflow:
    ResearchAgent → AnalystAgent → ManagerAgent
    """

    def __init__(self, message_bus: MessageBus, llm: Optional[LLMProvider] = None):
        super().__init__(
            name="AnalystAgent",
            role="Analyzes research findings and provides assessments",
            message_bus=message_bus,
            llm=llm,
        )

    def process_task(self, task: str, task_id: Optional[str] = None) -> str:
        """
        Process an analysis task.
        
        Can work in two modes:
        1. Analyze a direct task (when called with a task string)
        2. Analyze the latest message in inbox (when receiving from Research Agent)
        """
        # Check if we have received data from Research Agent
        input_data = task
        if self.inbox:
            latest = self.inbox[-1]
            input_data = f"Research findings: {latest.content}\n\nAdditional context: {task}"

        # Generate analysis using LLM
        system_prompt = (
            "You are an Analyst Agent in a multi-agent AI system. "
            "Your job is to analyze information, identify patterns, "
            "assess risks, and provide structured analysis."
        )

        result = self.llm.generate(
            prompt=f"Analyze the following information and provide your assessment: {input_data}",
            system_prompt=system_prompt,
        )

        # Send result to Manager Agent via Message Bus
        self.send_message(
            receiver="ManagerAgent",
            content=result,
            task_id=task_id,
        )

        return result
