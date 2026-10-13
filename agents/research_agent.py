"""
Sentinel-MAS: Research Agent
==============================
Performs research tasks and sends findings to the Analyst Agent.
This is a "normal" agent — it does legitimate work.
"""

from typing import Optional
from agents.base_agent import BaseAgent
from communication.message_bus import MessageBus
from llm.llm_provider import LLMProvider


class ResearchAgent(BaseAgent):
    """
    Research Agent: investigates topics and reports findings.
    
    In the normal workflow:
    ResearchAgent → AnalystAgent → ManagerAgent
    """

    def __init__(self, message_bus: MessageBus, llm: Optional[LLMProvider] = None):
        super().__init__(
            name="ResearchAgent",
            role="Performs research and information gathering tasks",
            message_bus=message_bus,
            llm=llm,
        )

    def process_task(self, task: str, task_id: Optional[str] = None) -> str:
        """
        Process a research task.
        
        1. Uses the LLM to generate research findings
        2. Sends the result to AnalystAgent
        3. Returns the result
        """
        # Generate research using LLM
        system_prompt = (
            "You are a Research Agent in a multi-agent AI system. "
            "Your job is to research topics and provide detailed findings. "
            "Be thorough but concise in your analysis."
        )
        
        result = self.llm.generate(
            prompt=f"Research the following topic and provide key findings: {task}",
            system_prompt=system_prompt,
        )

        # Send result to Analyst Agent via Message Bus
        self.send_message(
            receiver="AnalystAgent",
            content=result,
            task_id=task_id,
        )

        return result
