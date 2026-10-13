"""
Sentinel-MAS: Manager Agent
==============================
Coordinates the workflow, receives results from other agents,
and produces the final consolidated result.
"""

from typing import Optional
from agents.base_agent import BaseAgent
from communication.message_bus import MessageBus
from llm.llm_provider import LLMProvider


class ManagerAgent(BaseAgent):
    """
    Manager Agent: coordinates workflow and produces final results.
    
    In the normal workflow:
    ResearchAgent → AnalystAgent → ManagerAgent
    """

    def __init__(self, message_bus: MessageBus, llm: Optional[LLMProvider] = None):
        super().__init__(
            name="ManagerAgent",
            role="Coordinates workflow and produces final consolidated results",
            message_bus=message_bus,
            llm=llm,
        )

    def process_task(self, task: str, task_id: Optional[str] = None) -> str:
        """
        Process a management/coordination task.
        
        Collects input from inbox (analyst results) and produces
        a final coordinated output.
        """
        # Gather all received messages
        input_data = task
        if self.inbox:
            received_data = "\n".join(
                f"From {m.sender}: {m.content}" for m in self.inbox
            )
            input_data = f"Agent reports:\n{received_data}\n\nOriginal task: {task}"

        # Generate final summary using LLM
        system_prompt = (
            "You are a Manager Agent in a multi-agent AI system. "
            "Your job is to coordinate the work of other agents, "
            "synthesize their findings, and produce a final summary."
        )

        result = self.llm.generate(
            prompt=f"Coordinate and summarize the following agent outputs: {input_data}",
            system_prompt=system_prompt,
        )

        return result
