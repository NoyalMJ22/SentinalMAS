"""
Sentinel-MAS: Mock LLM Provider
================================
Simulates LLM responses WITHOUT needing any API key.
This is the DEFAULT mode — the entire security pipeline works with this.

The mock provider returns realistic-looking responses for each agent role,
making the demo fully functional offline.
"""

import random
from llm.llm_provider import LLMProvider


class MockProvider(LLMProvider):
    """
    Mock LLM that returns pre-defined realistic responses.
    
    This is crucial for the project because:
    1. No API costs during development
    2. Demo works without internet
    3. Consistent outputs for testing
    4. The security pipeline is the focus, not the LLM quality
    """

    def __init__(self):
        # Responses organized by agent role keywords
        self._responses = {
            "research": [
                "Based on my research analysis, I found the following key findings: "
                "Multi-agent systems face several security challenges including "
                "prompt injection attacks, data poisoning, and unauthorized inter-agent "
                "communication. Recent studies show that 73% of multi-agent deployments "
                "lack adequate security monitoring. Recommendation: implement centralized "
                "message monitoring with real-time threat detection.",
                
                "Research completed. Key insights on AI agent security: "
                "1) Agent-to-agent communication channels are primary attack vectors. "
                "2) Prompt injection remains the most common attack type (estimated 45% of incidents). "
                "3) Behavioral anomaly detection shows promising results for early threat identification. "
                "4) Graph-based analysis can effectively trace attack propagation paths.",
                
                "After thorough investigation, here are the findings: "
                "The current landscape of multi-agent AI security reveals significant "
                "vulnerabilities in unmonitored communication channels. Defense mechanisms "
                "should include: rule-based detection for known patterns, behavioral analysis "
                "for unknown threats, and automated quarantine for confirmed compromises.",
            ],
            "analysis": [
                "Analysis complete. After reviewing the research data, I've identified "
                "the following patterns: The primary risk vectors are prompt injection "
                "(high severity), malicious tool outputs (medium severity), and abnormal "
                "communication patterns (medium severity). Recommended priority: "
                "implement prompt injection detection first, then behavioral monitoring.",
                
                "Analytical summary: The data suggests a strong correlation between "
                "unmonitored agent communication and successful attack propagation. "
                "Key metric: attacks spread to an average of 2.3 additional agents "
                "before detection in unprotected systems. With monitoring, this drops "
                "to 0.4 agents. Conclusion: message bus monitoring is essential.",
                
                "Analysis results indicate three critical areas requiring attention: "
                "1) Input validation for inter-agent messages (prevents 60% of attacks). "
                "2) Communication pattern monitoring (detects 25% of remaining threats). "
                "3) Context-aware verification (reduces false positives by 40%). "
                "Overall risk assessment: MODERATE — mitigatable with proper defenses.",
            ],
            "management": [
                "Management summary: Based on the analysis provided, I'm coordinating "
                "the following action plan: Phase 1 — Deploy message monitoring on all "
                "agent channels. Phase 2 — Implement rule-based threat detection. "
                "Phase 3 — Enable automated quarantine for confirmed threats. "
                "All agents are operating within normal parameters. Status: OPERATIONAL.",
                
                "Final coordination report: All task agents have completed their "
                "assigned work successfully. Research findings have been validated "
                "by the analyst. Key decisions: 1) Maintain current security posture. "
                "2) Continue monitoring for anomalies. 3) No threats detected in "
                "this workflow cycle. System status: ALL CLEAR.",
                
                "Workflow coordination complete. Summary of agent outputs: "
                "Research Agent provided comprehensive security landscape analysis. "
                "Analyst Agent validated findings and prioritized recommendations. "
                "All communications verified as normal. No security incidents "
                "detected during this operation cycle.",
            ],
            "default": [
                "Task completed successfully. All parameters within normal range.",
                "Processing complete. Results have been compiled and are ready for review.",
                "Operation finished. No anomalies detected during execution.",
            ],
        }

    def generate(self, prompt: str, system_prompt: str = "") -> str:
        """
        Generate a mock response based on the prompt content.
        
        Looks for keywords in the prompt/system_prompt to determine
        which type of response to return.
        """
        # Combine prompts for keyword matching
        combined = (prompt + " " + system_prompt).lower()

        # Match response type based on keywords
        if any(word in combined for word in ["research", "investigate", "find", "search"]):
            responses = self._responses["research"]
        elif any(word in combined for word in ["analy", "review", "assess", "evaluate"]):
            responses = self._responses["analysis"]
        elif any(word in combined for word in ["manage", "coordinate", "summarize", "final"]):
            responses = self._responses["management"]
        else:
            responses = self._responses["default"]

        return random.choice(responses)

    def get_provider_name(self) -> str:
        return "mock"
