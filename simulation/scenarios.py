"""
Sentinel-MAS: Scenario Definitions
=====================================
Defines all normal and attack scenarios for the system.

Each scenario is a function that orchestrates agents to
demonstrate a specific workflow (normal or attack).
"""

from typing import Optional


# ==========================================
# Normal Scenarios
# ==========================================

def run_normal_workflow(system: "SentinelSystem", task_id: Optional[str] = None) -> dict:
    """
    Normal workflow: Research → Analyst → Manager
    
    Demonstrates the multi-agent system working correctly
    with no attacks. All messages should be marked as NORMAL.
    """
    task = "Analyze the current state of AI agent security and provide recommendations"
    
    # Step 1: Research Agent investigates
    research_result = system.research_agent.process_task(task, task_id=task_id)
    
    # Step 2: Analyst Agent analyzes (receives via message bus from Research)
    analyst_result = system.analyst_agent.process_task(task, task_id=task_id)
    
    # Step 3: Manager Agent coordinates (receives via message bus from Analyst)
    manager_result = system.manager_agent.process_task(task, task_id=task_id)
    
    return {
        "scenario": "normal_workflow",
        "task": task,
        "results": {
            "research": research_result[:200],
            "analysis": analyst_result[:200],
            "management": manager_result[:200],
        },
        "status": "completed",
    }


# ==========================================
# Attack Scenarios
# ==========================================

def run_prompt_injection(system: "SentinelSystem", task_id: Optional[str] = None) -> dict:
    """
    Simulate a prompt injection attack.
    
    Attacker sends a malicious message to AnalystAgent
    attempting to override its instructions.
    """
    malicious_content = system.attacker_agent.simulate_prompt_injection(
        target="AnalystAgent",
        task_id=task_id,
    )
    
    return {
        "scenario": "prompt_injection",
        "target": "AnalystAgent",
        "malicious_content": malicious_content[:200],
        "status": "executed",
    }


def run_malicious_tool_output(system: "SentinelSystem", task_id: Optional[str] = None) -> dict:
    """
    Simulate a malicious tool output.
    
    Attacker injects a poisoned tool result targeting AnalystAgent.
    """
    malicious_content = system.attacker_agent.simulate_malicious_tool_output(
        target="AnalystAgent",
        task_id=task_id,
    )
    
    return {
        "scenario": "malicious_tool_output",
        "target": "AnalystAgent",
        "malicious_content": malicious_content[:200],
        "status": "executed",
    }


def run_abnormal_behavior(system: "SentinelSystem", task_id: Optional[str] = None) -> dict:
    """
    Simulate abnormal agent behavior (rapid messaging, unusual patterns).
    """
    abnormal_content = system.attacker_agent.simulate_abnormal_behavior(
        target="ManagerAgent",
        task_id=task_id,
    )
    
    return {
        "scenario": "abnormal_behavior",
        "target": "ManagerAgent",
        "abnormal_content": abnormal_content[:200],
        "status": "executed",
    }


def run_attack_propagation(system: "SentinelSystem", task_id: Optional[str] = None) -> dict:
    """
    Simulate an attack propagation through the agent chain.
    
    Attack path: Attacker → Analyst → Manager
    """
    chain = ["AnalystAgent", "ManagerAgent"]
    messages_sent = system.attacker_agent.simulate_attack_propagation(
        chain=chain,
        task_id=task_id,
    )
    
    return {
        "scenario": "attack_propagation",
        "chain": ["AttackerAgent"] + chain,
        "messages_sent": messages_sent,
        "status": "executed",
    }
