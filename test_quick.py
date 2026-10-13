"""Quick test of the Sentinel-MAS core engine."""
import sys
import os
os.environ["PYTHONIOENCODING"] = "utf-8"
try:
    sys.stdout.reconfigure(encoding="utf-8")
except (AttributeError, OSError):
    pass
sys.path.insert(0, '.')

from communication.message_bus import MessageBus
from llm.mock_provider import MockProvider
from agents.research_agent import ResearchAgent
from agents.analyst_agent import AnalystAgent
from agents.manager_agent import ManagerAgent
from agents.attacker_agent import AttackerAgent
from agents.defender_agent import DefenderAgent
from evaluation.metrics import SecurityMetrics

print('=== SENTINEL-MAS CORE ENGINE TEST ===')
print()

# Initialize
mb = MessageBus()
llm = MockProvider()
research = ResearchAgent(mb, llm)
analyst = AnalystAgent(mb, llm)
manager = ManagerAgent(mb, llm)
attacker = AttackerAgent(mb, llm)
defender = DefenderAgent(mb, llm)
metrics = SecurityMetrics(mb, defender.quarantine_manager)

print('1. All components initialized OK')

# Normal workflow
result = research.process_task('Test task', task_id='test1')
print(f'2. Research Agent: {result[:60]}...')

result = analyst.process_task('Analyze this', task_id='test1')
print(f'3. Analyst Agent: {result[:60]}...')

result = manager.process_task('Summarize', task_id='test1')
print(f'4. Manager Agent: {result[:60]}...')

print(f'5. Messages after normal workflow: {len(mb.messages)}')

# Attack
attacker.simulate_prompt_injection(target='AnalystAgent', task_id='test2')
print(f'6. Prompt injection simulated')

print(f'7. Messages total: {len(mb.messages)}')
print(f'8. Quarantined agents: {mb.quarantined_agents}')

# Metrics
m = metrics.calculate_all()
dr = m["detection_rate"]
sc = m["service_continuity"]
print(f'9. Detection Rate: {dr:.1%}')
print(f'10. Service Continuity: {sc:.1%}')

# Security summary
summary = defender.get_security_summary()
print()
print(summary)

print()
print('=== ALL TESTS PASSED ===')
