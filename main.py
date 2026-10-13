"""
Sentinel-MAS: Main Entry Point
================================
This is the central orchestrator that initializes all components
and provides the CLI interface for running experiments.

Usage:
    python main.py                    # Interactive CLI menu
    python main.py --scenario normal  # Run specific scenario
    python main.py --dashboard        # Launch Streamlit dashboard
"""

import sys
import json
import uuid

# Ensure UTF-8 output so rich can render emoji on Windows consoles.
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except (AttributeError, OSError):
        pass

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint

from config.settings import settings
from communication.message_bus import MessageBus
from llm.llm_provider import get_llm_provider
from agents.research_agent import ResearchAgent
from agents.analyst_agent import AnalystAgent
from agents.manager_agent import ManagerAgent
from agents.attacker_agent import AttackerAgent
from agents.defender_agent import DefenderAgent
from agents.base_agent import AgentStatus
from graph.neo4j_manager import Neo4jManager
from evaluation.metrics import SecurityMetrics
from simulation.scenarios import (
    run_normal_workflow,
    run_prompt_injection,
    run_malicious_tool_output,
    run_abnormal_behavior,
    run_attack_propagation,
)

console = Console()


class SentinelSystem:
    """
    The main Sentinel-MAS system.
    
    Initializes all components:
    - Message Bus (communication)
    - LLM Provider (AI backend)
    - All Agents (research, analyst, manager, attacker, defender)
    - Neo4j Graph (attack analysis)
    - Security Metrics (evaluation)
    """

    def __init__(self):
        console.print(Panel(
            "[bold cyan]🛡️ SENTINEL-MAS[/bold cyan]\n"
            "[dim]Self-Defending Security Framework for Multi-Agent AI Systems[/dim]",
            border_style="cyan",
        ))
        
        # --- Initialize Components ---
        console.print("\n[bold]Initializing system...[/bold]")
        
        # 1. Message Bus
        self.message_bus = MessageBus()
        console.print("  📬 Message Bus          [green]✓[/green]")
        
        # 2. LLM Provider
        self.llm = get_llm_provider()
        console.print(f"  🤖 LLM Provider         [green]✓[/green] ({self.llm.get_provider_name()})")
        
        # 3. Task Agents
        self.research_agent = ResearchAgent(self.message_bus, self.llm)
        self.analyst_agent = AnalystAgent(self.message_bus, self.llm)
        self.manager_agent = ManagerAgent(self.message_bus, self.llm)
        console.print("  🔍 Research Agent       [green]✓[/green]")
        console.print("  📊 Analyst Agent        [green]✓[/green]")
        console.print("  📋 Manager Agent        [green]✓[/green]")
        
        # 4. Security Agents
        self.attacker_agent = AttackerAgent(self.message_bus, self.llm)
        self.defender_agent = DefenderAgent(self.message_bus, self.llm)
        console.print("  💀 Attacker Agent       [green]✓[/green]")
        console.print("  🛡️  Defender Agent       [green]✓[/green]")
        
        # 5. Graph Database
        self.graph = Neo4jManager()
        self._register_agents_in_graph()
        
        # 6. Metrics
        self.metrics = SecurityMetrics(
            self.message_bus,
            self.defender_agent.quarantine_manager,
        )
        console.print("  📈 Metrics Engine       [green]✓[/green]")
        
        console.print("\n[bold green]System initialized successfully![/bold green]\n")

    def _register_agents_in_graph(self):
        """Add all agents as nodes in the graph."""
        agents = [
            ("ResearchAgent", "Research", "active"),
            ("AnalystAgent", "Analysis", "active"),
            ("ManagerAgent", "Management", "active"),
            ("AttackerAgent", "Attacker", "attacker"),
            ("DefenderAgent", "Security", "monitoring"),
        ]
        for name, role, status in agents:
            self.graph.add_agent(name, role, status)

    # ==========================================
    # Scenario Runners
    # ==========================================

    def run_scenario(self, scenario_name: str) -> dict:
        """Run a named scenario and return results."""
        task_id = f"{scenario_name}_{uuid.uuid4().hex[:6]}"
        
        scenarios = {
            "normal": run_normal_workflow,
            "prompt_injection": run_prompt_injection,
            "malicious_tool_output": run_malicious_tool_output,
            "abnormal_behavior": run_abnormal_behavior,
            "attack_propagation": run_attack_propagation,
        }
        
        scenario_fn = scenarios.get(scenario_name)
        if not scenario_fn:
            return {"error": f"Unknown scenario: {scenario_name}"}
        
        result = scenario_fn(self, task_id=task_id)
        
        # Record messages in graph
        for msg in self.message_bus.messages:
            if msg.task_id == task_id:
                self.graph.add_message(msg)
        
        # Update quarantined agents in graph
        for agent_name in self.message_bus.quarantined_agents:
            self.graph.update_agent_status(agent_name, "quarantined")
        
        return result

    def reset(self):
        """Reset the entire system to initial state."""
        self.message_bus.clear()
        self.defender_agent.reset()
        
        # Reset agent statuses
        self.research_agent.status = AgentStatus.ACTIVE
        self.research_agent.inbox.clear()
        self.analyst_agent.status = AgentStatus.ACTIVE
        self.analyst_agent.inbox.clear()
        self.manager_agent.status = AgentStatus.ACTIVE
        self.manager_agent.inbox.clear()
        self.attacker_agent.status = AgentStatus.ATTACKER
        self.attacker_agent.inbox.clear()
        self.defender_agent.status = AgentStatus.MONITORING
        self.defender_agent.inbox.clear()
        
        # Reset graph
        self.graph.clear()
        self._register_agents_in_graph()
        
        # Reset log file
        log_file = settings.LOG_DIR / "communication_log.json"
        with open(log_file, "w") as f:
            json.dump([], f)

    def get_agent_statuses(self) -> list[dict]:
        """Get status of all agents for dashboard display."""
        agents = [
            self.research_agent,
            self.analyst_agent,
            self.manager_agent,
            self.attacker_agent,
            self.defender_agent,
        ]
        return [
            {
                "name": a.name,
                "role": a.role,
                "status": a.status.value,
                "emoji": a.get_status_emoji(),
                "inbox_count": len(a.inbox),
            }
            for a in agents
        ]

    # ==========================================
    # Display Methods (CLI)
    # ==========================================

    def display_agent_status(self):
        """Display agent status in a beautiful table."""
        table = Table(title="Agent Status", show_header=True, header_style="bold cyan")
        table.add_column("Agent", style="bold")
        table.add_column("Status")
        table.add_column("Role", style="dim")
        
        for agent_info in self.get_agent_statuses():
            status_style = {
                "active": "[green]ACTIVE[/green]",
                "quarantined": "[red]QUARANTINED[/red]",
                "monitoring": "[blue]MONITORING[/blue]",
                "attacker": "[red]ATTACKER[/red]",
                "inactive": "[dim]INACTIVE[/dim]",
            }
            status_text = status_style.get(agent_info["status"], agent_info["status"])
            table.add_row(
                f"{agent_info['emoji']} {agent_info['name']}",
                status_text,
                agent_info["role"],
            )
        
        console.print(table)

    def display_metrics(self):
        """Display security metrics."""
        m = self.metrics.calculate_all()
        
        table = Table(title="Security Metrics", show_header=True, header_style="bold cyan")
        table.add_column("Metric", style="bold")
        table.add_column("Value", justify="right")
        
        table.add_row("Total Messages", str(m["total_messages"]))
        table.add_row("Total Attacks", str(m["total_attacks"]))
        table.add_row("Threats Detected", str(m["threats_detected"]))
        table.add_row("Threats Confirmed", str(m["threats_confirmed"]))
        table.add_row("False Positives", str(m["false_positives"]))
        table.add_row("Messages Blocked", str(m["messages_blocked"]))
        table.add_row("──────────────────", "────────")
        table.add_row("Detection Rate", f"{m['detection_rate']:.1%}")
        table.add_row("False Positive Rate", f"{m['false_positive_rate']:.1%}")
        table.add_row("Avg Containment Time", f"{m['containment_time_avg']:.3f}s")
        table.add_row("Propagation Accuracy", f"{m['propagation_accuracy']:.1%}")
        table.add_row("Service Continuity", f"{m['service_continuity']:.1%}")
        
        console.print(table)

    def display_communication_log(self):
        """Display recent communication messages."""
        table = Table(title="Communication Log", show_header=True, header_style="bold cyan")
        table.add_column("Time", style="dim", width=10)
        table.add_column("Sender", width=16)
        table.add_column("Receiver", width=16)
        table.add_column("Type", width=12)
        table.add_column("Status", width=14)
        table.add_column("Message", max_width=40)
        
        for msg in self.message_bus.messages[-15:]:  # Last 15 messages
            status_style = {
                "normal": "[green]NORMAL[/green]",
                "detected": "[yellow]DETECTED[/yellow]",
                "verified": "[red]VERIFIED[/red]",
                "blocked": "[red]BLOCKED[/red]",
                "pending": "[dim]PENDING[/dim]",
                "false_positive": "[green]FALSE POS[/green]",
            }
            status_text = status_style.get(msg.status.value, msg.status.value)
            
            type_style = {
                "normal": "[green]normal[/green]",
                "malicious": "[red]malicious[/red]",
                "system": "[blue]system[/blue]",
            }
            type_text = type_style.get(msg.message_type.value, msg.message_type.value)
            
            table.add_row(
                msg.timestamp[11:19],
                msg.sender,
                msg.receiver,
                type_text,
                status_text,
                msg.content[:40] + "..." if len(msg.content) > 40 else msg.content,
            )
        
        console.print(table)


def interactive_menu():
    """Run the interactive CLI menu."""
    system = SentinelSystem()
    
    while True:
        console.print("\n[bold cyan]═══ SENTINEL-MAS CONTROL PANEL ═══[/bold cyan]")
        console.print("1. Run Normal Workflow")
        console.print("2. Simulate Prompt Injection")
        console.print("3. Simulate Malicious Tool Output")
        console.print("4. Simulate Abnormal Behavior")
        console.print("5. Run Attack Propagation")
        console.print("6. Show Agent Status")
        console.print("7. Show Communication Log")
        console.print("8. Show Security Metrics")
        console.print("9. Show Security Summary")
        console.print("10. Reset System")
        console.print("11. Launch Dashboard (Streamlit)")
        console.print("0. Exit")
        
        choice = input("\nSelect option: ").strip()
        
        if choice == "1":
            console.print("\n[bold]Running normal workflow...[/bold]")
            result = system.run_scenario("normal")
            console.print(f"[green]✓ Normal workflow completed[/green]")
        elif choice == "2":
            console.print("\n[bold red]Simulating prompt injection...[/bold red]")
            result = system.run_scenario("prompt_injection")
            console.print(f"[red]💀 Prompt injection executed![/red]")
        elif choice == "3":
            console.print("\n[bold red]Simulating malicious tool output...[/bold red]")
            result = system.run_scenario("malicious_tool_output")
            console.print(f"[red]💀 Malicious tool output injected![/red]")
        elif choice == "4":
            console.print("\n[bold red]Simulating abnormal behavior...[/bold red]")
            result = system.run_scenario("abnormal_behavior")
            console.print(f"[red]💀 Abnormal behavior simulated![/red]")
        elif choice == "5":
            console.print("\n[bold red]Running attack propagation...[/bold red]")
            result = system.run_scenario("attack_propagation")
            console.print(f"[red]💀 Attack propagation complete![/red]")
        elif choice == "6":
            system.display_agent_status()
        elif choice == "7":
            system.display_communication_log()
        elif choice == "8":
            system.display_metrics()
        elif choice == "9":
            console.print(system.defender_agent.get_security_summary())
        elif choice == "10":
            system.reset()
            console.print("[green]✓ System reset complete[/green]")
        elif choice == "11":
            console.print("[cyan]Launching Streamlit dashboard...[/cyan]")
            console.print("Run: [bold]streamlit run dashboard/app.py[/bold]")
        elif choice == "0":
            console.print("[dim]Goodbye![/dim]")
            system.graph.close()
            break
        else:
            console.print("[red]Invalid option[/red]")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "--dashboard":
            import subprocess
            subprocess.run([
                sys.executable, "-m", "streamlit", "run", "dashboard/app.py"
            ])
        elif sys.argv[1] == "--scenario":
            scenario = sys.argv[2] if len(sys.argv) > 2 else "normal"
            system = SentinelSystem()
            result = system.run_scenario(scenario)
            rprint(result)
            system.display_metrics()
            system.graph.close()
        else:
            print(f"Unknown argument: {sys.argv[1]}")
            print("Usage: python main.py [--dashboard | --scenario <name>]")
    else:
        interactive_menu()
