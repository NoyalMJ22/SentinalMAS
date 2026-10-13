"""
Sentinel-MAS: Streamlit Dashboard
====================================
Visual dashboard for monitoring, controlling, and demonstrating
the security framework.

Launch with:
    streamlit run dashboard/app.py
    
    OR from main.py:
    python main.py --dashboard
"""

import sys
import os

# Add project root to path so imports work
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import json
from datetime import datetime

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


# ==========================================
# Page Configuration
# ==========================================
st.set_page_config(
    page_title="Sentinel-MAS Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ==========================================
# Initialize System (cached in session state)
# ==========================================
def init_system():
    """Initialize or retrieve the Sentinel system from session state."""
    if "system_initialized" not in st.session_state:
        st.session_state.message_bus = MessageBus()
        st.session_state.llm = get_llm_provider()
        
        mb = st.session_state.message_bus
        llm = st.session_state.llm
        
        st.session_state.research_agent = ResearchAgent(mb, llm)
        st.session_state.analyst_agent = AnalystAgent(mb, llm)
        st.session_state.manager_agent = ManagerAgent(mb, llm)
        st.session_state.attacker_agent = AttackerAgent(mb, llm)
        st.session_state.defender_agent = DefenderAgent(mb, llm)
        st.session_state.graph = Neo4jManager()
        st.session_state.metrics = SecurityMetrics(
            mb, st.session_state.defender_agent.quarantine_manager
        )
        
        # Register agents in graph
        for name, role, status in [
            ("ResearchAgent", "Research", "active"),
            ("AnalystAgent", "Analysis", "active"),
            ("ManagerAgent", "Management", "active"),
            ("AttackerAgent", "Attacker", "attacker"),
            ("DefenderAgent", "Security", "monitoring"),
        ]:
            st.session_state.graph.add_agent(name, role, status)
        
        st.session_state.scenario_log = []
        st.session_state.system_initialized = True


# Create a simple system-like object for scenario functions
class SystemProxy:
    """Proxy object to pass to scenario functions."""
    def __init__(self):
        self.message_bus = st.session_state.message_bus
        self.research_agent = st.session_state.research_agent
        self.analyst_agent = st.session_state.analyst_agent
        self.manager_agent = st.session_state.manager_agent
        self.attacker_agent = st.session_state.attacker_agent
        self.defender_agent = st.session_state.defender_agent


def run_scenario(name: str):
    """Run a scenario and log the result."""
    import uuid
    task_id = f"{name}_{uuid.uuid4().hex[:6]}"
    proxy = SystemProxy()
    
    scenarios = {
        "normal": run_normal_workflow,
        "prompt_injection": run_prompt_injection,
        "malicious_tool_output": run_malicious_tool_output,
        "abnormal_behavior": run_abnormal_behavior,
        "attack_propagation": run_attack_propagation,
    }
    
    fn = scenarios.get(name)
    if fn:
        result = fn(proxy, task_id=task_id)
        # Record in graph
        for msg in st.session_state.message_bus.messages:
            if msg.task_id == task_id:
                st.session_state.graph.add_message(msg)
        for agent_name in st.session_state.message_bus.quarantined_agents:
            st.session_state.graph.update_agent_status(agent_name, "quarantined")
        
        st.session_state.scenario_log.append({
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "scenario": name,
            "result": result,
        })
        
        # Update agent statuses if quarantined
        for agent in [st.session_state.research_agent, st.session_state.analyst_agent, 
                      st.session_state.manager_agent]:
            if st.session_state.message_bus.is_quarantined(agent.name):
                agent.status = AgentStatus.QUARANTINED


def reset_system():
    """Reset the entire system."""
    st.session_state.message_bus.clear()
    st.session_state.defender_agent.reset()
    st.session_state.research_agent.status = AgentStatus.ACTIVE
    st.session_state.research_agent.inbox.clear()
    st.session_state.analyst_agent.status = AgentStatus.ACTIVE
    st.session_state.analyst_agent.inbox.clear()
    st.session_state.manager_agent.status = AgentStatus.ACTIVE
    st.session_state.manager_agent.inbox.clear()
    st.session_state.attacker_agent.status = AgentStatus.ATTACKER
    st.session_state.attacker_agent.inbox.clear()
    st.session_state.defender_agent.status = AgentStatus.MONITORING
    st.session_state.defender_agent.inbox.clear()
    st.session_state.graph.clear()
    for name, role, status in [
        ("ResearchAgent", "Research", "active"),
        ("AnalystAgent", "Analysis", "active"),
        ("ManagerAgent", "Management", "active"),
        ("AttackerAgent", "Attacker", "attacker"),
        ("DefenderAgent", "Security", "monitoring"),
    ]:
        st.session_state.graph.add_agent(name, role, status)
    st.session_state.scenario_log = []
    log_file = settings.LOG_DIR / "communication_log.json"
    with open(log_file, "w") as f:
        json.dump([], f)


# ==========================================
# Custom CSS
# ==========================================
st.markdown("""
<style>
    .stMetric {
        background: linear-gradient(135deg, #1e1e2e 0%, #2d2d44 100%);
        padding: 1rem;
        border-radius: 0.75rem;
        border: 1px solid #3d3d5c;
    }
    .agent-card {
        padding: 1rem;
        border-radius: 0.5rem;
        margin-bottom: 0.5rem;
        border-left: 4px solid;
    }
    .agent-active { border-left-color: #00c853; background: #1a2e1a; }
    .agent-quarantined { border-left-color: #ff1744; background: #2e1a1a; }
    .agent-monitoring { border-left-color: #2979ff; background: #1a1a2e; }
    .agent-attacker { border-left-color: #ff6d00; background: #2e1a1a; }
    .threat-alert {
        padding: 1rem;
        border-radius: 0.5rem;
        background: linear-gradient(135deg, #2e1a1a 0%, #3d1a1a 100%);
        border-left: 4px solid #ff1744;
        margin-bottom: 0.5rem;
    }
</style>
""", unsafe_allow_html=True)


# ==========================================
# Main Dashboard
# ==========================================
init_system()

# --- Header ---
st.title("🛡️ Sentinel-MAS Dashboard")
st.caption("Self-Defending Security Framework for Multi-Agent AI Systems")

# --- Sidebar Controls ---
with st.sidebar:
    st.header("🎮 Controls")
    st.divider()
    
    st.subheader("Normal Operations")
    if st.button("▶️ Run Normal Workflow", use_container_width=True, type="primary"):
        run_scenario("normal")
        st.rerun()
    
    st.divider()
    st.subheader("⚔️ Attack Simulations")
    
    if st.button("💉 Prompt Injection", use_container_width=True):
        run_scenario("prompt_injection")
        st.rerun()
    
    if st.button("🔧 Malicious Tool Output", use_container_width=True):
        run_scenario("malicious_tool_output")
        st.rerun()
    
    if st.button("📡 Abnormal Behavior", use_container_width=True):
        run_scenario("abnormal_behavior")
        st.rerun()
    
    if st.button("🔗 Attack Propagation", use_container_width=True):
        run_scenario("attack_propagation")
        st.rerun()
    
    st.divider()
    st.subheader("🔄 System")
    if st.button("🗑️ Reset Experiment", use_container_width=True):
        reset_system()
        st.rerun()
    
    st.divider()
    st.caption(f"LLM: {st.session_state.llm.get_provider_name()}")
    st.caption(f"Messages: {len(st.session_state.message_bus.messages)}")


# ==========================================
# Section A: System Overview
# ==========================================
st.header("📊 System Overview")

mb = st.session_state.message_bus
counts = mb.get_message_count()
quarantined_count = len(mb.quarantined_agents)

col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("Total Agents", "5")
col2.metric("Active Agents", str(5 - quarantined_count))
col3.metric("Quarantined", str(quarantined_count))
col4.metric("Threats Detected", str(counts.get("detected", 0) + counts.get("verified", 0)))
col5.metric("Messages", str(counts.get("total", 0)))


# ==========================================
# Section B: Agent Status
# ==========================================
st.header("🤖 Agent Status")

agents_info = [
    (st.session_state.research_agent, "🔍"),
    (st.session_state.analyst_agent, "📊"),
    (st.session_state.manager_agent, "📋"),
    (st.session_state.attacker_agent, "💀"),
    (st.session_state.defender_agent, "🛡️"),
]

cols = st.columns(5)
for i, (agent, icon) in enumerate(agents_info):
    with cols[i]:
        status_color = {
            AgentStatus.ACTIVE: "🟢",
            AgentStatus.QUARANTINED: "🔴",
            AgentStatus.MONITORING: "🔵",
            AgentStatus.ATTACKER: "💀",
            AgentStatus.INACTIVE: "⚪",
        }
        emoji = status_color.get(agent.status, "❓")
        st.markdown(f"**{icon} {agent.name.replace('Agent', '')}**")
        st.markdown(f"{emoji} `{agent.status.value.upper()}`")


# ==========================================
# Section C & D: Communication Logs & Threat Alerts (Tabs)
# ==========================================
st.header("📋 Activity Monitor")

tab1, tab2, tab3 = st.tabs(["📨 Communication Logs", "🚨 Threat Alerts", "🔗 Attack Propagation"])

with tab1:
    if mb.messages:
        log_data = []
        for msg in mb.messages:
            log_data.append({
                "Time": msg.timestamp[11:19],
                "Sender": msg.sender,
                "Receiver": msg.receiver,
                "Type": msg.message_type.value,
                "Status": msg.status.value,
                "Attack": msg.attack_type.value,
                "Message": msg.content[:80] + "..." if len(msg.content) > 80 else msg.content,
            })
        
        df = pd.DataFrame(log_data)
        
        # Color-code the status
        def highlight_status(val):
            colors = {
                "normal": "background-color: #1a3a1a",
                "detected": "background-color: #3a3a1a",
                "verified": "background-color: #3a1a1a",
                "blocked": "background-color: #3a1a1a",
                "false_positive": "background-color: #1a3a1a",
            }
            return colors.get(val, "")
        
        st.dataframe(
            df.style.map(highlight_status, subset=["Status"]),
            use_container_width=True,
            height=400,
        )
    else:
        st.info("No messages yet. Run a scenario to see communication logs.")

with tab2:
    alerts = st.session_state.defender_agent.get_threat_alerts()
    if alerts:
        for alert in alerts:
            severity = "🔴" if alert["is_confirmed"] else "🟡"
            status_text = "CONFIRMED" if alert["is_confirmed"] else "DISMISSED"
            
            st.markdown(f"""
            <div class="threat-alert">
                <strong>{severity} {alert['threat_type'].upper()}</strong> | 
                Score: {alert['threat_score']:.2f} | 
                Status: {status_text}<br>
                <small>Source: {alert['source']} | 
                Confidence: {alert['confidence']:.2f}</small><br>
                <small>Evidence: {', '.join(alert['evidence'][:3])}</small>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.info("No threat alerts yet. Simulate an attack to see alerts.")

with tab3:
    graph_data = st.session_state.graph.get_graph_data()
    attack_edges = st.session_state.graph.get_attack_path()
    
    if attack_edges:
        st.subheader("Attack Path")
        
        # Build the attack chain display
        chain_parts = []
        for edge in attack_edges:
            sender = edge.get("from", edge.get("from_agent", "?"))
            receiver = edge.get("to", edge.get("to_agent", "?"))
            attack = edge.get("attack_type", "unknown")
            chain_parts.append(f"**{sender}** →[{attack}]→ **{receiver}**")
        
        st.markdown(" | ".join(chain_parts))
        
        # Build a simple flow chart with plotly
        if len(attack_edges) > 0:
            nodes = set()
            for e in attack_edges:
                nodes.add(e.get("from", e.get("from_agent", "")))
                nodes.add(e.get("to", e.get("to_agent", "")))
            nodes = list(nodes)
            
            # Create a Sankey diagram for attack flow
            source_indices = []
            target_indices = []
            values = []
            labels_list = []
            
            for e in attack_edges:
                src = e.get("from", e.get("from_agent", ""))
                tgt = e.get("to", e.get("to_agent", ""))
                if src in nodes and tgt in nodes:
                    source_indices.append(nodes.index(src))
                    target_indices.append(nodes.index(tgt))
                    values.append(1)
            
            if source_indices:
                fig = go.Figure(go.Sankey(
                    node=dict(
                        pad=15,
                        thickness=20,
                        label=nodes,
                        color=["#ff4444" if "Attacker" in n or st.session_state.message_bus.is_quarantined(n) 
                               else "#4444ff" for n in nodes],
                    ),
                    link=dict(
                        source=source_indices,
                        target=target_indices,
                        value=values,
                        color="rgba(255,68,68,0.4)",
                    ),
                ))
                fig.update_layout(
                    title_text="Attack Propagation Flow",
                    font_size=12,
                    height=350,
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                )
                st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No attack propagation data yet. Run an attack scenario.")


# ==========================================
# Section F: Security Metrics
# ==========================================
st.header("📈 Security Metrics")

m = st.session_state.metrics.calculate_all()

if m["total_messages"] > 0:
    col1, col2, col3, col4, col5 = st.columns(5)
    
    col1.metric("Detection Rate", f"{m['detection_rate']:.1%}")
    col2.metric("False Positive Rate", f"{m['false_positive_rate']:.1%}")
    col3.metric("Containment Time", f"{m['containment_time_avg']:.3f}s")
    col4.metric("Propagation Accuracy", f"{m['propagation_accuracy']:.1%}")
    col5.metric("Service Continuity", f"{m['service_continuity']:.1%}")
    
    # Pie chart of message statuses
    status_counts = {
        "Normal": counts.get("normal", 0),
        "Detected": counts.get("detected", 0),
        "Verified": counts.get("verified", 0),
        "Blocked": counts.get("blocked", 0),
        "False Positive": counts.get("false_positive", 0),
    }
    # Remove zero values
    status_counts = {k: v for k, v in status_counts.items() if v > 0}
    
    if status_counts:
        col_chart1, col_chart2 = st.columns(2)
        with col_chart1:
            fig = px.pie(
                names=list(status_counts.keys()),
                values=list(status_counts.values()),
                title="Message Status Distribution",
                color_discrete_map={
                    "Normal": "#00c853",
                    "Detected": "#ffab00",
                    "Verified": "#ff1744",
                    "Blocked": "#d50000",
                    "False Positive": "#00bfa5",
                },
            )
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                height=350,
            )
            st.plotly_chart(fig, use_container_width=True)
        
        with col_chart2:
            # Bar chart of metrics
            metric_names = ["Detection\nRate", "False Positive\nRate", 
                          "Propagation\nAccuracy", "Service\nContinuity"]
            metric_values = [
                m["detection_rate"], m["false_positive_rate"],
                m["propagation_accuracy"], m["service_continuity"],
            ]
            colors = ["#00c853", "#ff1744", "#2979ff", "#00bfa5"]
            
            fig = go.Figure(go.Bar(
                x=metric_names,
                y=metric_values,
                marker_color=colors,
                text=[f"{v:.1%}" for v in metric_values],
                textposition="auto",
            ))
            fig.update_layout(
                title="Security Performance",
                yaxis_title="Rate",
                yaxis_range=[0, 1.1],
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                height=350,
            )
            st.plotly_chart(fig, use_container_width=True)
else:
    st.info("Run some scenarios to see security metrics.")


# ==========================================
# Section: Scenario Log
# ==========================================
if st.session_state.scenario_log:
    st.header("📝 Scenario Execution Log")
    for entry in reversed(st.session_state.scenario_log[-10:]):
        icon = "✅" if entry["scenario"] == "normal" else "⚔️"
        st.markdown(
            f"`{entry['timestamp']}` {icon} **{entry['scenario']}** — "
            f"{entry['result'].get('status', 'unknown')}"
        )


# ==========================================
# Footer
# ==========================================
st.divider()
st.caption(
    "🛡️ Sentinel-MAS | Academic Research Project | "
    "All attacks are simulated within a controlled sandbox environment."
)
