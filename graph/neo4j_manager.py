"""
Sentinel-MAS: Neo4j Graph Manager
====================================
Manages the Neo4j graph database for communication and attack analysis.

Graph Model:
- Nodes = Agents (with properties: name, status, role)
- Relationships = Messages (with properties: timestamp, type, status, attack_type)

This allows us to:
- Visualize agent communication topology
- Trace attack propagation paths
- Identify compromised nodes
- Analyze the spread of attacks

IMPORTANT: The system works WITHOUT Neo4j too.
If Neo4j is not available, we fall back to a simple in-memory graph
(dictionaries of nodes and edges) that needs no external dependencies.
"""

from typing import Optional
from communication.message_models import Message
from config.settings import settings


class Neo4jManager:
    """
    Manages Neo4j graph database operations.
    
    Falls back to an in-memory graph (dict of nodes + list of edges)
    if Neo4j is unavailable.
    """

    def __init__(self):
        self._driver = None
        self._use_neo4j = False
        self._memory_graph = {
            "nodes": {},   # agent_name -> {properties}
            "edges": [],   # list of {from, to, properties}
        }

        # Try to connect to Neo4j
        self._try_connect()

    def _try_connect(self):
        """Attempt to connect to Neo4j. Fall back gracefully if unavailable."""
        if not settings.NEO4J_PASSWORD or settings.NEO4J_PASSWORD == "your_neo4j_password_here":
            print("[INFO] Neo4j not configured. Using in-memory graph. "
                  "(Set NEO4J_PASSWORD in .env to enable Neo4j)")
            return

        try:
            from neo4j import GraphDatabase
            self._driver = GraphDatabase.driver(
                settings.NEO4J_URI,
                auth=(settings.NEO4J_USER, settings.NEO4J_PASSWORD),
            )
            # Test connection
            with self._driver.session() as session:
                session.run("RETURN 1")
            self._use_neo4j = True
            print("[OK] Connected to Neo4j successfully!")
        except Exception as e:
            print(f"[WARN] Neo4j connection failed: {e}")
            print("   Using in-memory graph instead.")
            self._driver = None
            self._use_neo4j = False

    # ==========================================
    # Agent (Node) Operations
    # ==========================================

    def add_agent(self, name: str, role: str, status: str = "active"):
        """Add an agent node to the graph."""
        if self._use_neo4j:
            self._neo4j_add_agent(name, role, status)
        else:
            self._memory_graph["nodes"][name] = {
                "name": name,
                "role": role,
                "status": status,
            }

    def update_agent_status(self, name: str, status: str):
        """Update an agent's status (e.g., 'quarantined')."""
        if self._use_neo4j:
            self._neo4j_update_agent_status(name, status)
        else:
            if name in self._memory_graph["nodes"]:
                self._memory_graph["nodes"][name]["status"] = status

    # ==========================================
    # Message (Relationship) Operations
    # ==========================================

    def add_message(self, message: Message):
        """Add a message as a relationship between two agent nodes."""
        if self._use_neo4j:
            self._neo4j_add_message(message)
        else:
            self._memory_graph["edges"].append({
                "from": message.sender,
                "to": message.receiver,
                "message_id": message.message_id,
                "timestamp": message.timestamp,
                "message_type": message.message_type.value,
                "attack_type": message.attack_type.value,
                "status": message.status.value,
                "is_threat": message.is_threat,
            })

    # ==========================================
    # Query Operations
    # ==========================================

    def get_attack_path(self, task_id: Optional[str] = None) -> list[dict]:
        """
        Get the attack propagation path.
        
        Returns a list of edges that are part of an attack chain.
        """
        if self._use_neo4j:
            return self._neo4j_get_attack_path(task_id)
        else:
            # Filter edges for attack-related messages
            attack_edges = [
                e for e in self._memory_graph["edges"]
                if e["is_threat"] or e["attack_type"] != "none"
            ]
            return attack_edges

    def get_agent_connections(self) -> dict:
        """Get all agent connections for visualization."""
        connections = {}
        edges = self._memory_graph["edges"] if not self._use_neo4j else self._neo4j_get_all_edges()

        for edge in edges:
            if not isinstance(edge, dict):
                continue
            sender = edge.get("from", "")
            if sender not in connections:
                connections[sender] = []
            connections[sender].append(edge)

        return connections

    def get_graph_data(self) -> dict:
        """Get complete graph data for dashboard visualization."""
        if self._use_neo4j:
            return self._neo4j_get_graph_data()
        return self._memory_graph

    # ==========================================
    # Neo4j Implementation
    # ==========================================

    def _neo4j_add_agent(self, name: str, role: str, status: str):
        with self._driver.session() as session:
            session.run(
                "MERGE (a:Agent {name: $name}) "
                "SET a.role = $role, a.status = $status",
                name=name, role=role, status=status,
            )

    def _neo4j_update_agent_status(self, name: str, status: str):
        with self._driver.session() as session:
            session.run(
                "MATCH (a:Agent {name: $name}) SET a.status = $status",
                name=name, status=status,
            )

    def _neo4j_add_message(self, message: Message):
        with self._driver.session() as session:
            session.run(
                "MATCH (sender:Agent {name: $sender}) "
                "MATCH (receiver:Agent {name: $receiver}) "
                "CREATE (sender)-[:SENT_MESSAGE {"
                "  message_id: $msg_id, "
                "  timestamp: $timestamp, "
                "  message_type: $msg_type, "
                "  attack_type: $attack_type, "
                "  status: $status, "
                "  is_threat: $is_threat"
                "}]->(receiver)",
                sender=message.sender,
                receiver=message.receiver,
                msg_id=message.message_id,
                timestamp=message.timestamp,
                msg_type=message.message_type.value,
                attack_type=message.attack_type.value,
                status=message.status.value,
                is_threat=message.is_threat,
            )

    def _neo4j_get_attack_path(self, task_id: Optional[str] = None) -> list[dict]:
        with self._driver.session() as session:
            result = session.run(
                "MATCH (a:Agent)-[r:SENT_MESSAGE]->(b:Agent) "
                "WHERE r.is_threat = true OR r.attack_type <> 'none' "
                "RETURN a.name AS from_agent, b.name AS to_agent, "
                "r.message_type AS message_type, r.attack_type AS attack_type, "
                "r.timestamp AS timestamp, r.status AS status "
                "ORDER BY r.timestamp"
            )
            return [
                {
                    "from": record["from_agent"],
                    "to": record["to_agent"],
                    "message_type": record["message_type"],
                    "attack_type": record["attack_type"],
                    "timestamp": record["timestamp"],
                    "status": record["status"],
                }
                for record in result
            ]

    def _neo4j_get_all_edges(self) -> list[dict]:
        with self._driver.session() as session:
            result = session.run(
                "MATCH (a:Agent)-[r:SENT_MESSAGE]->(b:Agent) "
                "RETURN a.name AS from_agent, b.name AS to_agent, "
                "r.message_type AS message_type, r.attack_type AS attack_type, "
                "r.status AS status, r.is_threat AS is_threat "
                "ORDER BY r.timestamp"
            )
            return [
                {
                    "from": record["from_agent"],
                    "to": record["to_agent"],
                    "message_type": record["message_type"],
                    "attack_type": record["attack_type"],
                    "status": record["status"],
                    "is_threat": record["is_threat"],
                }
                for record in result
            ]

    def _neo4j_get_graph_data(self) -> dict:
        nodes = {}
        with self._driver.session() as session:
            result = session.run(
                "MATCH (a:Agent) RETURN a.name AS name, a.role AS role, a.status AS status"
            )
            for record in result:
                nodes[record["name"]] = {
                    "name": record["name"],
                    "role": record["role"],
                    "status": record["status"],
                }
        edges = self._neo4j_get_all_edges()
        return {"nodes": nodes, "edges": edges}

    # ==========================================
    # Maintenance
    # ==========================================

    def clear(self):
        """Clear all graph data."""
        if self._use_neo4j:
            with self._driver.session() as session:
                session.run("MATCH (n) DETACH DELETE n")
        self._memory_graph = {"nodes": {}, "edges": []}

    def close(self):
        """Close the Neo4j connection."""
        if self._driver:
            self._driver.close()
