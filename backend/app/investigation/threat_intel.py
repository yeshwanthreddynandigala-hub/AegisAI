"""
Threat Intelligence & Cross-Incident Correlation Engine.
Computes behavioral similarities and clusters related incidents across sessions.
Maintains graph relations strictly for behavioral patterns without fabricating attribution.
"""

from typing import List, Dict, Any, Set
from sqlalchemy.orm import Session

from app.models.incident import IncidentModel
from app.models.event import SecurityEventModel

class ThreatIntelligenceCorrelator:
    """Discovers shared campaign indicators and behavioral graphs across incidents."""

    def build_threat_graph(self, db: Session) -> Dict[str, Any]:
        """
        Constructs a node-edge graph representation of incidents and shared behavioral patterns.
        Distinguishes between similar behavioral signatures and shared mock infrastructure.
        """
        incidents = db.query(IncidentModel).all()
        events = db.query(SecurityEventModel).all()

        events_by_session: Dict[str, List[SecurityEventModel]] = {}
        for e in events:
            events_by_session.setdefault(e.session_id, []).append(e)

        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []

        # 1. Add Incident Nodes
        incident_profiles: Dict[str, Dict[str, Any]] = {}
        for inc in incidents:
            sess_events = events_by_session.get(inc.session_id, [])
            tools = list(set(e.tool_name for e in sess_events if e.tool_name))
            resources = list(set(e.resource for e in sess_events if e.resource))

            incident_profiles[inc.incident_id] = {
                "incident": inc,
                "tools": set(tools),
                "resources": set(resources),
                "category": inc.primary_threat_category
            }

            nodes.append({
                "id": inc.incident_id,
                "label": inc.title[:32],
                "type": "INCIDENT",
                "severity": inc.severity,
                "category": inc.primary_threat_category,
                "agent_id": inc.agent_id,
                "created_at": inc.created_at.isoformat()
            })

        # 2. Add Category Nodes
        categories = list(set(inc.primary_threat_category for inc in incidents))
        for cat in categories:
            cat_id = f"CAT_{cat}"
            nodes.append({
                "id": cat_id,
                "label": cat.replace("_", " ").title(),
                "type": "THREAT_CATEGORY"
            })

            # Edge from incident to category
            for inc in incidents:
                if inc.primary_threat_category == cat:
                    edges.append({
                        "source": inc.incident_id,
                        "target": cat_id,
                        "relationship": "CLASSIFIED_AS",
                        "weight": 1.0
                    })

        # 3. Correlate Incidents Based on Shared Behavioral Patterns & Resources
        inc_ids = list(incident_profiles.keys())
        for i in range(len(inc_ids)):
            for j in range(i + 1, len(inc_ids)):
                id_a = inc_ids[i]
                id_b = inc_ids[j]
                prof_a = incident_profiles[id_a]
                prof_b = incident_profiles[id_b]

                # Resource overlap
                common_resources = prof_a["resources"].intersection(prof_b["resources"])
                # Tool overlap
                common_tools = prof_a["tools"].intersection(prof_b["tools"])

                similarity_score = 0.0
                if prof_a["category"] == prof_b["category"]:
                    similarity_score += 0.4
                if common_resources:
                    similarity_score += 0.4
                if len(common_tools) >= 2:
                    similarity_score += 0.2

                if similarity_score >= 0.6:
                    edges.append({
                        "source": id_a,
                        "target": id_b,
                        "relationship": "BEHAVIORAL_SIMILARITY",
                        "weight": round(similarity_score, 2),
                        "shared_targets": list(common_resources),
                        "attribution_disclaimer": "Behavioral pattern similarity only. No individual attribution implied."
                    })

        return {
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "nodes": nodes,
            "edges": edges
        }

threat_correlator = ThreatIntelligenceCorrelator()
