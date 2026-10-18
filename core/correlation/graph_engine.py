"""
ThreatFusion CTI - In-Memory NetworkX Knowledge Graph Engine
Synthesizes entity links across Actors, Campaigns, Malware, IOCs, CVEs, Sectors, and MITRE TTPs.
"""

from typing import Dict, Any, List, Set, Tuple, Optional
import json
from datetime import datetime
import networkx as nx
import pandas as pd

from config.settings import PROCESSED_DATA_DIR, GRAPH_DATA_DIR, PARQUET_COMPRESSION_CODEC
from config.logging_config import setup_logger
from database.parquet_store import ParquetStore
from core.correlation.graph_models import GraphNode, GraphEdge, RelationTypes, ConfidenceScorer

logger = setup_logger("GraphEngine")


class KnowledgeGraphEngine:
    NODE_COLORS = {
        "ACTOR": "#F85149",       # Red
        "CAMPAIGN": "#D29922",    # Amber
        "MALWARE": "#BC8CFF",     # Purple
        "IOC": "#58A6FF",         # Blue
        "CVE": "#F0883E",         # Orange
        "TECHNIQUE": "#3FB950",   # Green
        "COUNTRY": "#39D353",     # Lime
        "SECTOR": "#79C0FF"       # Sky Blue
    }

    def __init__(self, store: Optional[ParquetStore] = None) -> None:
        self.store = store or ParquetStore()
        self.graph = nx.DiGraph()
        self.nodes_parquet = GRAPH_DATA_DIR / "nodes.parquet"
        self.edges_parquet = GRAPH_DATA_DIR / "edges.parquet"

    def build_graph_from_lake(self) -> nx.DiGraph:
        """
        Reads processed lakehouse tables (reports, iocs, actors, malware, campaigns)
        and compiles a unified directed knowledge graph.
        """
        self.graph.clear()
        logger.info("Compiling Threat Knowledge Graph from Lakehouse storage...")

        # 1. Load Processed Tables
        df_reports = self.store.read_table("reports")
        df_iocs = self.store.read_table("iocs")

        # 2. Extract and correlate entities from processed reports
        if not df_reports.empty:
            for _, r in df_reports.iterrows():
                rep_id = str(r.get("report_id", ""))
                actors = r.get("extracted_actors", []) or []
                malware = r.get("extracted_malware", []) or []
                cves = r.get("extracted_cves", []) or []
                techs = r.get("mitre_hits", []) or []
                countries = r.get("target_countries", []) or []
                sectors = r.get("extracted_sectors", []) or []
                campaigns = r.get("extracted_campaigns", []) or []
                report_iocs = r.get("extracted_iocs", []) or []

                # Add Actor Nodes
                for act in actors:
                    self.upsert_node("ACTOR", act, {"name": act})
                    # Actor -> Malware
                    for mal in malware:
                        self.upsert_node("MALWARE", mal, {"name": mal})
                        self.upsert_edge("ACTOR", act, RelationTypes.ACTOR_USES_MALWARE, "MALWARE", mal, rep_id)

                    # Actor -> CVE
                    for cve in cves:
                        self.upsert_node("CVE", cve, {"cve_id": cve})
                        self.upsert_edge("ACTOR", act, RelationTypes.ACTOR_EXPLOITS_VULNERABILITY, "CVE", cve, rep_i

                    # Actor -> Technique
                    for tech in techs:
                        self.upsert_node("TECHNIQUE", tech, {"technique_id": tech})
                        self.upsert_edge("ACTOR", act, RelationTypes.ACTOR_EXHIBITS_TECHNIQUE, "TECHNIQUE", tech, re

                    # Actor -> Sector
                    for sec in sectors:
                        self.upsert_node("SECTOR", sec, {"name": sec})
                        self.upsert_edge("ACTOR", act, RelationTypes.ACTOR_TARGETS_SECTOR, "SECTOR", sec, rep_id)

                    # Actor -> Country
                    for ctry in countries:
                        self.upsert_node("COUNTRY", ctry, {"code": ctry})
                        self.upsert_edge("ACTOR", act, RelationTypes.ACTOR_TARGETS_COUNTRY, "COUNTRY", ctry, rep_id)

                # Add Campaign Nodes
                for camp in campaigns:
                    self.upsert_node("CAMPAIGN", camp, {"name": camp})
                    # Actor -> Campaign
                    for act in actors:
                        self.upsert_edge("ACTOR", act, RelationTypes.ACTOR_CONDUCTS_CAMPAIGN, "CAMPAIGN", camp, rep_
                    # Campaign -> Malware
                    for mal in malware:
                        self.upsert_edge("CAMPAIGN", camp, RelationTypes.CAMPAIGN_DEPLOYS_MALWARE, "MALWARE", mal, r
                    # Campaign -> Sector
                    for sec in sectors:
                        self.upsert_edge("CAMPAIGN", camp, RelationTypes.CAMPAIGN_TARGETS_SECTOR, "SECTOR", sec, rep

                # Malware -> Techniques
                for mal in malware:
                    for tech in techs:
                        self.upsert_edge("MALWARE", mal, RelationTypes.MALWARE_EXHIBITS_TECHNIQUE, "TECHNIQUE", tech

        # 3. Extract and correlate IOC Nodes from iocs table
        if not df_iocs.empty:
            for _, ioc in df_iocs.iterrows():
                raw_val = str(ioc.get("ioc_value", ""))
                ioc_type = str(ioc.get("ioc_type", "IOC"))
                decay_score = float(ioc.get("decay_score", 100.0))

                self.upsert_node("IOC", raw_val, {
                    "type": ioc_type,
                    "value": raw_val,
                    "decay_score": decay_score,
                    "c2_flag": bool(ioc.get("c2_flag", False))
                })

                # Link IOC to Malware
                for mal in (ioc.get("malware_families") or []):
                    self.upsert_node("MALWARE", mal, {"name": mal})
                    self.upsert_edge("MALWARE", mal, RelationTypes.MALWARE_COMMUNICATES_WITH_IOC, "IOC", raw_val)

                # Link IOC to Campaigns
                for camp in (ioc.get("campaigns") or []):
                    self.upsert_node("CAMPAIGN", camp, {"name": camp})
                    self.upsert_edge("CAMPAIGN", camp, RelationTypes.CAMPAIGN_UTILIZES_IOC, "IOC", raw_val)

        # Compute graph centrality scores
        if len(self.graph.nodes) > 0:
            degree_centralities = nx.degree_centrality(self.graph)
            for node_id, centrality in degree_centralities.items():
                self.graph.nodes[node_id]["degree_centrality"] = round(float(centrality), 4)

        logger.info(f"Knowledge Graph ready: {self.graph.number_of_nodes()} Nodes, {self.graph.number_of_edges()} Ed
        self.persist_graph_tables()
        return self.graph

    def upsert_node(self, node_type: str, label: str, attributes: Optional[Dict[str, Any]] = None) -> str:
        node_id = GraphNode.format_id(node_type, label)
        if not self.graph.has_node(node_id):
            self.graph.add_node(
                node_id,
                node_type=node_type,
                label=label,
                color=self.NODE_COLORS.get(node_type, "#C9D1D9"),
                attributes=json.dumps(attributes or {}),
                first_seen=datetime.utcnow().isoformat(),
                last_seen=datetime.utcnow().isoformat(),
                degree_centrality=0.0
            )
        else:
            self.graph.nodes[node_id]["last_seen"] = datetime.utcnow().isoformat()
            if attributes:
                curr_attr = json.loads(self.graph.nodes[node_id].get("attributes", "{}"))
                curr_attr.update(attributes)
                self.graph.nodes[node_id]["attributes"] = json.dumps(curr_attr)
        return node_id

    def upsert_edge(
        self,
        s_type: str, s_label: str,
        rel: str,
        t_type: str, t_label: str,
        evidence_report: str = ""
    ) -> None:
        source_id = GraphNode.format_id(s_type, s_label)
        target_id = GraphNode.format_id(t_type, t_label)

        if not self.graph.has_node(source_id):
            self.upsert_node(s_type, s_label)
        if not self.graph.has_node(target_id):
            self.upsert_node(t_type, t_label)

        edge_id = GraphEdge.generate_id(source_id, rel, target_id)

        if self.graph.has_edge(source_id, target_id):
            edge_data = self.graph[source_id][target_id]
            edge_data["weight"] += 1.0
            reports = edge_data.get("evidence_reports", [])
            if evidence_report and evidence_report not in reports:
                reports.append(evidence_report)
            edge_data["evidence_reports"] = reports
            edge_data["last_observed"] = datetime.utcnow().isoformat()

            # Recalculate dynamic confidence score
            edge_data["confidence_score"] = ConfidenceScorer.calculate_edge_confidence(
                corroboration_count=int(edge_data["weight"])
            )
        else:
            conf = ConfidenceScorer.calculate_edge_confidence(corroboration_count=1)
            reports = [evidence_report] if evidence_report else []
            self.graph.add_edge(
                source_id,
                target_id,
                edge_id=edge_id,
                relation_type=rel,
                weight=1.0,
                confidence_score=conf,
                evidence_reports=reports,
                first_observed=datetime.utcnow().isoformat(),
                last_observed=datetime.utcnow().isoformat()
            )

    def persist_graph_tables(self) -> None:
        """Serializes current NetworkX graph into nodes.parquet and edges.parquet."""
        # 1. Nodes Table
        nodes_data = []
        for n_id, attrs in self.graph.nodes(data=True):
            nodes_data.append({
                "node_id": n_id,
                "node_type": attrs.get("node_type", "UNKNOWN"),
                "display_label": attrs.get("label", n_id),
                "degree_centrality": attrs.get("degree_centrality", 0.0),
                "attributes_json": attrs.get("attributes", "{}")
            })
        df_nodes = pd.DataFrame(nodes_data)
        if not df_nodes.empty:
            df_nodes.to_parquet(self.nodes_parquet, compression=PARQUET_COMPRESSION_CODEC)

        # 2. Edges Table
        edges_data = []
        for u, v, attrs in self.graph.edges(data=True):
            edges_data.append({
                "edge_id": attrs.get("edge_id", GraphEdge.generate_id(u, attrs.get("relation_type", ""), v)),
                "source_node": u,
                "target_node": v,
                "relation_type": attrs.get("relation_type", "RELATED_TO"),
                "confidence": attrs.get("confidence_score", 50.0),
                "weight": attrs.get("weight", 1.0),
                "first_observed": attrs.get("first_observed", datetime.utcnow().isoformat()),
                "last_observed": attrs.get("last_observed", datetime.utcnow().isoformat()),
                "evidence_reports": attrs.get("evidence_reports", [])
            })
        df_edges = pd.DataFrame(edges_data)
        if not df_edges.empty:
            df_edges.to_parquet(self.edges_parquet, compression=PARQUET_COMPRESSION_CODEC)

    def extract_subgraph(self, center_node_id: str, depth: int = 1) -> nx.DiGraph:
        """Extracts an ego subgraph centered on a specific entity node."""
        if not self.graph.has_node(center_node_id):
            return nx.DiGraph()

        current_nodes = {center_node_id}
        for _ in range(depth):
            next_level = set(current_nodes)
            for n in current_nodes:
                next_level.update(self.graph.predecessors(n))
                next_level.update(self.graph.successors(n))
            current_nodes = next_level

        return self.graph.subgraph(current_nodes).copy()
