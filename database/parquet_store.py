import os
from pathlib import Path
from typing import Dict, Any, List
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import duckdb

from config.settings import (
    PROCESSED_DATA_DIR,
    GRAPH_DATA_DIR,
    RAW_DATA_DIR,
    SIGNATURES_DIR,
    PARQUET_COMPRESSION_CODEC
)
from config.logging_config import setup_logger

logger = setup_logger("ParquetStore")

class ParquetStore:
    def __init__(self) -> None:
        self.processed_dir: Path = PROCESSED_DATA_DIR
        self.graph_dir: Path = GRAPH_DATA_DIR
        self.raw_dir: Path = RAW_DATA_DIR
        self.sig_dir: Path = SIGNATURES_DIR
        self.duck_conn: duckdb.DuckDBPyConnection = duckdb.connect(database=":memory:")
        self._ensure_directories()

    def _ensure_directories(self) -> None:
        for p in [self.processed_dir, self.graph_dir, self.raw_dir, self.sig_dir]:
            p.mkdir(parents=True, exist_ok=True)

    def initialize_lake(self) -> None:
        """Create empty Parquet tables with explicit types if not already existing."""
        tables: Dict[str, Dict[str, Any]] = {
            "actors": {
                "actor_id": "string", "canonical_name": "string", "aliases": "object",
                "origin_country": "string", "motivation": "object", "sophistication": "string",
                "first_observed": "datetime64[ns]", "last_observed": "datetime64[ns]",
                "targeted_countries": "object", "targeted_sectors": "object",
                "active_status": "bool", "confidence_score": "float64", "updated_at": "datetime64[ns]"
            },
            "malware": {
                "malware_id": "string", "canonical_name": "string", "aliases": "object",
                "malware_type": "object", "target_os": "object", "capabilities": "object",
                "is_open_source": "bool", "first_seen": "datetime64[ns]", "last_seen": "datetime64[ns]",
                "confidence_score": "float64"
            },
            "campaigns": {
                "campaign_id": "string", "campaign_name": "string", "threat_actors": "object",
                "target_regions": "object", "target_sectors": "object", "target_countries": "object",
                "start_date": "datetime64[ns]", "end_date": "datetime64[ns]", "confidence_score": "float64",
                "object_summary": "string", "created_at": "datetime64[ns]"
            },
            "iocs": {
                "ioc_id": "string", "ioc_type": "string", "ioc_value": "string",
                "c2_flag": "bool", "asn": "Int64", "asn_org": "string", "country_code": "string",
                "threat_actors": "object", "campaigns": "object", "malware_families": "object",
                "first_seen": "datetime64[ns]", "last_seen": "datetime64[ns]",
                "decay_score": "float64", "is_active": "bool"
            },
            "vulnerabilities": {
                "cve_id": "string", "cvss_v3_score": "float64", "cvss_vector": "string",
                "cwe_id": "object", "is_known_exploited": "bool", "ransomware_use": "bool",
                "affected_vendors": "object", "affected_products": "object",
                "first_published": "datetime64[ns]"
            },
            "reports": {
                "report_id": "string", "source_name": "string", "title": "string",
                "url": "string", "publish_date": "datetime64[ns]", "raw_text_path": "string",
                "extracted_actors": "object", "extracted_malware": "object",
                "extracted_cves": "object", "extracted_iocs": "object", "mitre_hits": "object"
            }
        }

        for table_name, schema_dict in tables.items():
            file_path = self.processed_dir / f"{table_name}.parquet"
            if not file_path.exists():
                df = pd.DataFrame({col: pd.Series(dtype=dt) for col, dt in schema_dict.items()})
                self.write_table(table_name, df)
                logger.info(f"Initialized blank table: {file_path.name}")

        # Initialize Graph Tables
        graph_tables = {
            "nodes": {
                "node_id": "string", "node_type": "string", "display_label": "string",
                "degree_centrality": "float64", "attributes_json": "string"
            },
            "edges": {
                "edge_id": "string", "source_node": "string", "target_node": "string",
                "relation_type": "string", "confidence": "float64", "weight": "float64",
                "first_observed": "datetime64[ns]", "last_observed": "datetime64[ns]",
                "evidence_reports": "object"
            }
        }
        for g_name, g_schema in graph_tables.items():
            g_path = self.graph_dir / f"{g_name}.parquet"
            if not g_path.exists():
                df_g = pd.DataFrame({col: pd.Series(dtype=dt) for col, dt in g_schema.items()})
                self.write_table(g_name, df_g, is_graph=True)
                logger.info(f"Initialized blank graph table: {g_path.name}")

    def write_table(self, table_name: str, df: pd.DataFrame, is_graph: bool = False) -> None:
        target_dir = self.graph_dir if is_graph else self.processed_dir
        target_path = target_dir / f"{table_name}.parquet"
        arrow_table = pa.Table.from_pandas(df)
        pq.write_table(arrow_table, target_path, compression=PARQUET_COMPRESSION_CODEC)

    def read_table(self, table_name: str, is_graph: bool = False) -> pd.DataFrame:
        target_dir = self.graph_dir if is_graph else self.processed_dir
        target_path = target_dir / f"{table_name}.parquet"
        if not target_path.exists():
            return pd.DataFrame()
        return pq.read_table(target_path).to_pandas()

    def query(self, sql_query: str) -> pd.DataFrame:
        """Execute in-memory DuckDB analytical queries across all active Parquet files."""
        # Register views pointing directly to local Parquet files
        for f in self.processed_dir.glob("*.parquet"):
            self.duck_conn.execute(f"CREATE OR REPLACE VIEW {f.stem} AS SELECT * FROM read_parquet('{f.as_posix()}')
        for f in self.graph_dir.glob("*.parquet"):
            self.duck_conn.execute(f"CREATE OR REPLACE VIEW {f.stem} AS SELECT * FROM read_parquet('{f.as_posix()}')
        return self.duck_conn.execute(sql_query).df()
