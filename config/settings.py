"""
ThreatFusion CTI - Global Application Settings & Paths
"""

import os
from pathlib import Path
from typing import Dict, Any

# Base & Core Directory Hierarchy
BASE_DIR: Path = Path(__file__).resolve().parent.parent
CONFIG_DIR: Path = BASE_DIR / "config"
DATA_DIR: Path = BASE_DIR / "data"
RAW_DATA_DIR: Path = DATA_DIR / "raw"
PROCESSED_DATA_DIR: Path = DATA_DIR / "processed"
GRAPH_DATA_DIR: Path = DATA_DIR / "graph"
SIGNATURES_DIR: Path = DATA_DIR / "signatures"
REPORTS_DIR: Path = DATA_DIR / "reports"
ASSETS_DIR: Path = BASE_DIR / "assets"
CSS_DIR: Path = ASSETS_DIR / "css"

# Ensure critical data directories exist
for directory in [DATA_DIR, RAW_DATA_DIR, PROCESSED_DATA_DIR, GRAPH_DATA_DIR, SIGNATURES_DIR, REPORTS_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

# Storage Configuration
PARQUET_COMPRESSION_CODEC: str = "zstd"

# Temporal & Scoring Defaults
DECAY_HALF_LIFE_DAYS: float = 30.0
CONFIDENCE_BASE_WEIGHTS: Dict[str, float] = {
    "HIGH_TRUST": 1.25,
    "MEDIUM_TRUST": 1.0,
    "LOW_TRUST": 0.75,
}

# Theme Configuration
THEME_CONFIG: Dict[str, str] = {
    "BG_COLOR": "#0E1117",
    "SURFACE_COLOR": "#161B22",
    "BORDER_COLOR": "#30363D",
    "TEXT_PRIMARY": "#C9D1D9",
    "TEXT_MUTED": "#8B949E",
    "ACCENT_CYAN": "#58A6FF",
    "ACCENT_RED": "#F85149",
    "ACCENT_AMBER": "#D29922",
    "ACCENT_GREEN": "#3FB950",
    "ACCENT_PURPLE": "#BC8CFF",
}

APP_TITLE: str = "ThreatFusion CTI"
APP_SUBTITLE: str = "Enterprise Cyber Threat Intelligence Platform"
