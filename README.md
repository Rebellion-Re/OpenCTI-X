# ThreatFusion CTI - Enterprise Cyber Threat Intelligence Platform

ThreatFusion CTI is an open-architecture Cyber Threat Intelligence (CTI) and Knowledge Graph platform built with Pyt

## Key Architecture Principles
- **Zero Paid/Token AI Dependencies:** Threat correlation, IOC parsing, TTP taggers, and entity resolution operate d
- **Columnar Lakehouse Storage:** Analytical data is stored in Apache Parquet format (`data/processed/` and `data/gr
- **Automated Ingestion:** GitHub Actions cron workflows continuously harvest threat intel feeds, parse IOCs, calcul
- **Enterprise Dark Theme:** Styled after OpenCTI and SOC consoles with custom CSS components.

## Directory Structure
- `.github/workflows/`: Automated ingestion, compacting, and testing pipelines.
- `config/`: Central configurations, source registries (`sources.yaml`), and alias maps.
- `database/`: Schema validation (`pydantic`), Parquet store (`pyarrow`), and DuckDB integration.
- `utils/`: High-performance deterministic parsers (IOC, MITRE TTP, Entity Resolver).
- `pages/`: Streamlit analytical multi-page dashboards.
- `assets/`: Custom enterprise SOC dark CSS and styling components.

## Getting Started

### Local Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/your-org/ThreatFusion-CTI.git
   cd ThreatFusion-CTI
   ```

2. Create and activate a Python virtual environment:
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

3. Install required packages:
```bash
pip install -r requirements.txt
```

4. Initialize the data directory:
```bash
python -c "from database.parquet_store import ParquetStore; ps = ParquetStore(); ps.initialize_lake()"
```

5. Run the Streamlit application:
```bash
streamlit run app.py
```
