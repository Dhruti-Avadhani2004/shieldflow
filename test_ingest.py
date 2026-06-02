from app.parsers.semgrep_parser import parse_semgrep_report
from app.services.ingestion_service import ingest_findings

from app.database.session import SessionLocal

db = SessionLocal()

findings = parse_semgrep_report("reports/semgrep.json")

ingest_findings(findings, db)

print("Ingestion complete:", len(findings))