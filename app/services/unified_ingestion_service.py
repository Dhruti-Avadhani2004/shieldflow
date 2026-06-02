# from uuid import uuid4
# from app.database.models import FindingDB
# from datetime import datetime


# def ingest_findings(findings, db):
#     for f in findings:

#         new_finding = FindingDB(
#             id=str(uuid4()),

#             tool=f["tool"],
#             type=f["type"],

#             title=f["title"],
#             severity=f["severity"],

#             file=f.get("file"),
#             line=f.get("line"),

#             description=f.get("description"),
#             evidence=f.get("evidence"),

#             status="OPEN",

#             created_at=datetime.utcnow(),
#             last_seen=datetime.utcnow(),
#         )

#         db.add(new_finding)

#     db.commit()


from app.parsers.semgrep_parser import parse_semgrep_report
from app.parsers.gitleaks_parser import parse_gitleaks_report
from app.parsers.trivy_parser import parse_trivy_report
from app.services.ingestion_service import ingest_findings


def run_full_ingestion(db):

    semgrep_findings = parse_semgrep_report("semgrep.json")
    gitleaks_findings = parse_gitleaks_report("gitleaks.json")
    trivy_findings = parse_trivy_report("trivy.json")

    all_findings = semgrep_findings + gitleaks_findings + trivy_findings

    return ingest_findings(all_findings, db)