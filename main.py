from fastapi import FastAPI
from app.models import Finding
from uuid import uuid4
from datetime import datetime

from app.parsers.semgrep_parser import parse_semgrep_report
from app.services.ingestion_service import ingest_findings

from app.models import Finding
from app.utils import generate_finding_hash

from app.database.connection import engine
from app.database.models import FindingDB

from app.database.connection import Base

Base.metadata.create_all(bind=engine)

from fastapi import Depends

from sqlalchemy.orm import Session

from app.database.models import FindingDB
from app.database.session import get_db

app = FastAPI()



@app.get("/")
def root():
    return {"message": "ShieldFlow is running"}

# @app.post("/findings")
# def create_finding(
#     finding: Finding,
#     db: Session = Depends(get_db)
# ):

#     stored_finding = FindingDB(
#         id=str(uuid4()),
#         created_at=datetime.utcnow().isoformat(),
#         finding_hash=generate_finding_hash(
#             finding.tool,
#             finding.title,
#             finding.file
#         ),

#         tool=finding.tool,
#         type=finding.type,
#         title=finding.title,
#         severity=finding.severity,
#         file=finding.file,
#         line=finding.line,
#         description=finding.description,
#         status=finding.status
#     )

#     db.add(stored_finding)

#     db.commit()

#     return {
#         "message": "finding stored",
#         "id": stored_finding.id
#     }

@app.post("/findings")
def create_finding(
    finding: Finding,
    db: Session = Depends(get_db)
):

    finding_hash = generate_finding_hash(
        finding.tool,
        finding.title,
        finding.file
    )

    existing_finding = db.query(FindingDB).filter(
        FindingDB.finding_hash == finding_hash
    ).first()

    # Finding already exists
    if existing_finding:

        existing_finding.occurrence_count += 1

        existing_finding.last_seen = datetime.utcnow().isoformat()

        db.commit()

        return {
            "message": "finding already exists",
            "occurrence_count": existing_finding.occurrence_count,
            "finding_id": existing_finding.id
        }

    # New finding
    stored_finding = FindingDB(
        id=str(uuid4()),

        finding_hash=finding_hash,

        tool=finding.tool,
        type=finding.type,

        title=finding.title,
        severity=finding.severity,

        file=finding.file,
        line=finding.line,

        description=finding.description,

        status=finding.status,

        created_at=datetime.utcnow().isoformat(),

        last_seen=datetime.utcnow().isoformat(),

        occurrence_count=1
    )

    db.add(stored_finding)

    db.commit()

    return {
        "message": "new finding created",
        "id": stored_finding.id
    }

@app.get("/findings")
def get_findings(
    db: Session = Depends(get_db)
):

    findings = db.query(FindingDB).all()

    return findings

import os
from fastapi import Depends
from sqlalchemy.orm import Session

@app.post("/ingest/semgrep")
def ingest_semgrep(db: Session = Depends(get_db)):

    report_path = "reports/semgrep.json"

    if not os.path.exists(report_path):
        return {
            "message": "semgrep report not found",
            "path": report_path
        }

    findings = parse_semgrep_report(report_path)

    ingest_findings(findings, db)

    return {
        "message": "semgrep ingestion completed",
        "findings_ingested": len(findings)
    }


from fastapi import Depends
from sqlalchemy.orm import Session
import os

from app.parsers.semgrep_parser import parse_semgrep_report
from app.services.ingestion_service import ingest_findings
from app.database.session import SessionLocal


@app.post("/ingest/semgrep")
def ingest_semgrep():

    db = SessionLocal()

    report_path = "reports/semgrep.json"

    if not os.path.exists(report_path):
        return {"error": "report not found"}

    findings = parse_semgrep_report(report_path)

    ingest_findings(findings, db)

    return {
        "message": "semgrep ingestion completed",
        "count": len(findings)
    }

from app.parsers.gitleaks_parser import parse_gitleaks_report
from app.services.ingestion_service import ingest_findings

@app.post("/ingest/gitleaks")
def ingest_gitleaks(db: Session = Depends(get_db)):

    findings = parse_gitleaks_report("gitleaks.json")
    ingest_findings(findings, db)

    return {
        "message": "gitleaks ingestion completed",
        "findings_ingested": len(findings)
    }


from app.parsers.trivy_parser import parse_trivy_report
from app.services.trivy_ingestion import ingest_trivy_findings

@app.post("/ingest/trivy")
def ingest_trivy(db: Session = Depends(get_db)):
    findings = parse_trivy_report("trivy.json")
    ingest_trivy_findings(findings, db)

    return {
        "message": "trivy ingestion completed",
        "findings_ingested": len(findings)
    }


# name: ShieldFlow Security Pipeline

# on:
#   push:
#   pull_request:

# jobs:
#   security-scan:
#     runs-on: ubuntu-latest

#     steps:
#       # ----------------------------------------------------
#       # 1. Checkout repo (FULL HISTORY FOR GITLEAKS)
#       # ----------------------------------------------------
#       - name: Checkout repo
#         uses: actions/checkout@v4
#         with:
#           fetch-depth: 0

#       # ----------------------------------------------------
#       # 2. Debug repo structure
#       # ----------------------------------------------------
#       - name: Show repo files
#         run: ls -R

#       # ----------------------------------------------------
#       # 3. Setup Python (Semgrep)
#       # ----------------------------------------------------
#       - name: Setup Python
#         uses: actions/setup-python@v5
#         with:
#           python-version: "3.12"

#       # ----------------------------------------------------
#       # 4. Install Semgrep
#       # ----------------------------------------------------
#       - name: Install Semgrep
#         run: pip install semgrep

#       # ----------------------------------------------------
#       # 5. Run Semgrep (SAST)
#       # ----------------------------------------------------
#       - name: Run Semgrep scan
#         run: semgrep --config auto . --json > semgrep.json

#       - name: Upload Semgrep report
#         uses: actions/upload-artifact@v4
#         with:
#           name: semgrep-report
#           path: semgrep.json

#       # ----------------------------------------------------
#       # 6. Install Gitleaks
#       # ----------------------------------------------------
#       - name: Install Gitleaks
#         run: |
#           wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.2/gitleaks_8.18.2_linux_x64.tar.gz
#           tar -xzf gitleaks_8.18.2_linux_x64.tar.gz
#           chmod +x gitleaks

#       # ----------------------------------------------------
#       # 7. Run Gitleaks (Secrets scan)
#       # ----------------------------------------------------
#       - name: Run Gitleaks scan
#         run: |
#           ./gitleaks detect \
#             --source . \
#             --report-format json \
#             --report-path gitleaks.json \
#             --verbose || true

#       - name: Upload Gitleaks report
#         uses: actions/upload-artifact@v4
#         with:
#           name: gitleaks-report
#           path: gitleaks.json

#       # ----------------------------------------------------
#       # 8. Install Trivy
#       # ----------------------------------------------------
#       - name: Install Trivy
#         run: |
#           sudo apt-get update
#           sudo apt-get install -y wget apt-transport-https gnupg lsb-release

#           wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -

#           echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/trivy.list

#           sudo apt-get update
#           sudo apt-get install -y trivy

#       # ----------------------------------------------------
#       # 9. Run Trivy filesystem scan
#       # ----------------------------------------------------
#       - name: Run Trivy scan
#         run: |
#           trivy fs . --format json --output trivy.json

#       - name: Upload Trivy report
#         uses: actions/upload-artifact@v4
#         with:
#           name: trivy-report
#           path: trivy.json

#       # ----------------------------------------------------
#       # 10. Debug outputs
#       # ----------------------------------------------------
#       - name: Show Semgrep output
#         run: cat semgrep.json

#       - name: Show Gitleaks output
#         run: cat gitleaks.json || echo "no gitleaks output"

#       - name: Show Trivy output
#         run: cat trivy.json || echo "no trivy output"

