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