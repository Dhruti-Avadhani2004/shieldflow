# from app.database.models import FindingDB
# from app.utils import generate_finding_hash

# from datetime import datetime
# from uuid import uuid4


# def ingest_findings(findings, db):

#     for finding in findings:

#         finding_hash = generate_finding_hash(
#             finding["tool"],
#             finding["title"],
#             finding["file"]
#         )

#         existing_finding = db.query(FindingDB).filter(
#             FindingDB.finding_hash == finding_hash
#         ).first()

#         if existing_finding:

#             existing_finding.occurrence_count += 1

#             existing_finding.last_seen = datetime.utcnow().isoformat()

#             db.add(existing_finding)

#         else:

#             new_finding = FindingDB(
#                 id=str(uuid4()),

#                 finding_hash=finding_hash,

#                 tool=finding["tool"],
#                 type=finding["type"],

#                 title=finding["title"],
#                 severity=finding["severity"],

#                 file=finding["file"],
#                 line=finding["line"],

#                 description=finding["description"],

#                 status="OPEN",

#                 created_at=datetime.utcnow().isoformat(),
#                 last_seen=datetime.utcnow().isoformat(),

#                 occurrence_count=1
#             )

#             db.add(new_finding)

#     db.commit()

from uuid import uuid4
from app.database.models import FindingDB
from sqlalchemy.orm import Session


def ingest_findings(findings, db: Session):

    inserted = 0

    for f in findings:

        finding_hash = f.get("finding_hash")
        if not finding_hash:
            continue

        existing = db.query(FindingDB).filter(
            FindingDB.finding_hash == finding_hash
        ).first()

        if existing:
            continue

        db_obj = FindingDB(
            id=str(uuid4()),   # 🔥 THIS IS THE FIX
            tool=f.get("tool"),
            type=f.get("type"),
            title=f.get("title"),
            severity=f.get("severity"),
            file=f.get("file"),
            line=f.get("line"),
            description=f.get("description"),
            evidence=f.get("evidence"),
            finding_hash=finding_hash,
            status=f.get("status", "open"),
            occurrence_count=1,
            created_at=f.get("created_at"),
            last_seen=f.get("last_seen")
        )

        db.add(db_obj)
        inserted += 1

    db.commit()
    return inserted