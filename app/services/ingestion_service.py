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


from app.database.models import FindingDB
from app.utils import generate_finding_hash
from datetime import datetime
from uuid import uuid4


def ingest_findings(findings, db):

    for finding in findings:

        finding_hash = generate_finding_hash(
            finding["tool"],
            finding["title"],
            finding["file"]
        )

        existing = db.query(FindingDB).filter(
            FindingDB.finding_hash == finding_hash
        ).first()

        if existing:
            existing.occurrence_count += 1
            existing.last_seen = datetime.utcnow().isoformat()

        else:
            db.add(FindingDB(
                id=str(uuid4()),
                finding_hash=finding_hash,

                tool=finding["tool"],
                type=finding["type"],
                title=finding["title"],
                severity=finding["severity"],

                file=finding["file"],
                line=finding["line"],
                description=finding["description"],

                status="OPEN",
                created_at=datetime.utcnow().isoformat(),
                last_seen=datetime.utcnow().isoformat(),
                occurrence_count=1
            ))

    db.commit()