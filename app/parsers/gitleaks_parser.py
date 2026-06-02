# import json

# def parse_gitleaks_report(file_path: str):
#     findings = []

#     try:
#         with open(file_path, "r", encoding="utf-8") as f:
#             report = json.load(f)
#     except Exception:
#         return findings

#     for item in report:
#         findings.append({
#             "tool": "gitleaks",
#             "type": "SECRET",
#             "title": item.get("Description", "Secret detected"),
#             "severity": "CRITICAL",
#             "file": item.get("File", ""),
#             "line": item.get("StartLine", 0),
#             "description": item.get("Secret", "Sensitive value detected")
#         })

#     return findings

import json
import hashlib


def make_hash(tool, file, line, title, description):
    raw = f"{tool}:{file}:{line}:{title}:{description}"
    return hashlib.sha256(raw.encode()).hexdigest()


def parse_gitleaks_report(report_path):
    findings = []

    with open(report_path, "r", encoding="utf-8") as f:
        report = json.load(f)

    for item in report:

        file = item.get("File")
        line = item.get("StartLine")

        title = item.get("RuleID")
        description = item.get("Description")

        findings.append({
            "tool": "gitleaks",
            "type": "SECRETS",
            "title": title,
            "severity": "CRITICAL",
            "file": file,
            "line": line,
            "description": description,
            "evidence": item.get("Secret"),

            "finding_hash": make_hash(
                "gitleaks",
                file,
                line,
                title,
                item.get("Secret")
            )
        })

    return findings