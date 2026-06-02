# import json

# def parse_trivy_report(file_path):
#     with open(file_path, "r", encoding="utf-8") as f:
#         data = json.load(f)

#     findings = []

#     for result in data.get("Results", []):
#         for vuln in result.get("Vulnerabilities", []):
#             findings.append({
#                 "tool": "trivy",
#                 "type": "SCA",
#                 "title": vuln.get("Title"),
#                 "severity": vuln.get("Severity"),
#                 "file": result.get("Target"),
#                 "line": None,
#                 "description": vuln.get("Description")
#             })

#     return findings

import json
import hashlib


def make_hash(tool, file, line, title, description):
    raw = f"{tool}:{file}:{line}:{title}:{description}"
    return hashlib.sha256(raw.encode()).hexdigest()


def parse_trivy_report(report_path):
    findings = []

    with open(report_path, "r", encoding="utf-8") as f:
        report = json.load(f)

    for result in report.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):

            file = result.get("Target")

            title = vuln.get("VulnerabilityID")
            description = vuln.get("Description")

            findings.append({
                "tool": "trivy",
                "type": "SCA",
                "title": title,
                "severity": vuln.get("Severity", "MEDIUM"),
                "file": file,
                "line": None,
                "description": description,
                "evidence": vuln.get("PkgName"),

                "finding_hash": make_hash(
                    "trivy",
                    file,
                    None,
                    title,
                    vuln.get("PkgName")
                )
            })

    return findings