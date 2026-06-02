# import json


# def parse_semgrep_report(report_path):

#     findings = []

#     try:
#         with open(report_path, "r", encoding="utf-8") as file:
#             report = json.load(file)

#     except UnicodeDecodeError:
#         with open(report_path, "r", encoding="utf-16") as file:
#             report = json.load(file)

#     results = report.get("results", [])

#     for result in results:

#         finding = {
#             "tool": "semgrep",
#             "type": "SAST",

#             "title": result.get("check_id"),

#             "severity": result.get("extra", {}).get(
#                 "severity",
#                 "UNKNOWN"
#             ),

#             "file": result.get("path"),

#             "line": result.get("start", {}).get("line"),

#             "description": result.get(
#                 "extra",
#                 {}
#             ).get(
#                 "message",
#                 ""
#             )
#         }

#         findings.append(finding)

#     return findings

import json
import hashlib


def make_hash(tool, file, line, title, description):
    raw = f"{tool}:{file}:{line}:{title}:{description}"
    return hashlib.sha256(raw.encode()).hexdigest()


def parse_semgrep_report(report_path):
    findings = []

    with open(report_path, "r", encoding="utf-8") as f:
        report = json.load(f)

    for result in report.get("results", []):

        file = result.get("path")
        line = result.get("start", {}).get("line")

        title = result.get("check_id")
        description = result.get("extra", {}).get("message", "")

        findings.append({
            "tool": "semgrep",
            "type": "SAST",
            "title": title,
            "severity": result.get("extra", {}).get("severity", "UNKNOWN"),
            "file": file,
            "line": line,
            "description": description,
            "evidence": None,

            "finding_hash": make_hash(
                "semgrep", file, line, title, description
            )
        })

    return findings