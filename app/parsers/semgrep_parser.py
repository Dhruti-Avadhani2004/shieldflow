import json


def parse_semgrep_report(report_path):

    findings = []

    try:
        with open(report_path, "r", encoding="utf-8") as file:
            report = json.load(file)

    except UnicodeDecodeError:
        with open(report_path, "r", encoding="utf-16") as file:
            report = json.load(file)

    results = report.get("results", [])

    for result in results:

        finding = {
            "tool": "semgrep",
            "type": "SAST",

            "title": result.get("check_id"),

            "severity": result.get("extra", {}).get(
                "severity",
                "UNKNOWN"
            ),

            "file": result.get("path"),

            "line": result.get("start", {}).get("line"),

            "description": result.get(
                "extra",
                {}
            ).get(
                "message",
                ""
            )
        }

        findings.append(finding)

    return findings