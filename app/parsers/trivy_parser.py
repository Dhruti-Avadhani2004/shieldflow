import json

def parse_trivy_report(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    findings = []

    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            findings.append({
                "tool": "trivy",
                "type": "SCA",
                "title": vuln.get("Title"),
                "severity": vuln.get("Severity"),
                "file": result.get("Target"),
                "line": None,
                "description": vuln.get("Description")
            })

    return findings