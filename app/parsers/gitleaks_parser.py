import json

def parse_gitleaks_report(file_path: str):
    findings = []

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            report = json.load(f)
    except Exception:
        return findings

    for item in report:
        findings.append({
            "tool": "gitleaks",
            "type": "SECRET",
            "title": item.get("Description", "Secret detected"),
            "severity": "CRITICAL",
            "file": item.get("File", ""),
            "line": item.get("StartLine", 0),
            "description": item.get("Secret", "Sensitive value detected")
        })

    return findings