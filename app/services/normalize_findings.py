# from datetime import datetime


# def normalize_semgrep(result):
#     return {
#         "tool": "semgrep",
#         "type": "SAST",
#         "severity": result.get("extra", {}).get("severity", "INFO"),
#         "title": result.get("check_id"),
#         "description": result.get("extra", {}).get("message"),
#         "file": result.get("path"),
#         "line": result.get("start", {}).get("line"),
#         "evidence": None,
#         "timestamp": datetime.utcnow().isoformat()
#     }


# def normalize_gitleaks(result):
#     return {
#         "tool": "gitleaks",
#         "type": "SECRETS",
#         "severity": "HIGH",
#         "title": result.get("RuleID"),
#         "description": result.get("Description"),
#         "file": result.get("File"),
#         "line": result.get("StartLine"),
#         "evidence": result.get("Secret"),
#         "timestamp": datetime.utcnow().isoformat()
#     }


# def normalize_trivy(result):
#     return {
#         "tool": "trivy",
#         "type": "SCA",
#         "severity": result.get("Severity", "MEDIUM"),
#         "title": result.get("VulnerabilityID"),
#         "description": result.get("Description"),
#         "file": result.get("PkgName"),
#         "line": None,
#         "evidence": result.get("InstalledVersion"),
#         "timestamp": datetime.utcnow().isoformat()
#     }


from datetime import datetime


def base_normalize(tool, type_, title, severity, file, line, description, evidence, hash_):

    return {
        "id": hash_,
        "tool": tool,
        "type": type_,
        "title": title,
        "severity": severity,
        "file": file,
        "line": line,
        "description": description,
        "evidence": evidence,
        "finding_hash": hash_,
        "status": "open",
        "created_at": datetime.utcnow().isoformat(),
        "last_seen": datetime.utcnow().isoformat()
    }