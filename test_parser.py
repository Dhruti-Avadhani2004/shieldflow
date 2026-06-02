from app.parsers.semgrep_parser import parse_semgrep_report

findings = parse_semgrep_report(
    "reports/semgrep.json"
)

for finding in findings:
    print(finding)