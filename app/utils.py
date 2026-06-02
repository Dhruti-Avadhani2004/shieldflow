import hashlib


def generate_finding_hash(tool, title, file):
    data = f"{tool}:{title}:{file}"
    return hashlib.sha256(data.encode()).hexdigest()